import uuid

import pytest
from fastapi.testclient import TestClient

from app.credentials import _INTERNAL_SECRETS
from app.main import app
from app.protected.crm import protected_crm
from app.seed import DEMO_EMAIL, DEMO_PASSWORD


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_crm():
    protected_crm.reset()
    yield
    protected_crm.reset()


def _login(client: TestClient, email=DEMO_EMAIL, password=DEMO_PASSWORD) -> str:
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200
    return res.json()["access_token"]


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _acme(client: TestClient) -> dict:
    return _headers(_login(client))


def _agent_named(client: TestClient, headers: dict, name: str) -> dict:
    agents = client.get("/api/agents", headers=headers).json()
    return next(a for a in agents if a["name"] == name)


def _rotate(client: TestClient, headers: dict, agent_id: str) -> str:
    res = client.post(f"/api/agents/{agent_id}/rotate", headers=headers)
    assert res.status_code == 200
    return res.json()["token"]


def _sales_token(client: TestClient) -> str:
    headers = _acme(client)
    return _rotate(client, headers, _agent_named(client, headers, "Sales Copilot")["id"])


def _reader_token(client: TestClient) -> str:
    headers = _acme(client)
    return _rotate(client, headers, _agent_named(client, headers, "Research Reader")["id"])


def _gateway(client: TestClient, token: str, tool: str, operation: str, **body):
    return client.post(
        f"/api/gateway/tools/{tool}/{operation}",
        headers={"X-Agent-Token": token},
        json=body or {"scope": "customers"},
    )


def _response_text(res) -> str:
    return res.text.lower()


def test_allowed_request_executes_tool(client: TestClient):
    token = _sales_token(client)
    before = protected_crm.call_count
    res = _gateway(client, token, "crm", "read", scope="customers")
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "ALLOW"
    assert body["executed"] is True
    assert body["result"]["operation"] == "read"
    assert body["tool"] == "crm"
    assert protected_crm.call_count == before + 1


def test_missing_capability_blocks_and_does_not_execute(client: TestClient):
    token = _reader_token(client)
    before = protected_crm.call_count
    res = _gateway(client, token, "crm", "read", scope="customers")
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "BLOCK"
    assert body["executed"] is False
    assert body["result"] is None
    assert protected_crm.call_count == before


def test_policy_block_does_not_execute_tool(client: TestClient):
    token = _sales_token(client)
    before = protected_crm.call_count
    res = _gateway(client, token, "crm", "delete", scope="all")
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "BLOCK"
    assert body["executed"] is False
    assert protected_crm.call_count == before


def test_approval_does_not_execute_until_human_review(client: TestClient):
    headers = _acme(client)
    sales = _agent_named(client, headers, "Sales Copilot")
    perms = client.get(
        f"/api/agents/{sales['id']}/permissions", headers=headers
    ).json()
    has_update = any(
        p["resource_kind"] == "crm" and p["action"] == "UPDATE" and p["scope"] == "customers"
        for p in perms
    )
    if not has_update:
        added = client.post(
            f"/api/agents/{sales['id']}/permissions",
            headers=headers,
            json={"resource_kind": "crm", "action": "UPDATE", "scope": "customers"},
        )
        assert added.status_code == 200
    policy = client.post(
        "/api/policies",
        headers=headers,
        json={
            "name": f"approve-crm-update-{uuid.uuid4()}",
            "description": "CRM update requires a human",
            "resource_kind": "crm",
            "action": "UPDATE",
            "scope_pattern": "*",
            "decision": "APPROVAL",
            "priority": 8,
        },
    )
    assert policy.status_code == 200
    token = _rotate(client, headers, sales["id"])
    before = protected_crm.call_count
    res = _gateway(client, token, "crm", "update", scope="customers")
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "APPROVAL"
    assert body["approval_id"]
    assert body["executed"] is False
    assert body["result"] is None
    assert protected_crm.call_count == before


def test_suspicious_blocked_step_in_trajectory_does_not_execute(client: TestClient):
    token = _sales_token(client)
    exec_id = str(uuid.uuid4())
    first = _gateway(
        client, token, "crm", "read", scope="customers", execution_id=exec_id
    )
    assert first.status_code == 200
    assert first.json()["executed"] is True
    before = protected_crm.call_count
    blocked = _gateway(
        client, token, "crm", "delete", scope="all", execution_id=exec_id
    )
    assert blocked.status_code == 200
    assert blocked.json()["decision"] == "BLOCK"
    assert blocked.json()["executed"] is False
    assert protected_crm.call_count == before


def test_behavior_pattern_detected_on_gateway_path(client: TestClient):
    headers = _acme(client)
    created = client.post(
        "/api/behavior-patterns",
        headers=headers,
        json={
            "name": f"gw-seq-{uuid.uuid4()}",
            "type": "THRESHOLD",
            "severity": "high",
            "definition": {"resource_kind": "crm", "action": "READ", "count": 2},
        },
    )
    assert created.status_code in {200, 201}
    pattern_id = created.json()["id"]
    token = _sales_token(client)
    exec_id = str(uuid.uuid4())
    _gateway(client, token, "crm", "read", scope="customers", execution_id=exec_id)
    second = _gateway(
        client, token, "crm", "read", scope="customers", execution_id=exec_id
    )
    assert second.status_code == 200
    assert second.json()["decision"] == "ALLOW"
    assert second.json()["executed"] is True
    from app import models
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        signals = (
            db.query(models.BehaviorSignal)
            .filter(
                models.BehaviorSignal.pattern_id == pattern_id,
                models.BehaviorSignal.execution_id == exec_id,
            )
            .all()
        )
        assert signals
    finally:
        db.close()


def test_agent_cannot_use_another_agent_token(client: TestClient):
    sales = _sales_token(client)
    reader = _reader_token(client)
    assert sales != reader
    res = client.post(
        "/api/gateway/tools/crm/read",
        headers={"X-Agent-Token": reader + "tampered"},
        json={"scope": "customers"},
    )
    assert res.status_code == 401
    stolen = _gateway(client, reader, "crm", "delete", scope="all")
    assert stolen.status_code == 200
    assert stolen.json()["decision"] == "BLOCK"
    assert stolen.json()["executed"] is False


def test_agent_token_cannot_access_control_plane(client: TestClient):
    token = _sales_token(client)
    agent_headers = {"X-Agent-Token": token}
    for path in (
        "/api/policies",
        "/api/agents",
        "/api/behavior-patterns",
        "/api/approvals",
        "/api/auth/me",
        "/api/stats",
    ):
        res = client.get(path, headers=agent_headers)
        assert res.status_code == 403, path
    bearer = client.get(
        "/api/policies", headers={"Authorization": f"Bearer {token}"}
    )
    assert bearer.status_code == 403


def test_protected_credential_never_returned_to_agent(client: TestClient):
    token = _sales_token(client)
    res = _gateway(client, token, "crm", "read", scope="customers")
    assert res.status_code == 200
    text = _response_text(res)
    secret = _INTERNAL_SECRETS["crm"]
    assert secret.lower() not in text
    assert "aegis-internal-crm" not in text
    body = res.json()
    assert "secret" not in str(body.get("result"))
    assert body["result"] is not None


def test_block_means_zero_tool_executions(client: TestClient):
    token = _sales_token(client)
    before = protected_crm.call_count
    res = _gateway(client, token, "crm", "delete", scope="all")
    assert res.json()["decision"] == "BLOCK"
    assert res.json()["executed"] is False
    assert protected_crm.call_count == before
    assert protected_crm.call_count - before == 0


def test_direct_crm_http_route_does_not_exist(client: TestClient):
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/gateway/tools/{tool}/{operation}" in paths
    assert not any("/crm" in path and "/gateway" not in path for path in paths)
    direct = client.post("/api/crm/read", json={"scope": "customers"})
    assert direct.status_code in {404, 405}


def test_in_process_tool_call_without_gateway_is_architectural_limitation():
    before = protected_crm.call_count
    result = protected_crm.execute(
        "read",
        _INTERNAL_SECRETS["crm"],
        scope="customers",
    )
    assert result["ok"] is True
    assert protected_crm.call_count == before + 1
