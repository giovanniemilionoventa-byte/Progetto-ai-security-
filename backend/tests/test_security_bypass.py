import uuid

import pytest
from fastapi.testclient import TestClient

from app import models
from app.database import SessionLocal
from app.main import app
from app.seed import DEMO_EMAIL, DEMO_PASSWORD


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _login(client: TestClient, email=DEMO_EMAIL, password=DEMO_PASSWORD) -> str:
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    if res.status_code == 200:
        return res.json()["access_token"]
    return ""


def _register(client: TestClient, email: str, password: str, org: str, name: str) -> str:
    existing = _login(client, email, password)
    if existing:
        return existing
    res = client.post(
        "/api/auth/register",
        json={
            "organization_name": org,
            "full_name": name,
            "email": email,
            "password": password,
        },
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _acme_headers(client: TestClient) -> dict:
    return _auth_headers(_login(client))


def _beta_headers(client: TestClient) -> dict:
    token = _register(
        client, "admin@beta-sec.test", "beta-sec-pass", "Beta Security", "Bea Sec"
    )
    return _auth_headers(token)


def _agent_named(client: TestClient, headers: dict, name: str) -> dict:
    agents = client.get("/api/agents", headers=headers).json()
    return next(a for a in agents if a["name"] == name)


def _rotate(client: TestClient, headers: dict, agent_id: str) -> str:
    res = client.post(f"/api/agents/{agent_id}/rotate", headers=headers)
    assert res.status_code == 200, res.text
    return res.json()["token"]


def _sales_token(client: TestClient) -> str:
    headers = _acme_headers(client)
    sales = _agent_named(client, headers, "Sales Copilot")
    return _rotate(client, headers, sales["id"])


def _reader_token(client: TestClient) -> str:
    headers = _acme_headers(client)
    reader = _agent_named(client, headers, "Research Reader")
    return _rotate(client, headers, reader["id"])


def _authorize(client: TestClient, token: str, payload: dict):
    return client.post(
        "/api/authorize",
        headers={"X-Agent-Token": token},
        json=payload,
    )


def _count_events(request_id: str | None = None, agent_id: str | None = None, execution_id: str | None = None) -> int:
    db = SessionLocal()
    try:
        q = db.query(models.Event)
        if request_id:
            q = q.filter(models.Event.request_id == request_id)
        if agent_id:
            q = q.filter(models.Event.agent_id == agent_id)
        if execution_id:
            q = q.filter(models.Event.execution_id == execution_id)
        return q.count()
    finally:
        db.close()


def _signals(pattern_id: str, execution_id: str | None = None) -> list:
    db = SessionLocal()
    try:
        q = db.query(models.BehaviorSignal).filter(
            models.BehaviorSignal.pattern_id == pattern_id
        )
        if execution_id:
            q = q.filter(models.BehaviorSignal.execution_id == execution_id)
        return q.all()
    finally:
        db.close()


def _executions_owned(execution_id: str, agent_id: str) -> bool:
    db = SessionLocal()
    try:
        execution = (
            db.query(models.Execution)
            .filter(models.Execution.id == execution_id)
            .first()
        )
        if not execution:
            return False
        return execution.agent_id == agent_id
    finally:
        db.close()


def _global_sequence_pattern(client: TestClient) -> dict:
    headers = _acme_headers(client)
    patterns = client.get("/api/behavior-patterns", headers=headers).json()
    return next(
        p
        for p in patterns
        if p["organization_id"] is None and p["type"] == "SEQUENCE"
    )


def test_permission_bypass_blocked_when_policy_would_allow(client: TestClient):
    token = _reader_token(client)
    res = _authorize(
        client,
        token,
        {"resource_kind": "crm", "action": "READ", "scope": "customers"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "BLOCK"
    assert "permission" in body["reason"].lower() or "least privilege" in body["reason"].lower()


def test_policy_bypass_blocked_despite_permission(client: TestClient):
    token = _sales_token(client)
    res = _authorize(
        client,
        token,
        {"resource_kind": "crm", "action": "DELETE", "scope": "all"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "BLOCK"
    assert "policy" in body["reason"].lower() or "delete" in body["reason"].lower()


def test_execution_isolation_events_do_not_leak(client: TestClient):
    headers = _acme_headers(client)
    created = client.post(
        "/api/behavior-patterns",
        headers=headers,
        json={
            "name": f"iso-{uuid.uuid4()}",
            "description": "crm then files read",
            "type": "SEQUENCE",
            "severity": "medium",
            "definition": {
                "steps": [
                    {"resource_kind": "crm", "action": "READ"},
                    {"resource_kind": "files", "action": "READ"},
                ]
            },
        },
    )
    assert created.status_code in {200, 201}
    pattern_id = created.json()["id"]
    token = _sales_token(client)
    exec_a = str(uuid.uuid4())
    exec_b = str(uuid.uuid4())

    first = _authorize(
        client,
        token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": exec_a,
        },
    )
    assert first.status_code == 200
    second = _authorize(
        client,
        token,
        {
            "resource_kind": "files",
            "action": "READ",
            "scope": "/Sales",
            "execution_id": exec_b,
        },
    )
    assert second.status_code == 200
    assert not _signals(pattern_id, exec_a)
    assert not _signals(pattern_id, exec_b)
    assert _count_events(execution_id=exec_a) == 1
    assert _count_events(execution_id=exec_b) == 1


def test_cross_organization_execution_rejected(client: TestClient):
    acme_token = _sales_token(client)
    exec_id = str(uuid.uuid4())
    seed = _authorize(
        client,
        acme_token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": exec_id,
        },
    )
    assert seed.status_code == 200
    before = _count_events(execution_id=exec_id)

    beta = _beta_headers(client)
    created = client.post(
        "/api/agents",
        headers=beta,
        json={"name": f"beta-agent-{uuid.uuid4()}", "provider": "demo"},
    )
    assert created.status_code == 200
    beta_agent = created.json()
    beta_token = beta_agent["token"]
    beta_agent_id = beta_agent["agent"]["id"]
    client.post(
        f"/api/agents/{beta_agent_id}/permissions",
        headers=beta,
        json={"resource_kind": "crm", "action": "READ", "scope": "customers"},
    )

    attack = _authorize(
        client,
        beta_token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": exec_id,
        },
    )
    assert attack.status_code == 403
    assert _count_events(execution_id=exec_id) == before
    db = SessionLocal()
    try:
        execution = db.query(models.Execution).filter(models.Execution.id == exec_id).one()
        assert execution.agent_id != beta_agent_id
        foreign = (
            db.query(models.Event)
            .filter(
                models.Event.execution_id == exec_id,
                models.Event.agent_id == beta_agent_id,
            )
            .count()
        )
        assert foreign == 0
    finally:
        db.close()


def test_foreign_agent_execution_rejected_same_org(client: TestClient):
    sales = _sales_token(client)
    exec_id = str(uuid.uuid4())
    seed = _authorize(
        client,
        sales,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": exec_id,
        },
    )
    assert seed.status_code == 200
    before = _count_events(execution_id=exec_id)
    reader = _reader_token(client)
    attack = _authorize(
        client,
        reader,
        {
            "resource_kind": "files",
            "action": "READ",
            "scope": "/Sales",
            "execution_id": exec_id,
        },
    )
    assert attack.status_code == 403
    assert _count_events(execution_id=exec_id) == before


def test_unknown_execution_id_starts_empty_owned_trajectory(client: TestClient):
    token = _sales_token(client)
    headers = _acme_headers(client)
    sales = _agent_named(client, headers, "Sales Copilot")
    unknown = str(uuid.uuid4())
    res = _authorize(
        client,
        token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": unknown,
        },
    )
    assert res.status_code == 200
    assert _executions_owned(unknown, sales["id"])
    assert _count_events(execution_id=unknown) == 1


def test_fake_trajectory_via_metadata_ignored(client: TestClient):
    pattern = _global_sequence_pattern(client)
    before = len(_signals(pattern["id"]))
    token = _sales_token(client)
    exec_id = str(uuid.uuid4())
    res = _authorize(
        client,
        token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": exec_id,
            "metadata": {
                "trajectory": [
                    {"resource_kind": "crm", "action": "READ"},
                    {"resource_kind": "files", "action": "EXPORT"},
                    {
                        "resource_kind": "email",
                        "action": "SEND",
                        "scope": "external",
                    },
                ],
                "history": [
                    {"resource_kind": "files", "action": "EXPORT"},
                    {"resource_kind": "email", "action": "SEND", "scope": "external"},
                ],
            },
        },
    )
    assert res.status_code == 200
    assert len(_signals(pattern["id"])) == before
    assert not _signals(pattern["id"], exec_id)


def test_cannot_mutate_or_delete_global_pattern(client: TestClient):
    headers = _acme_headers(client)
    pattern = _global_sequence_pattern(client)
    patch = client.patch(
        f"/api/behavior-patterns/{pattern['id']}",
        headers=headers,
        json={"enabled": False, "name": "disabled-by-attacker"},
    )
    assert patch.status_code == 403
    delete = client.delete(
        f"/api/behavior-patterns/{pattern['id']}", headers=headers
    )
    assert delete.status_code == 403
    still = client.get(
        f"/api/behavior-patterns/{pattern['id']}", headers=headers
    )
    assert still.status_code == 200
    assert still.json()["enabled"] is True
    assert still.json()["name"] == pattern["name"]


def test_cannot_mutate_or_delete_other_org_pattern(client: TestClient):
    acme = _acme_headers(client)
    created = client.post(
        "/api/behavior-patterns",
        headers=acme,
        json={
            "name": f"acme-secret-{uuid.uuid4()}",
            "type": "THRESHOLD",
            "severity": "high",
            "definition": {"resource_kind": "crm", "action": "READ", "count": 9},
        },
    )
    assert created.status_code in {200, 201}
    pattern_id = created.json()["id"]
    beta = _beta_headers(client)
    assert (
        client.get(f"/api/behavior-patterns/{pattern_id}", headers=beta).status_code
        == 404
    )
    assert (
        client.patch(
            f"/api/behavior-patterns/{pattern_id}",
            headers=beta,
            json={"enabled": False},
        ).status_code
        == 404
    )
    assert (
        client.delete(f"/api/behavior-patterns/{pattern_id}", headers=beta).status_code
        == 404
    )
    still = client.get(f"/api/behavior-patterns/{pattern_id}", headers=acme)
    assert still.status_code == 200
    assert still.json()["enabled"] is True


def test_malicious_pattern_definitions_rejected(client: TestClient):
    headers = _acme_headers(client)
    payloads = [
        {
            "name": f"evil-eval-{uuid.uuid4()}",
            "type": "SEQUENCE",
            "definition": {
                "steps": [
                    {"resource_kind": "crm", "action": "READ"},
                    {"resource_kind": "files", "action": "READ"},
                ],
                "eval": "os.system('id')",
            },
        },
        {
            "name": f"evil-exec-{uuid.uuid4()}",
            "type": "THRESHOLD",
            "definition": {
                "resource_kind": "crm",
                "action": "READ",
                "count": 2,
                "exec": "import os",
            },
        },
        {
            "name": f"evil-import-{uuid.uuid4()}",
            "type": "SEQUENCE",
            "definition": {
                "steps": [
                    {"resource_kind": "__import__", "action": "READ"},
                    {"resource_kind": "files", "action": "eval(1)"},
                ]
            },
        },
        {
            "name": f"evil-code-{uuid.uuid4()}",
            "type": "SEQUENCE",
            "definition": {
                "steps": [
                    {"resource_kind": "crm", "action": "READ", "code": "print(1)"},
                    {"resource_kind": "files", "action": "READ"},
                ]
            },
        },
    ]
    for payload in payloads:
        res = client.post("/api/behavior-patterns", headers=headers, json=payload)
        assert res.status_code == 400, payload["name"]


def test_idempotency_replay_does_not_duplicate_event(client: TestClient):
    token = _sales_token(client)
    request_id = str(uuid.uuid4())
    exec_id = str(uuid.uuid4())
    payload = {
        "resource_kind": "crm",
        "action": "READ",
        "scope": "customers",
        "execution_id": exec_id,
        "client_request_id": request_id,
    }
    first = _authorize(client, token, payload)
    assert first.status_code == 200
    second = _authorize(client, token, payload)
    assert second.status_code == 200
    assert first.json()["request_id"] == request_id
    assert second.json()["request_id"] == request_id
    assert second.json()["decision"] == first.json()["decision"]
    assert _count_events(request_id=request_id) == 1
    assert _count_events(execution_id=exec_id) == 1


def test_idempotency_key_reuse_with_different_payload_rejected(client: TestClient):
    token = _sales_token(client)
    request_id = str(uuid.uuid4())
    first = _authorize(
        client,
        token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "client_request_id": request_id,
        },
    )
    assert first.status_code == 200
    before = _count_events(request_id=request_id)
    replay = _authorize(
        client,
        token,
        {
            "resource_kind": "email",
            "action": "SEND",
            "scope": "external",
            "destination": "external",
            "client_request_id": request_id,
        },
    )
    assert replay.status_code == 409
    assert _count_events(request_id=request_id) == before


def test_distinct_request_ids_create_distinct_events(client: TestClient):
    token = _sales_token(client)
    exec_id = str(uuid.uuid4())
    first_id = str(uuid.uuid4())
    second_id = str(uuid.uuid4())
    a = _authorize(
        client,
        token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": exec_id,
            "client_request_id": first_id,
        },
    )
    b = _authorize(
        client,
        token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": exec_id,
            "client_request_id": second_id,
        },
    )
    assert a.status_code == 200
    assert b.status_code == 200
    assert a.json()["request_id"] != b.json()["request_id"]
    assert _count_events(request_id=first_id) == 1
    assert _count_events(request_id=second_id) == 1
    assert _count_events(execution_id=exec_id) == 2


def test_new_execution_does_not_erase_existing_behavior_signal(client: TestClient):
    headers = _acme_headers(client)
    created = client.post(
        "/api/behavior-patterns",
        headers=headers,
        json={
            "name": f"persist-{uuid.uuid4()}",
            "type": "SEQUENCE",
            "severity": "high",
            "definition": {
                "steps": [
                    {"resource_kind": "crm", "action": "READ"},
                    {"resource_kind": "files", "action": "READ"},
                ]
            },
        },
    )
    pattern_id = created.json()["id"]
    token = _sales_token(client)
    exec_a = str(uuid.uuid4())
    _authorize(
        client,
        token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": exec_a,
        },
    )
    _authorize(
        client,
        token,
        {
            "resource_kind": "files",
            "action": "READ",
            "scope": "/Sales",
            "execution_id": exec_a,
        },
    )
    assert _signals(pattern_id, exec_a)
    before = len(_signals(pattern_id, exec_a))
    exec_b = str(uuid.uuid4())
    _authorize(
        client,
        token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": exec_b,
        },
    )
    assert len(_signals(pattern_id, exec_a)) == before
    assert not _signals(pattern_id, exec_b)


def test_composed_allowed_actions_emit_behavior_signal(client: TestClient):
    headers = _acme_headers(client)
    created = client.post(
        "/api/behavior-patterns",
        headers=headers,
        json={
            "name": f"compose-{uuid.uuid4()}",
            "description": "individually allowed, jointly suspicious",
            "type": "SEQUENCE",
            "severity": "high",
            "definition": {
                "steps": [
                    {"resource_kind": "crm", "action": "READ"},
                    {"resource_kind": "files", "action": "READ"},
                ]
            },
        },
    )
    pattern_id = created.json()["id"]
    token = _sales_token(client)
    exec_id = str(uuid.uuid4())
    first = _authorize(
        client,
        token,
        {
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": exec_id,
        },
    )
    second = _authorize(
        client,
        token,
        {
            "resource_kind": "files",
            "action": "READ",
            "scope": "/Sales",
            "execution_id": exec_id,
        },
    )
    assert first.status_code == 200
    assert first.json()["decision"] == "ALLOW"
    assert second.status_code == 200
    assert second.json()["decision"] == "ALLOW"
    assert _signals(pattern_id, exec_id)


def test_direct_tool_bypass_is_architectural_limitation(client: TestClient):
    routes = {route.path for route in app.routes}
    assert "/api/authorize" in routes
    assert any("/gateway/" in path for path in routes)
    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    assert health.get("layer") == "control-plane"
    assert not any(
        "/crm" in path and "/gateway" not in path for path in routes
    )
