from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app import config
from app.credentials import _INTERNAL_SECRETS
from app.eat import EatError, param_hash, sign_claims, sign_eat, verify_eat
from app.main import create_app
from app.protected.crm import protected_crm
from app.seed import DEMO_EMAIL, DEMO_PASSWORD


def _token(**overrides) -> str:
    kwargs = dict(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-1",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={"id": "c-1"},
        ttl_seconds=60,
        jti="jti-bind-1",
        contract_id="sales-contract",
        contract_version=1,
        contract_status="ACTIVE",
        contract_valid_from=1_699_000_000,
        contract_expires_at=9_999_999_999,
    )
    kwargs.update(overrides)
    return sign_eat(**kwargs)


def _broker_body(eat: str, **overrides) -> dict:
    body = {
        "eat": eat,
        "tool": "crm",
        "operation": "read",
        "scope": "customers",
        "destination": None,
        "payload": {"id": "c-1"},
        "org_id": "org-1",
        "agent_id": "agent-1",
        "execution_id": "exec-1",
        "request_id": "req-1",
        "contract_id": "sales-contract",
        "contract_version": 1,
    }
    body.update(overrides)
    return body


@pytest.fixture()
def broker_client(monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")
    monkeypatch.setattr(config, "TOOL_URL", "")
    with TestClient(create_app("credential-broker")) as client:
        yield client


def _post(client, eat: str, **overrides):
    return client.post(
        "/api/internal/broker/execute",
        headers={"X-Internal-Token": "gw-token"},
        json=_broker_body(eat, **overrides),
    )


def _login(client: TestClient) -> str:
    res = client.post(
        "/api/auth/login", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
    )
    assert res.status_code == 200
    return res.json()["access_token"]


def _sales_token(client: TestClient) -> str:
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    agents = client.get("/api/agents", headers=headers).json()
    sales = next(a for a in agents if a["name"] == "Sales Copilot")
    rotated = client.post(f"/api/agents/{sales['id']}/rotate", headers=headers)
    assert rotated.status_code == 200
    return rotated.json()["token"]


def _reader_token(client: TestClient) -> str:
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    agents = client.get("/api/agents", headers=headers).json()
    reader = next(a for a in agents if a["name"] == "Research Reader")
    rotated = client.post(f"/api/agents/{reader['id']}/rotate", headers=headers)
    assert rotated.status_code == 200
    return rotated.json()["token"]


def test_valid_eat_accepted(broker_client):
    rid = str(uuid4())
    eat = _token(jti=str(uuid4()), request_id=rid)
    res = _post(broker_client, eat, request_id=rid)
    assert res.status_code == 200
    assert res.json()["ok"] is True
    assert "secret" not in res.json()
    assert _INTERNAL_SECRETS["crm"] not in res.text


def test_modified_signature_blocked(broker_client):
    eat = _token(jti=str(uuid4()))
    body, _sig = eat.split(".", 1)
    res = _post(broker_client, body + ".AAAA")
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"
    assert _INTERNAL_SECRETS["crm"] not in res.text


def test_wrong_issuer_blocked(broker_client):
    claims = verify_eat(_token(jti=str(uuid4())))
    claims["iss"] = "agent"
    eat = sign_claims(claims)
    res = _post(broker_client, eat)
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"


def test_wrong_audience_blocked(broker_client):
    claims = verify_eat(_token(jti=str(uuid4())))
    claims["aud"] = "protected-tool"
    eat = sign_claims(claims)
    res = _post(broker_client, eat)
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"


def test_expired_eat_blocked(broker_client):
    eat = _token(jti=str(uuid4()), ttl_seconds=5, now=1_700_000_000)
    res = _post(broker_client, eat)
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"


def test_not_yet_valid_eat_blocked(monkeypatch, broker_client):
    eat = _token(jti=str(uuid4()), now=9_999_999_999)
    res = _post(broker_client, eat)
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"


def test_jti_replay_blocked(broker_client):
    rid = str(uuid4())
    eat = _token(jti=str(uuid4()), request_id=rid)
    first = _post(broker_client, eat, request_id=rid)
    assert first.status_code == 200
    replay = _post(broker_client, eat, request_id=rid)
    assert replay.status_code == 401
    assert replay.json()["detail"] == "eat_rejected"


@pytest.mark.parametrize(
    "mutate",
    [
        {"org_id": "other-org"},
        {"agent_id": "other-agent"},
        {"execution_id": "other-exec"},
        {"request_id": "other-req"},
        {"tool": "email"},
        {"operation": "delete"},
        {"scope": "all"},
        {"destination": "external"},
        {"payload": {"id": "c-2"}},
        {"contract_id": "other-contract"},
        {"contract_version": 9},
    ],
)
def test_claim_mismatch_blocked(broker_client, mutate):
    rid = str(uuid4())
    eat = _token(jti=str(uuid4()), request_id=rid)
    extras = {"request_id": rid, **mutate}
    res = _post(broker_client, eat, **extras)
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"
    assert _INTERNAL_SECRETS["crm"] not in res.text


def test_nested_payload_modified_blocked(broker_client):
    payload = {"user": {"id": "1", "meta": {"ok": True}}, "tags": ["a"]}
    rid = str(uuid4())
    eat = _token(jti=str(uuid4()), request_id=rid, payload=payload)
    mutated = {"user": {"id": "1", "meta": {"ok": False}}, "tags": ["a"]}
    res = _post(broker_client, eat, request_id=rid, payload=mutated)
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"


def test_array_modified_blocked(broker_client):
    payload = {"ids": ["a", "b", "c"]}
    rid = str(uuid4())
    eat = _token(jti=str(uuid4()), request_id=rid, payload=payload)
    res = _post(broker_client, eat, request_id=rid, payload={"ids": ["a", "c", "b"]})
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"


def test_key_order_is_deterministic():
    left = param_hash("customers", None, {"a": 1, "b": 2})
    right = param_hash("customers", None, {"b": 2, "a": 1})
    nested_left = param_hash("customers", "d", {"z": {"b": 2, "a": 1}, "y": [1, 2]})
    nested_right = param_hash("customers", "d", {"y": [1, 2], "z": {"a": 1, "b": 2}})
    assert left == right
    assert nested_left == nested_right
    assert param_hash("customers", None, {"a": 1, "b": 3}) != left


def test_same_request_id_different_payload_blocked(broker_client):
    rid = str(uuid4())
    eat = _token(jti=str(uuid4()), request_id=rid, payload={"id": "p1"})
    res = _post(broker_client, eat, request_id=rid, payload={"id": "p2"})
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"


def test_valid_eat_on_different_execution_blocked(broker_client):
    rid = str(uuid4())
    eat = _token(jti=str(uuid4()), request_id=rid, execution_id="exec-1")
    res = _post(broker_client, eat, request_id=rid, execution_id="exec-2")
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"


def test_valid_eat_for_different_action_blocked(broker_client):
    rid = str(uuid4())
    eat = _token(jti=str(uuid4()), request_id=rid, operation="read")
    res = _post(broker_client, eat, request_id=rid, operation="update")
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"


def test_eat_binds_authorized_action_claims():
    eat = _token(
        jti=str(uuid4()),
        tool="crm",
        operation="read",
        scope="customers",
        destination="internal",
        payload={"id": "1"},
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-bound",
        contract_id="sales-contract",
        contract_version=1,
    )
    claims = verify_eat(eat)
    assert claims["org_id"] == "org-1"
    assert claims["agent_id"] == "agent-1"
    assert claims["execution_id"] == "exec-1"
    assert claims["request_id"] == "req-bound"
    assert claims["tool"] == "crm"
    assert claims["operation"] == "read"
    assert claims["scope"] == "customers"
    assert claims["destination"] == "internal"
    assert claims["contract_id"] == "sales-contract"
    assert claims["contract_version"] == 1
    assert claims["param_hash"] == param_hash(
        "customers", "internal", {"id": "1"}
    )


def test_missing_destination_claim_rejected():
    claims = verify_eat(_token(jti=str(uuid4())))
    del claims["destination"]
    try:
        verify_eat(sign_claims(claims))
        assert False
    except EatError as exc:
        assert exc.reason == "missing_claim"


def _deny_does_not_dispatch(monkeypatch, token_fn, tool, operation, scope):
    dispatched = []

    def fake_dispatch(**kwargs):
        dispatched.append(kwargs)
        return {"ok": True}

    monkeypatch.setattr(config, "BROKER_URL", "http://broker.test")
    monkeypatch.setattr("app.routers.gateway.dispatch_via_broker", fake_dispatch)
    signed = []

    def fake_sign(**kwargs):
        signed.append(kwargs)
        return "should-not-sign"

    monkeypatch.setattr("app.remote.sign_eat", fake_sign)
    with TestClient(create_app("all")) as client:
        token = token_fn(client)
        before = protected_crm.call_count
        res = client.post(
            f"/api/gateway/tools/{tool}/{operation}",
            headers={"X-Agent-Token": token},
            json={"scope": scope},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["executed"] is False
        assert body["result"] is None
        assert dispatched == []
        assert signed == []
        assert protected_crm.call_count == before
        return body


def test_block_does_not_produce_eat(monkeypatch):
    body = _deny_does_not_dispatch(
        monkeypatch, _sales_token, "crm", "delete", "all"
    )
    assert body["decision"] == "BLOCK"


def test_approval_pending_does_not_produce_eat(monkeypatch):
    monkeypatch.setattr(config, "BROKER_URL", "http://broker.test")
    dispatched = []
    monkeypatch.setattr(
        "app.routers.gateway.dispatch_via_broker",
        lambda **kwargs: dispatched.append(kwargs) or {"ok": True},
    )
    signed = []
    monkeypatch.setattr(
        "app.remote.sign_eat",
        lambda **kwargs: signed.append(kwargs) or "nope",
    )
    with TestClient(create_app("all")) as client:
        token = _login(client)
        headers = {"Authorization": f"Bearer {token}"}
        agents = client.get("/api/agents", headers=headers).json()
        sales = next(a for a in agents if a["name"] == "Sales Copilot")
        perms = client.get(
            f"/api/agents/{sales['id']}/permissions", headers=headers
        ).json()
        if not any(
            p["resource_kind"] == "crm"
            and p["action"] == "UPDATE"
            and p["scope"] == "customers"
            for p in perms
        ):
            added = client.post(
                f"/api/agents/{sales['id']}/permissions",
                headers=headers,
                json={
                    "resource_kind": "crm",
                    "action": "UPDATE",
                    "scope": "customers",
                },
            )
            assert added.status_code == 200
        policy = client.post(
            "/api/policies",
            headers=headers,
            json={
                "name": f"approve-crm-update-{uuid4()}",
                "description": "CRM update requires a human",
                "resource_kind": "crm",
                "action": "UPDATE",
                "scope_pattern": "*",
                "decision": "APPROVAL",
                "priority": 8,
            },
        )
        assert policy.status_code == 200
        rotated = client.post(
            f"/api/agents/{sales['id']}/rotate", headers=headers
        )
        agent_token = rotated.json()["token"]
        before = protected_crm.call_count
        res = client.post(
            "/api/gateway/tools/crm/update",
            headers={"X-Agent-Token": agent_token},
            json={"scope": "customers"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["decision"] == "APPROVAL"
        assert body["executed"] is False
        assert dispatched == []
        assert signed == []
        assert protected_crm.call_count == before


def test_phase10_permission_block_does_not_produce_eat(monkeypatch):
    body = _deny_does_not_dispatch(
        monkeypatch, _reader_token, "crm", "read", "customers"
    )
    assert body["decision"] == "BLOCK"


def test_phase12b_trajectory_violation_does_not_produce_eat(monkeypatch):
    event = SimpleNamespace(
        decision="BLOCK",
        reason="Invalid workflow transition.",
        request_id="req-traj",
        risk_score=90.0,
        risk_level="high",
        agent_id="agent-1",
        organization_id="org-1",
        execution_id="exec-1",
        scope="internal",
        destination="internal",
    )
    outcome = SimpleNamespace(
        event=event,
        replayed=False,
        approval_id=None,
        contract_id="sales-contract",
        contract_version=1,
        authorized_payload={"to": "ada@acme.test"},
    )
    monkeypatch.setattr(
        "app.routers.gateway.authorize_request", lambda *args, **kwargs: outcome
    )
    monkeypatch.setattr(config, "BROKER_URL", "http://broker.test")
    dispatched = []
    monkeypatch.setattr(
        "app.routers.gateway.dispatch_via_broker",
        lambda **kwargs: dispatched.append(kwargs) or {"ok": True},
    )
    signed = []
    monkeypatch.setattr(
        "app.remote.sign_eat",
        lambda **kwargs: signed.append(kwargs) or "nope",
    )
    with TestClient(create_app("all")) as client:
        token = _sales_token(client)
        before = protected_crm.call_count
        res = client.post(
            "/api/gateway/tools/crm/read",
            headers={"X-Agent-Token": token},
            json={"scope": "customers"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["decision"] == "BLOCK"
        assert body["executed"] is False
        assert dispatched == []
        assert signed == []
        assert protected_crm.call_count == before


def test_dispatch_uses_authorized_payload_not_request_copy(monkeypatch):
    event = SimpleNamespace(
        decision="ALLOW",
        reason="allowed",
        request_id="req-authz",
        risk_score=10.0,
        risk_level="low",
        agent_id="agent-1",
        organization_id="org-1",
        execution_id="exec-1",
        scope="customers",
        destination=None,
    )
    authorized = {"id": "authorized-p1"}
    outcome = SimpleNamespace(
        event=event,
        replayed=False,
        approval_id=None,
        contract_id=None,
        contract_version=None,
        authorized_payload=authorized,
    )
    monkeypatch.setattr(
        "app.routers.gateway.authorize_request", lambda *args, **kwargs: outcome
    )
    monkeypatch.setattr(config, "BROKER_URL", "http://broker.test")
    captured = []

    def fake_dispatch(**kwargs):
        captured.append(kwargs)
        return {"ok": True}

    monkeypatch.setattr("app.routers.gateway.dispatch_via_broker", fake_dispatch)
    with TestClient(create_app("all")) as client:
        token = _sales_token(client)
        res = client.post(
            "/api/gateway/tools/crm/read",
            headers={"X-Agent-Token": token},
            json={"scope": "customers", "payload": {"id": "agent-declared-p2"}},
        )
        assert res.status_code == 200
        assert res.json()["executed"] is True
        assert len(captured) == 1
        assert captured[0]["payload"] == authorized
        assert captured[0]["payload"] != {"id": "agent-declared-p2"}
        assert captured[0]["tool"] == "crm"
        assert captured[0]["operation"] == "read"
        assert captured[0]["scope"] == "customers"
        assert captured[0]["request_id"] == "req-authz"
        assert captured[0]["execution_id"] == "exec-1"


def test_param_hash_matches_sign_and_verify():
    payload = {"b": 2, "a": {"d": 4, "c": 3}}
    eat = _token(jti=str(uuid4()), payload=payload)
    claims = verify_eat(eat)
    assert claims["param_hash"] == param_hash("customers", None, payload)
    assert claims["param_hash"] == param_hash(
        "customers", None, {"a": {"c": 3, "d": 4}, "b": 2}
    )
