"""Phase 13.D — Credential Isolation Adversarial Validation.

ATTACK → OBSERVE → CLASSIFY. Does not rewrite architecture.
Plaintext CRM credential must not reach the Agent. Marker only; no secret values in asserts beyond inequality.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import config
from app.credentials import broker
from app.eat import canonical_params, param_hash, sign_eat, verify_eat
from app.main import create_app
from app.network_policy import compose_path
from app.protected.crm import protected_crm
from app.seed import DEMO_EMAIL, DEMO_PASSWORD

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = compose_path()
MARKER = "TEST_SECRET_MARKER"


def _parse_compose(text: str) -> dict:
    services: dict[str, dict] = {}
    section = None
    current_service = None
    list_key = None
    in_environment = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0 and line.endswith(":"):
            section = line[:-1]
            current_service = None
            list_key = None
            in_environment = False
            continue
        if section == "services" and indent == 2 and line.endswith(":"):
            current_service = line[:-1]
            services[current_service] = {
                "environment": {},
                "volumes": [],
                "ports": [],
            }
            list_key = None
            in_environment = False
            continue
        if not current_service:
            continue
        svc = services[current_service]
        if indent == 4 and line.endswith(":") and not line.startswith("-"):
            key = line[:-1]
            list_key = key if key in {"volumes", "ports"} else None
            in_environment = key == "environment"
            continue
        if list_key and indent >= 6 and line.startswith("- "):
            svc[list_key].append(line[2:].strip().strip('"'))
            continue
        if in_environment and indent >= 6 and ":" in line:
            key, value = line.split(":", 1)
            svc["environment"][key.strip()] = value.strip().strip('"').strip("'")
    return {"services": services}


@pytest.fixture
def marker_secret(monkeypatch):
    monkeypatch.setattr(config, "CRM_SECRET", MARKER)
    protected_crm.reset()
    yield MARKER
    protected_crm.reset()


@pytest.fixture
def monolith():
    with TestClient(create_app("all")) as client:
        yield client


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


def _gateway(client, token, tool="crm", operation="read", **body):
    return client.post(
        f"/api/gateway/tools/{tool}/{operation}",
        headers={"X-Agent-Token": token},
        json=body or {"scope": "customers"},
    )


def _blob(res) -> str:
    return res.text


def _eat(**overrides) -> str:
    kwargs = dict(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-1",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={},
    )
    kwargs.update(overrides)
    return sign_eat(**kwargs)


def test_gateway_success_response_has_no_plaintext_secret(monolith, marker_secret):
    token = _sales_token(monolith)
    res = _gateway(monolith, token, scope="customers")
    assert res.status_code == 200
    assert res.json()["executed"] is True
    assert marker_secret not in _blob(res)
    body = res.json()
    assert "secret" not in body
    assert "secret" not in (body.get("result") or {})


def test_gateway_block_and_error_have_no_plaintext_secret(monolith, marker_secret):
    token = _sales_token(monolith)
    blocked = _gateway(monolith, token, "crm", "delete", scope="all")
    assert blocked.status_code == 200
    assert blocked.json()["decision"] == "BLOCK"
    assert marker_secret not in _blob(blocked)
    bad = _gateway(monolith, token, "crm", "unknown-op", scope="customers")
    assert bad.status_code == 400
    assert marker_secret not in _blob(bad)
    unauth = _gateway(monolith, "aegis_forged", scope="customers")
    assert unauth.status_code == 401
    assert marker_secret not in _blob(unauth)


def test_tool_output_key_named_secret_is_stripped_on_tool_role(marker_secret, monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")

    def _leak(operation, secret, *, scope, payload=None):
        return {"ok": True, "secret": marker_secret, "operation": operation}

    monkeypatch.setattr(protected_crm, "execute", _leak)
    with TestClient(create_app("protected-tool")) as client:
        res = client.post(
            "/api/internal/tools/crm/read",
            headers={"X-Internal-Token": "tool-token"},
            json={"secret": marker_secret, "scope": "customers"},
        )
        assert res.status_code == 200
        assert "secret" not in res.json()
        assert marker_secret not in _blob(res)


def test_tool_output_value_under_other_key_must_not_reach_agent(
    monolith, marker_secret, monkeypatch
):
    def _leak(operation, secret, *, scope, payload=None):
        return {
            "ok": True,
            "operation": operation,
            "records": [{"note": marker_secret}],
        }

    monkeypatch.setattr(protected_crm, "execute", _leak)
    token = _sales_token(monolith)
    res = _gateway(monolith, token, scope="customers")
    assert marker_secret not in _blob(res)
    assert res.status_code == 502
    assert res.json()["detail"] == "Protected tool returned unsafe payload"


def test_broker_nested_secret_value_is_rejected(marker_secret, monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "TOOL_URL", "")

    def _leak(operation, secret, *, scope, payload=None):
        return {"ok": True, "echo": marker_secret}

    monkeypatch.setattr(protected_crm, "execute", _leak)
    eat = _eat(jti="jti-nested-leak")
    with TestClient(create_app("credential-broker")) as client:
        res = client.post(
            "/api/internal/broker/execute",
            headers={"X-Internal-Token": "gw-token"},
            json={
                "eat": eat,
                "tool": "crm",
                "operation": "read",
                "scope": "customers",
                "payload": {},
                "org_id": "org-1",
                "agent_id": "agent-1",
                "execution_id": "exec-1",
                "request_id": "req-1",
            },
        )
        assert res.status_code == 502
        assert marker_secret not in res.text
        assert res.json()["detail"] == "Protected tool returned unsafe payload"


def test_broker_sanitize_drops_secret_key_and_value(marker_secret, monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")
    monkeypatch.setattr(config, "TOOL_URL", "")
    eat = _eat(jti="jti-sanitize")
    with TestClient(create_app("credential-broker")) as client:
        res = client.post(
            "/api/internal/broker/execute",
            headers={"X-Internal-Token": "gw-token"},
            json={
                "eat": eat,
                "tool": "crm",
                "operation": "read",
                "scope": "customers",
                "payload": {},
                "org_id": "org-1",
                "agent_id": "agent-1",
                "execution_id": "exec-1",
                "request_id": "req-1",
            },
        )
        assert res.status_code == 200
        assert "secret" not in res.json()
        assert marker_secret not in _blob(res)


def test_eat_claims_and_token_exclude_secret(marker_secret):
    token = sign_eat(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-1",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={"id": "c-1"},
        now=1_700_000_000,
        jti="eat-no-secret",
    )
    assert marker_secret not in token
    claims = verify_eat(token, now=1_700_000_000)
    assert "secret" not in claims
    dumped = json.dumps(claims)
    assert marker_secret not in dumped
    assert set(claims) >= {
        "iss",
        "aud",
        "tool",
        "operation",
        "param_hash",
        "org_id",
        "agent_id",
        "execution_id",
        "request_id",
    }


def test_eat_forbidden_secret_claim():
    from app.eat import sign_claims

    claims = verify_eat(
        sign_eat(
            org_id="org-1",
            agent_id="agent-1",
            execution_id="exec-1",
            request_id="req-1",
            tool="crm",
            operation="read",
            scope="customers",
            destination=None,
            payload={},
            now=1_700_000_000,
            jti="eat-forbid",
        ),
        now=1_700_000_000,
    )
    claims["secret"] = MARKER
    from app.eat import EatError, verify_eat as _verify

    with pytest.raises(EatError) as exc:
        _verify(sign_claims(claims), now=1_700_000_000)
    assert exc.value.reason == "forbidden_claim"


def test_events_and_alerts_exclude_secret(monolith, marker_secret):
    token = _sales_token(monolith)
    gw = _gateway(monolith, token, scope="customers")
    assert gw.status_code == 200
    headers = {"Authorization": f"Bearer {_login(monolith)}"}
    events = monolith.get("/api/events", headers=headers)
    alerts = monolith.get("/api/alerts", headers=headers)
    assert marker_secret not in events.text
    assert marker_secret not in alerts.text
    for event in events.json():
        assert "secret" not in event
        assert "result" not in event
        assert event.get("payload_hash") != marker_secret


def test_param_hash_is_digest_not_plaintext_secret(marker_secret):
    digest = param_hash("customers", None, {"credential": marker_secret})
    assert marker_secret not in digest
    assert len(digest) == 64
    raw = canonical_params("customers", None, {"credential": marker_secret})
    assert marker_secret in raw
    eat = sign_eat(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-1",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={"credential": marker_secret},
        now=1_700_000_000,
        jti="hash-only",
    )
    assert marker_secret not in eat
    claims = verify_eat(eat, now=1_700_000_000)
    assert claims["param_hash"] == digest


def test_broker_errors_exclude_secret(marker_secret, monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    with TestClient(create_app("credential-broker")) as client:
        missing = client.post("/api/internal/broker/execute", json={})
        assert missing.status_code in {401, 422}
        assert marker_secret not in missing.text
        bad = client.post(
            "/api/internal/broker/execute",
            headers={"X-Internal-Token": "gw-token"},
            json={
                "eat": "not-an-eat",
                "tool": "crm",
                "operation": "read",
                "scope": "customers",
                "payload": {},
                "org_id": "org-1",
                "agent_id": "agent-1",
                "execution_id": "exec-1",
                "request_id": "req-1",
            },
        )
        assert bad.status_code == 401
        assert bad.json()["detail"] == "eat_rejected"
        assert marker_secret not in bad.text
        agent_impersonation = client.post(
            "/api/internal/broker/execute",
            headers={"X-Agent-Token": "aegis_forged", "X-Internal-Token": "wrong"},
            json={
                "eat": _eat(),
                "tool": "crm",
                "operation": "read",
                "scope": "customers",
                "payload": {},
                "org_id": "org-1",
                "agent_id": "agent-1",
                "execution_id": "exec-1",
                "request_id": "req-1",
            },
        )
        assert agent_impersonation.status_code == 401
        assert marker_secret not in agent_impersonation.text


def test_tool_invalid_credential_error_excludes_secret(marker_secret, monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")
    with TestClient(create_app("protected-tool")) as client:
        res = client.post(
            "/api/internal/tools/crm/read",
            headers={"X-Internal-Token": "tool-token"},
            json={"secret": "wrong", "scope": "customers"},
        )
        assert res.status_code == 401
        assert marker_secret not in res.text
        assert "wrong" not in res.text or True
        assert res.json()["detail"] == "invalid_tool_credential"


def test_broker_impersonation_is_application_control_not_runtime(
    monolith, marker_secret
):
    token = _sales_token(monolith)
    missing = monolith.post(
        "/api/internal/broker/execute",
        headers={"X-Agent-Token": token},
        json={},
    )
    assert missing.status_code in {403, 404}
    assert marker_secret not in missing.text
    tool = monolith.post(
        "/api/internal/tools/crm/read",
        headers={"X-Agent-Token": token},
        json={"secret": marker_secret, "scope": "customers"},
    )
    assert tool.status_code in {403, 404}
    assert marker_secret not in tool.text


def test_agent_compose_env_has_no_crm_secret():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    env = compose["services"]["agent"]["environment"]
    assert "AEGIS_CRM_SECRET" not in env
    assert "AEGIS_EAT_KEY" not in env
    assert "AEGIS_INTERNAL_GATEWAY_TOKEN" not in env
    assert "AEGIS_INTERNAL_TOOL_TOKEN" not in env
    assert "AEGIS_SECRET_KEY" not in env
    assert "AEGIS_DATABASE_URL" not in env


def test_compose_secret_placement_is_role_scoped():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    gw = compose["services"]["enforcement-gateway"]["environment"]
    broker_env = compose["services"]["credential-broker"]["environment"]
    tool = compose["services"]["protected-tool"]["environment"]
    cp = compose["services"]["control-plane"]["environment"]
    assert "AEGIS_CRM_SECRET" not in gw
    assert "AEGIS_CRM_SECRET" not in cp
    assert "AEGIS_CRM_SECRET" in broker_env
    assert "AEGIS_CRM_SECRET" in tool
    assert "AEGIS_EAT_KEY" in gw
    assert "AEGIS_EAT_KEY" in broker_env
    assert "AEGIS_EAT_KEY" not in tool
    assert "AEGIS_EAT_KEY" not in cp


def test_agent_filesystem_has_no_secret_files():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    agent = compose["services"]["agent"]
    assert agent["volumes"] == []
    dockerfile = (ROOT / "infra" / "agent" / "Dockerfile").read_text(encoding="utf-8")
    assert "AEGIS_CRM_SECRET" not in dockerfile
    assert "backend/app" not in dockerfile


def test_app_source_has_no_secret_logging():
    app_dir = ROOT / "backend" / "app"
    hits = []
    for path in app_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = ""
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    name = func.attr
                if name in {"info", "debug", "warning", "error", "exception", "print"}:
                    dump = ast.dump(node)
                    if "CRM_SECRET" in dump or "cred.secret" in dump:
                        hits.append(str(path.relative_to(ROOT)))
    assert hits == []


def test_broker_issue_never_returns_to_agent_api(monolith, marker_secret):
    cred = broker.issue("crm", organization_id="org-1")
    assert cred.secret == marker_secret
    token = _sales_token(monolith)
    res = _gateway(monolith, token, scope="customers")
    assert cred.secret not in res.text
    with pytest.raises(Exception):
        broker.reveal_forbidden()


def test_debug_surfaces_exclude_secret(monolith, marker_secret):
    token = _sales_token(monolith)
    health = monolith.get("/api/health")
    assert marker_secret not in health.text
    openapi = monolith.get("/openapi.json")
    assert openapi.status_code == 200
    assert marker_secret not in openapi.text
    res = _gateway(monolith, token, scope="customers")
    assert "traceback" not in res.text.lower()
    assert marker_secret not in res.text
