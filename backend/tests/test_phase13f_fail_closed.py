"""Phase 13.F — Fail-closed & failure-mode adversarial validation.

UNCERTAINTY → DENY. FAILURE → DENY. NEVER FAILURE → FALLBACK → ALLOW.
Host pytest is application-level only. L3/runtime remains NOT VERIFIED.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import config, models, schemas
from app.contract_store import ContractResolutionError, save_contract
from app.credentials import CredentialAccessDenied, broker
from app.database import Base
from app.eat import EatError, sign_eat, verify_eat
from app.engines import enforcement as enforcement_mod
from app.engines.enforcement import authorize_request
from app.engines.trajectory import reconstruct_trajectory_state
from app.main import create_app
from app.protected.crm import protected_crm
from app.seed import DEMO_EMAIL, DEMO_PASSWORD

MARKER = "TEST_SECRET_MARKER"
ROOT = Path(__file__).resolve().parents[2]


def _engine():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _fk(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    return engine


def _db():
    session = sessionmaker(bind=_engine())()
    session.add(models.Organization(id="org-1", name="Acme", slug="acme"))
    session.flush()
    session.add(
        models.User(
            id="user-1",
            organization_id="org-1",
            email="a@acme.test",
            password_hash="x",
            full_name="Ada",
        )
    )
    session.flush()
    session.add(
        models.Agent(
            id="agent-1",
            organization_id="org-1",
            owner_id="user-1",
            name="Sales",
        )
    )
    session.flush()
    session.add(
        models.Permission(
            agent_id="agent-1",
            resource_kind="crm",
            action="READ",
            scope="customers",
            effect="allow",
        )
    )
    session.add(
        models.Permission(
            agent_id="agent-1",
            resource_kind="email",
            action="SEND",
            scope="internal",
            effect="allow",
        )
    )
    session.commit()
    return session


def _agent(db, agent_id="agent-1"):
    return db.query(models.Agent).filter_by(id=agent_id).one()


def _contract(**overrides):
    payload = {
        "organization_id": "org-1",
        "agent_id": "agent-1",
        "contract_id": "sales-contract",
        "version": 1,
        "status": "ACTIVE",
        "purpose": "bounded sales access",
        "capabilities": [
            {"name": "crm.read", "actions": ["READ"]},
            {"name": "email.send", "actions": ["SEND"]},
        ],
        "resources": [
            {"kind": "crm", "scope": "customers"},
            {"kind": "email", "scope": "internal"},
        ],
        "constraints": {
            "destination_restrictions": {"allow": ["internal"], "deny": ["external"]},
        },
        "data_constraints": {"allowed_fields": ["id", "name", "to"]},
        "workflow": {
            "initial_steps": ["read_crm"],
            "steps": [
                {"id": "read_crm", "resource_kind": "crm", "action": "READ"},
                {"id": "send_email", "resource_kind": "email", "action": "SEND"},
            ],
            "transitions": [{"from": "read_crm", "to": "send_email"}],
            "terminal_steps": ["send_email"],
        },
    }
    payload.update(overrides)
    return payload


def _authorize(db, agent, **body):
    request = {
        "resource_kind": "crm",
        "action": "READ",
        "scope": "customers",
        "request_id": str(uuid4()),
    }
    request.update(body)
    return authorize_request(db, agent, schemas.AuthorizeRequest(**request))


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
        contract_id="sales-contract",
        contract_version=1,
        contract_status="ACTIVE",
        contract_valid_from=1_699_000_000,
        contract_expires_at=9_999_999_999,
    )
    kwargs.update(overrides)
    return sign_eat(**kwargs)


@pytest.fixture
def monolith():
    with TestClient(create_app("all")) as client:
        yield client


@pytest.fixture
def marker_secret(monkeypatch):
    monkeypatch.setattr(config, "CRM_SECRET", MARKER)
    protected_crm.reset()
    yield MARKER
    protected_crm.reset()


@pytest.fixture
def broker_client(monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")
    monkeypatch.setattr(config, "TOOL_URL", "")
    with TestClient(create_app("credential-broker")) as client:
        yield client


def _broker_post(client, eat, **overrides):
    body = {
        "eat": eat,
        "tool": "crm",
        "operation": "read",
        "scope": "customers",
        "destination": None,
        "payload": {},
        "org_id": "org-1",
        "agent_id": "agent-1",
        "execution_id": "exec-1",
        "request_id": "req-1",
        "contract_id": "sales-contract",
        "contract_version": 1,
    }
    body.update(overrides)
    return client.post(
        "/api/internal/broker/execute",
        headers={"X-Internal-Token": "gw-token"},
        json=body,
    )


def _docker_present() -> bool:
    if Path("/var/run/docker.sock").exists():
        return True
    import socket

    try:
        live = socket.create_connection(("127.0.0.1", 2375), timeout=0.2)
        live.close()
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Authorization engine
# ---------------------------------------------------------------------------


def test_authorization_exception_does_not_allow(monkeypatch):
    db = _db()
    agent = _agent(db)

    def boom(*_args, **_kwargs):
        raise RuntimeError("policy subsystem unavailable")

    monkeypatch.setattr(enforcement_mod.policy_engine, "evaluate", boom)
    with pytest.raises(RuntimeError):
        _authorize(db, agent)
    events = db.query(models.Event).all()
    assert all(event.decision != "ALLOW" for event in events)


def test_authorization_exception_does_not_execute_tool(monolith, monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("authorization engine crashed")

    monkeypatch.setattr("app.routers.gateway.authorize_request", boom)
    token = _sales_token(monolith)
    before = protected_crm.call_count
    with pytest.raises(RuntimeError):
        _gateway(monolith, token, scope="customers")
    assert protected_crm.call_count == before


def test_unknown_contract_resolution_reason_blocks(monkeypatch):
    db = _db()
    save_contract(db, _contract())
    db.commit()
    agent = _agent(db)

    def fail(*_args, **_kwargs):
        raise ContractResolutionError("storage_corrupt")

    monkeypatch.setattr(
        enforcement_mod, "resolve_active_contract_for_agent", fail
    )
    outcome = _authorize(db, agent)
    assert outcome.event.decision == "BLOCK"
    assert "cannot be resolved" in outcome.event.reason
    assert outcome.contract_id is None


def test_expired_and_revoked_contracts_block():
    db = _db()
    from datetime import datetime, timezone

    save_contract(
        db,
        _contract(
            status="ACTIVE",
            valid_from=datetime(2000, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2001, 1, 1, tzinfo=timezone.utc),
        ),
    )
    db.commit()
    expired = _authorize(db, _agent(db))
    assert expired.event.decision == "BLOCK"
    assert expired.event.decision != "ALLOW"

    db2 = _db()
    save_contract(db2, _contract(status="REVOKED"))
    db2.commit()
    revoked = _authorize(db2, _agent(db2))
    assert revoked.event.decision == "BLOCK"


def test_invalid_permission_input_does_not_default_allow():
    db = _db()
    agent = _agent(db)
    for perm in list(agent.permissions):
        db.delete(perm)
    db.commit()
    db.refresh(agent)
    outcome = _authorize(db, agent)
    assert outcome.event.decision == "BLOCK"


# ---------------------------------------------------------------------------
# Trajectory
# ---------------------------------------------------------------------------


def test_trajectory_state_failure_blocks_non_initial_workflow(monkeypatch):
    db = _db()
    save_contract(db, _contract())
    db.commit()

    def fail(*_args, **_kwargs):
        raise RuntimeError("trajectory reconstruction failed")

    monkeypatch.setattr(
        enforcement_mod.trajectory_engine, "reconstruct_trajectory_state", fail
    )
    with pytest.raises(RuntimeError):
        _authorize(
            db,
            _agent(db),
            resource_kind="email",
            action="SEND",
            scope="internal",
            destination="internal",
            payload={"id": "1", "to": "ada@acme.test"},
        )
    events = db.query(models.Event).all()
    assert all(event.decision != "ALLOW" for event in events)


def test_missing_trajectory_state_cannot_skip_workflow(monkeypatch):
    db = _db()
    save_contract(db, _contract())
    db.commit()
    monkeypatch.setattr(
        enforcement_mod.trajectory_engine,
        "reconstruct_trajectory_state",
        lambda *_args, **_kwargs: None,
    )
    skipped = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1", "to": "ada@acme.test"},
    )
    assert skipped.event.decision == "BLOCK"
    assert skipped.event.decision != "ALLOW"


def test_corrupted_previous_step_cannot_authorize_next():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    blocked = _authorize(
        db, _agent(db), execution_id="exec-corrupt", payload={"ssn": "x"}
    )
    assert blocked.event.decision == "BLOCK"
    nxt = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1", "to": "ada@acme.test"},
        execution_id="exec-corrupt",
    )
    assert nxt.event.decision == "BLOCK"
    state = reconstruct_trajectory_state(db, "exec-corrupt")
    assert state is not None
    assert state.authorized_actions == ()


# ---------------------------------------------------------------------------
# Event / evidence persistence
# ---------------------------------------------------------------------------


def test_event_persistence_failure_does_not_allow():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    original = db.commit

    def fail_commit():
        raise RuntimeError("event store unavailable")

    db.commit = fail_commit
    try:
        with pytest.raises(RuntimeError):
            _authorize(db, _agent(db))
    finally:
        db.commit = original
    db.rollback()
    stored = db.query(models.Event).all()
    assert all(event.decision != "ALLOW" for event in stored)


# ---------------------------------------------------------------------------
# Gateway / EAT / Broker / Tool
# ---------------------------------------------------------------------------


def test_eat_signing_failure_does_not_execute(monolith, monkeypatch, marker_secret):
    monkeypatch.setattr(config, "BROKER_URL", "http://broker.test")

    def boom(**_kwargs):
        raise RuntimeError("hmac unavailable")

    monkeypatch.setattr("app.remote.sign_eat", boom)
    token = _sales_token(monolith)
    before = protected_crm.call_count
    res = _gateway(monolith, token, scope="customers")
    assert res.status_code == 502
    assert res.json()["detail"] == "Tool dispatch failed"
    assert protected_crm.call_count == before
    assert marker_secret not in res.text
    assert res.json().get("executed") is not True


def test_broker_unavailable_is_fail_closed(monolith, monkeypatch, marker_secret):
    monkeypatch.setattr(config, "BROKER_URL", "http://broker.test")

    def boom(*_args, **_kwargs):
        raise httpx.ConnectError("broker down")

    monkeypatch.setattr("app.remote.httpx.post", boom)
    token = _sales_token(monolith)
    before = protected_crm.call_count
    res = _gateway(monolith, token, scope="customers")
    assert res.status_code == 503
    assert "unavailable" in res.json()["detail"].lower()
    assert protected_crm.call_count == before
    assert marker_secret not in res.text


def test_broker_denied_execute_does_not_fall_back_to_allow(
    monolith, monkeypatch, marker_secret
):
    monkeypatch.setattr(config, "BROKER_URL", "http://broker.test")

    def deny(*_args, **_kwargs):
        response = MagicMock()
        response.status_code = 401
        response.json.return_value = {"detail": "eat_rejected"}
        response.text = '{"detail":"eat_rejected"}'
        return response

    monkeypatch.setattr("app.remote.httpx.post", deny)
    token = _sales_token(monolith)
    before = protected_crm.call_count
    res = _gateway(monolith, token, scope="customers")
    assert res.status_code == 502
    assert protected_crm.call_count == before
    assert marker_secret not in res.text


def test_missing_and_malformed_eat_rejected(broker_client, marker_secret):
    missing = _broker_post(broker_client, "")
    assert missing.status_code == 401
    assert missing.json()["detail"] == "eat_rejected"
    assert marker_secret not in missing.text
    malformed = _broker_post(broker_client, "not-a-token")
    assert malformed.status_code == 401
    assert malformed.json()["detail"] == "eat_rejected"
    assert marker_secret not in malformed.text


def test_eat_verification_failure_does_not_issue_credential(
    broker_client, marker_secret
):
    eat = _eat(jti=str(uuid4()), request_id=str(uuid4()))
    body, _sig = eat.split(".", 1)
    res = _broker_post(
        broker_client, body + ".AAAA", request_id="req-bad-sig"
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "eat_rejected"
    assert marker_secret not in res.text


def test_eat_replay_does_not_reissue_credential(broker_client, marker_secret):
    rid = str(uuid4())
    eat = _eat(jti=str(uuid4()), request_id=rid)
    first = _broker_post(broker_client, eat, request_id=rid)
    assert first.status_code == 200
    assert marker_secret not in first.text
    replay = _broker_post(broker_client, eat, request_id=rid)
    assert replay.status_code == 401
    assert replay.json()["detail"] == "eat_rejected"
    assert marker_secret not in replay.text


def test_credential_lookup_failure_is_denied(broker_client, monkeypatch, marker_secret):
    def deny(*_args, **_kwargs):
        raise CredentialAccessDenied("No credential for tool 'crm'")

    monkeypatch.setattr(broker, "issue", deny)
    rid = str(uuid4())
    eat = _eat(jti=str(uuid4()), request_id=rid)
    res = _broker_post(broker_client, eat, request_id=rid)
    assert res.status_code == 403
    assert res.json()["detail"] == "credential_denied"
    assert marker_secret not in res.text


def test_tool_unavailable_is_fail_closed(broker_client, monkeypatch, marker_secret):
    monkeypatch.setattr(config, "TOOL_URL", "http://protected-tool.test/api")

    def boom(*_args, **_kwargs):
        raise httpx.ReadTimeout("tool timeout")

    monkeypatch.setattr("app.routers.broker.httpx.post", boom)
    rid = str(uuid4())
    eat = _eat(jti=str(uuid4()), request_id=rid)
    res = _broker_post(broker_client, eat, request_id=rid)
    assert res.status_code == 503
    assert "unavailable" in res.json()["detail"].lower()
    assert marker_secret not in res.text


def test_malformed_tool_response_is_fail_closed(
    broker_client, monkeypatch, marker_secret
):
    monkeypatch.setattr(config, "TOOL_URL", "http://protected-tool.test/api")

    def bad(*_args, **_kwargs):
        response = MagicMock()
        response.status_code = 200
        response.json.side_effect = json.JSONDecodeError("x", "x", 0)
        return response

    monkeypatch.setattr("app.routers.broker.httpx.post", bad)
    rid = str(uuid4())
    eat = _eat(jti=str(uuid4()), request_id=rid)
    with pytest.raises(json.JSONDecodeError):
        _broker_post(broker_client, eat, request_id=rid)


def test_missing_internal_token_does_not_execute(marker_secret, monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    with TestClient(create_app("credential-broker")) as client:
        res = client.post(
            "/api/internal/broker/execute",
            json={
                "eat": _eat(jti=str(uuid4())),
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
        assert res.status_code == 401
        assert marker_secret not in res.text


def test_missing_agent_token_does_not_allow(monolith, marker_secret):
    res = monolith.post(
        "/api/gateway/tools/crm/read", json={"scope": "customers"}
    )
    assert res.status_code == 401
    assert marker_secret not in res.text


def test_block_and_approval_never_execute_or_issue_eat(monolith, monkeypatch):
    monkeypatch.setattr(config, "BROKER_URL", "http://broker.test")
    signed = []

    def fake_sign(**kwargs):
        signed.append(kwargs)
        return "must-not-sign"

    monkeypatch.setattr("app.remote.sign_eat", fake_sign)
    token = _sales_token(monolith)
    before = protected_crm.call_count
    blocked = _gateway(monolith, token, "crm", "delete", scope="all")
    assert blocked.status_code == 200
    assert blocked.json()["decision"] == "BLOCK"
    assert blocked.json()["executed"] is False
    assert blocked.json()["result"] is None
    assert signed == []
    assert protected_crm.call_count == before


def test_gateway_replay_of_allow_does_not_reexecute(monolith):
    token = _sales_token(monolith)
    request_id = str(uuid4())
    first = _gateway(
        monolith, token, scope="customers", request_id=request_id
    )
    assert first.status_code == 200
    assert first.json()["decision"] == "ALLOW"
    assert first.json()["executed"] is True
    before = protected_crm.call_count
    replay = _gateway(
        monolith, token, scope="customers", request_id=request_id
    )
    assert replay.status_code == 200
    assert replay.json()["decision"] == "ALLOW"
    assert replay.json()["executed"] is False
    assert replay.json()["result"] is None
    assert protected_crm.call_count == before


def test_stale_contract_at_dispatch_blocks_execution(monolith, monkeypatch):
    from app.contract_store import ContractResolutionError as CRE

    class Outcome:
        def __init__(self, event):
            self.event = event
            self.replayed = False
            self.approval_id = None
            self.contract_id = "sales-contract"
            self.contract_version = 1
            self.authorized_payload = {}

    event = models.Event(
        organization_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        seq=1,
        resource_kind="crm",
        action="READ",
        scope="customers",
        destination=None,
        decision="ALLOW",
        risk_score=10.0,
        risk_level="low",
        reason="allowed",
        request_id="req-stale",
    )

    monkeypatch.setattr(
        "app.routers.gateway.authorize_request",
        lambda *_args, **_kwargs: Outcome(event),
    )
    monkeypatch.setattr(
        "app.routers.gateway.assert_contract_current_for_dispatch",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CRE("no_active_contract")),
    )
    dispatched = []
    monkeypatch.setattr(
        "app.routers.gateway.dispatch_via_broker",
        lambda **kwargs: dispatched.append(kwargs) or {"ok": True},
    )
    monkeypatch.setattr(config, "BROKER_URL", "http://broker.test")
    token = _sales_token(monolith)
    before = protected_crm.call_count
    res = _gateway(monolith, token, scope="customers")
    assert res.status_code == 200
    assert res.json()["decision"] == "BLOCK"
    assert res.json()["executed"] is False
    assert dispatched == []
    assert protected_crm.call_count == before


# ---------------------------------------------------------------------------
# Credential leakage regression (F-13D-01)
# ---------------------------------------------------------------------------


def test_f13d01_nested_secret_still_rejected(monolith, marker_secret, monkeypatch):
    def leak(operation, secret, *, scope, payload=None):
        return {"ok": True, "records": [{"note": marker_secret}]}

    monkeypatch.setattr(protected_crm, "execute", leak)
    token = _sales_token(monolith)
    res = _gateway(monolith, token, scope="customers")
    assert marker_secret not in res.text
    assert res.status_code == 502
    assert res.json()["detail"] == "Protected tool returned unsafe payload"


def test_secret_absent_after_dispatch_and_auth_errors(
    monolith, marker_secret, monkeypatch
):
    monkeypatch.setattr(config, "BROKER_URL", "http://broker.test")
    monkeypatch.setattr(
        "app.remote.httpx.post",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            httpx.ConnectError("down")
        ),
    )
    token = _sales_token(monolith)
    failed = _gateway(monolith, token, scope="customers")
    assert failed.status_code >= 400
    assert marker_secret not in failed.text
    blocked = _gateway(monolith, token, "crm", "delete", scope="all")
    assert marker_secret not in blocked.text
    unauth = _gateway(monolith, "aegis_forged", scope="customers")
    assert marker_secret not in unauth.text


def test_legitimate_allow_still_executes_without_secret(monolith, marker_secret):
    token = _sales_token(monolith)
    res = _gateway(monolith, token, scope="customers")
    assert res.status_code == 200
    assert res.json()["decision"] == "ALLOW"
    assert res.json()["executed"] is True
    assert marker_secret not in res.text
    assert "secret" not in (res.json().get("result") or {})


# ---------------------------------------------------------------------------
# Static fallback audit (application source)
# ---------------------------------------------------------------------------


def test_app_except_handlers_do_not_assign_allow():
    app_dir = ROOT / "backend" / "app"
    offenders = []
    for path in app_dir.rglob("*.py"):
        lines = path.read_text(encoding="utf-8").splitlines()
        in_except = False
        depth = 0
        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("except"):
                in_except = True
                depth = len(line) - len(line.lstrip(" "))
                continue
            if in_except:
                current = len(line) - len(line.lstrip(" ")) if line.strip() else depth + 1
                if stripped and current <= depth and not stripped.startswith("except"):
                    in_except = False
                    continue
                lowered = stripped.replace(" ", "")
                if "decision=\"ALLOW\"" in lowered or "decision='ALLOW'" in lowered:
                    offenders.append(f"{path.relative_to(ROOT)}:{index}")
                if "authorized=True" in lowered:
                    offenders.append(f"{path.relative_to(ROOT)}:{index}")
    assert offenders == []


def test_verify_eat_never_returns_on_bad_input():
    with pytest.raises(EatError):
        verify_eat("")
    with pytest.raises(EatError):
        verify_eat(None)
    with pytest.raises(EatError):
        verify_eat("aaaa.bbbb")


def test_runtime_l3_not_claimed_without_docker():
    if _docker_present():
        pytest.fail(
            "Docker present but Phase 13.F did not run live Agent-namespace "
            "probes; do not mark L3 VERIFIED from pytest"
        )
    pytest.skip(
        "RUNTIME VERIFICATION: NOT VERIFIED — Docker daemon absent; "
        "fail-closed proven at application layer only"
    )
