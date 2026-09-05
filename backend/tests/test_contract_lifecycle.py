import time
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import config, models, schemas
from app.contract_store import (
    ContractResolutionError,
    ContractStoreError,
    assert_contract_current_for_dispatch,
    resolve_active_contract,
    save_contract,
    select_active_contract,
    transition_contract_status,
)
from app.database import Base
from app.eat import EatError, sign_eat
from app.engines.behavior import TrajectoryStep
from app.engines.contract import evaluate_contract
from app.engines.enforcement import authorize_request
from app.main import create_app
from app.protected.crm import protected_crm


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
    for kind, action, scope in [("crm", "READ", "customers")]:
        session.add(
            models.Permission(
                agent_id="agent-1",
                resource_kind=kind,
                action=action,
                scope=scope,
                effect="allow",
            )
        )
    session.commit()
    return session


def _agent(db):
    return db.query(models.Agent).filter_by(id="agent-1").one()


def _contract(**overrides):
    payload = {
        "organization_id": "org-1",
        "agent_id": "agent-1",
        "contract_id": "sales-contract",
        "version": 1,
        "status": "ACTIVE",
        "purpose": "bounded sales access",
        "capabilities": [{"name": "crm.read", "actions": ["READ"]}],
        "resources": [{"kind": "crm", "scope": "customers"}],
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


# ---------------------------------------------------------------------------
# Store: lifecycle transitions and versioning
# ---------------------------------------------------------------------------


def test_transition_draft_to_active_and_revoke():
    db = _db()
    save_contract(db, _contract(status="DRAFT"))
    db.commit()
    active = transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "ACTIVE")
    db.commit()
    assert active.status == "ACTIVE"
    revoked = transition_contract_status(
        db, "org-1", "agent-1", "sales-contract", 1, "REVOKED"
    )
    db.commit()
    assert revoked.status == "REVOKED"
    with pytest.raises(ContractStoreError) as exc:
        transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "ACTIVE")
    assert exc.value.reason == "invalid_transition"


def test_terminal_statuses_cannot_return_to_active():
    db = _db()
    for status in ("REVOKED", "EXPIRED", "SUPERSEDED"):
        db = _db()
        save_contract(db, _contract(status=status))
        db.commit()
        with pytest.raises(ContractStoreError) as exc:
            transition_contract_status(
                db, "org-1", "agent-1", "sales-contract", 1, "ACTIVE"
            )
        assert exc.value.reason == "invalid_transition"


def test_two_active_contracts_impossible_via_transition():
    db = _db()
    save_contract(db, _contract(contract_id="one", status="ACTIVE"))
    save_contract(db, _contract(contract_id="two", status="DRAFT"))
    db.commit()
    with pytest.raises(ContractStoreError) as exc:
        transition_contract_status(db, "org-1", "agent-1", "two", 1, "ACTIVE")
    assert exc.value.reason == "active_contract_exists"


def test_supersede_active_then_activate_next_version():
    db = _db()
    save_contract(db, _contract(version=1, status="ACTIVE"))
    db.commit()
    transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "SUPERSEDED")
    save_contract(db, _contract(version=2, status="DRAFT"))
    db.commit()
    active = transition_contract_status(db, "org-1", "agent-1", "sales-contract", 2, "ACTIVE")
    db.commit()
    assert active.version == 2
    resolved = resolve_active_contract(db, "org-1", "agent-1")
    assert resolved.version == 2


# ---------------------------------------------------------------------------
# Store: temporal gating is deterministic
# ---------------------------------------------------------------------------


def _row(status="ACTIVE", valid_from=None, expires_at=None):
    return models.RuntimeContract(
        organization_id="org-1",
        agent_id="agent-1",
        contract_id="sales-contract",
        version=1,
        status=status,
        purpose="",
        capabilities=[],
        resources=[],
        constraints={},
        data_constraints={},
        approval_rules=[],
        valid_from=valid_from,
        expires_at=expires_at,
    )


def test_select_active_contract_temporal_window():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    future = _row(valid_from=datetime(2099, 1, 1, tzinfo=timezone.utc))
    with pytest.raises(ContractResolutionError) as exc:
        select_active_contract([future], "org-1", "agent-1", now=now)
    assert exc.value.reason == "contract_not_yet_valid"

    expired = _row(expires_at=datetime(2000, 1, 1, tzinfo=timezone.utc))
    with pytest.raises(ContractResolutionError) as exc:
        select_active_contract([expired], "org-1", "agent-1", now=now)
    assert exc.value.reason == "contract_expired"

    valid = _row(
        valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
        expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    assert select_active_contract([valid], "org-1", "agent-1", now=now).id == valid.id


def test_no_fallback_to_older_contract_when_active_expired():
    db = _db()
    save_contract(db, _contract(version=1, status="SUPERSEDED"))
    save_contract(
        db,
        _contract(
            version=2,
            status="ACTIVE",
            valid_from=datetime(2000, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2001, 1, 1, tzinfo=timezone.utc),
        ),
    )
    db.commit()
    with pytest.raises(ContractResolutionError) as exc:
        resolve_active_contract(db, "org-1", "agent-1")
    assert exc.value.reason == "contract_expired"


def test_dispatch_recheck_blocks_revoked_contract():
    db = _db()
    save_contract(db, _contract(status="ACTIVE"))
    db.commit()
    row = assert_contract_current_for_dispatch(
        db, "org-1", "agent-1", "sales-contract", 1
    )
    assert row.status == "ACTIVE"
    transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "REVOKED")
    db.commit()
    with pytest.raises(ContractResolutionError) as exc:
        assert_contract_current_for_dispatch(db, "org-1", "agent-1", "sales-contract", 1)
    assert exc.value.reason == "no_active_contract"


def test_dispatch_recheck_blocks_superseded_version():
    db = _db()
    save_contract(db, _contract(version=1, status="ACTIVE"))
    db.commit()
    transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "SUPERSEDED")
    save_contract(db, _contract(version=2, status="ACTIVE"))
    db.commit()
    with pytest.raises(ContractResolutionError) as exc:
        assert_contract_current_for_dispatch(db, "org-1", "agent-1", "sales-contract", 1)
    assert exc.value.reason == "untrusted_contract_id"
    current = assert_contract_current_for_dispatch(
        db, "org-1", "agent-1", "sales-contract", 2
    )
    assert current.version == 2


def test_dispatch_recheck_blocks_expired_contract():
    db = _db()
    save_contract(
        db,
        _contract(
            status="ACTIVE",
            valid_from=datetime(2000, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2001, 1, 1, tzinfo=timezone.utc),
        ),
    )
    db.commit()
    with pytest.raises(ContractResolutionError) as exc:
        assert_contract_current_for_dispatch(db, "org-1", "agent-1", "sales-contract", 1)
    assert exc.value.reason == "contract_expired"


# ---------------------------------------------------------------------------
# Enforcement: lifecycle and temporal gating through authorize_request()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["DRAFT", "REVOKED", "SUPERSEDED", "EXPIRED"])
def test_non_active_lifecycle_statuses_block_even_with_permission(status):
    db = _db()
    save_contract(db, _contract(status=status))
    db.commit()
    outcome = _authorize(db, _agent(db))
    assert outcome.event.decision == "BLOCK"
    assert outcome.event.reason == "No runtime contract is active for this agent."


def test_active_contract_allows_when_other_checks_pass():
    db = _db()
    save_contract(db, _contract(status="ACTIVE"))
    db.commit()
    outcome = _authorize(db, _agent(db))
    assert outcome.event.decision == "ALLOW"
    assert outcome.contract_id == "sales-contract"
    assert outcome.contract_version == 1


def test_not_yet_valid_contract_blocks():
    db = _db()
    save_contract(
        db,
        _contract(status="ACTIVE", valid_from=datetime(2099, 1, 1, tzinfo=timezone.utc)),
    )
    db.commit()
    outcome = _authorize(db, _agent(db))
    assert outcome.event.decision == "BLOCK"
    assert "not yet valid" in outcome.event.reason


def test_expired_contract_blocks():
    db = _db()
    save_contract(
        db,
        _contract(
            status="ACTIVE",
            valid_from=datetime(2000, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2001, 1, 1, tzinfo=timezone.utc),
        ),
    )
    db.commit()
    outcome = _authorize(db, _agent(db))
    assert outcome.event.decision == "BLOCK"
    assert "has expired" in outcome.event.reason


def test_contract_inside_window_can_proceed():
    db = _db()
    save_contract(
        db,
        _contract(
            status="ACTIVE",
            valid_from=datetime(2000, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        ),
    )
    db.commit()
    outcome = _authorize(db, _agent(db))
    assert outcome.event.decision == "ALLOW"


def test_revocation_after_allow_blocks_new_requests():
    db = _db()
    save_contract(db, _contract(status="ACTIVE"))
    db.commit()
    allowed = _authorize(db, _agent(db))
    assert allowed.event.decision == "ALLOW"
    transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "REVOKED")
    db.commit()
    blocked = _authorize(db, _agent(db))
    assert blocked.event.decision == "BLOCK"
    assert blocked.event.reason == "No runtime contract is active for this agent."


def test_supersession_after_allow_uses_new_version_only():
    db = _db()
    save_contract(db, _contract(version=1, status="ACTIVE"))
    db.commit()
    first = _authorize(db, _agent(db))
    assert first.contract_version == 1
    transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "SUPERSEDED")
    save_contract(db, _contract(version=2, status="ACTIVE"))
    db.commit()
    second = _authorize(db, _agent(db))
    assert second.event.decision == "ALLOW"
    assert second.contract_version == 2
    assert second.contract_id == "sales-contract"


def test_two_active_versions_impossible_then_new_requests_use_v2():
    db = _db()
    save_contract(db, _contract(version=1, status="ACTIVE"))
    db.commit()
    with pytest.raises(ContractStoreError) as exc:
        save_contract(db, _contract(version=2, status="ACTIVE"))
    assert exc.value.reason == "active_contract_exists"
    transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "SUPERSEDED")
    save_contract(db, _contract(version=2, status="ACTIVE"))
    db.commit()
    outcome = _authorize(db, _agent(db))
    assert outcome.contract_version == 2


def test_evaluate_contract_fail_closed_on_lifecycle_and_temporal():
    now = datetime.now(timezone.utc)
    current = TrajectoryStep("crm", "READ", "customers", None)
    non_active = _row(status="REVOKED")
    verdict = evaluate_contract(
        non_active, kind="crm", action="READ", scope="customers", destination=None,
        payload=None, previous=[], current=current,
    )
    assert verdict.allowed is False
    not_yet = _row(
        status="ACTIVE",
        valid_from=now.replace(year=now.year + 5),
    )
    verdict = evaluate_contract(
        not_yet, kind="crm", action="READ", scope="customers", destination=None,
        payload=None, previous=[], current=current,
    )
    assert verdict.allowed is False
    expired = _row(
        status="ACTIVE",
        expires_at=now.replace(year=now.year - 5),
    )
    verdict = evaluate_contract(
        expired, kind="crm", action="READ", scope="customers", destination=None,
        payload=None, previous=[], current=current,
    )
    assert verdict.allowed is False


# ---------------------------------------------------------------------------
# Broker: EAT alone is not sufficient; contract currency is verified
# ---------------------------------------------------------------------------


@pytest.fixture()
def broker_client(monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")
    monkeypatch.setattr(config, "TOOL_URL", "")
    with TestClient(create_app("credential-broker")) as client:
        yield client


def _eat_for_broker(
    *,
    jti,
    request_id,
    contract_id=None,
    contract_version=None,
    contract_status=None,
    contract_valid_from=None,
    contract_expires_at=None,
    ttl_seconds=60,
):
    now = int(time.time())
    return sign_eat(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id=request_id,
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={},
        ttl_seconds=ttl_seconds,
        now=now,
        jti=jti,
        contract_id=contract_id,
        contract_version=contract_version,
        contract_status=contract_status,
        contract_valid_from=contract_valid_from,
        contract_expires_at=contract_expires_at,
    )


def _broker_post(client, eat, request_id, contract_id=None, contract_version=None):
    body = {
        "eat": eat,
        "tool": "crm",
        "operation": "read",
        "scope": "customers",
        "payload": {},
        "org_id": "org-1",
        "agent_id": "agent-1",
        "execution_id": "exec-1",
        "request_id": request_id,
    }
    if contract_id is not None:
        body["contract_id"] = contract_id
    if contract_version is not None:
        body["contract_version"] = contract_version
    return client.post(
        "/api/internal/broker/execute",
        headers={"X-Internal-Token": "gw-token"},
        json=body,
    )


def test_broker_allows_valid_contract_with_current_eat(broker_client):
    now = int(time.time())
    rid = str(uuid4())
    eat = _eat_for_broker(
        jti=str(uuid4()),
        request_id=rid,
        contract_id="sales-contract",
        contract_version=1,
        contract_status="ACTIVE",
        contract_valid_from=now - 3600,
        contract_expires_at=now + 3600,
    )
    res = _broker_post(
        broker_client, eat, rid, contract_id="sales-contract", contract_version=1
    )
    assert res.status_code == 200
    assert res.json()["ok"] is True
    assert "secret" not in res.text


def test_broker_rejects_eat_after_contract_revoked(broker_client):
    rid = str(uuid4())
    eat = _eat_for_broker(
        jti=str(uuid4()),
        request_id=rid,
        contract_id="sales-contract",
        contract_version=1,
        contract_status="REVOKED",
    )
    res = _broker_post(
        broker_client, eat, rid, contract_id="sales-contract", contract_version=1
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "contract_rejected"
    assert "secret" not in res.text


def test_broker_rejects_eat_after_contract_expired(broker_client):
    now = int(time.time())
    rid = str(uuid4())
    eat = _eat_for_broker(
        jti=str(uuid4()),
        request_id=rid,
        contract_id="sales-contract",
        contract_version=1,
        contract_status="ACTIVE",
        contract_valid_from=now - 7200,
        contract_expires_at=now - 3600,
    )
    res = _broker_post(
        broker_client, eat, rid, contract_id="sales-contract", contract_version=1
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "contract_rejected"


def test_broker_rejects_eat_before_contract_valid_from(broker_client):
    now = int(time.time())
    rid = str(uuid4())
    eat = _eat_for_broker(
        jti=str(uuid4()),
        request_id=rid,
        contract_id="sales-contract",
        contract_version=1,
        contract_status="ACTIVE",
        contract_valid_from=now + 3600,
    )
    res = _broker_post(
        broker_client, eat, rid, contract_id="sales-contract", contract_version=1
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "contract_rejected"


def test_broker_still_allows_contract_free_eat_phase10(broker_client):
    rid = str(uuid4())
    eat = _eat_for_broker(jti=str(uuid4()), request_id=rid)
    res = _broker_post(broker_client, eat, rid)
    assert res.status_code == 200
    assert res.json()["ok"] is True
    assert "secret" not in res.text


def test_broker_never_leaks_reasoning_or_secrets(broker_client):
    now = int(time.time())
    rid = str(uuid4())
    eat = _eat_for_broker(
        jti=str(uuid4()),
        request_id=rid,
        contract_id="sales-contract",
        contract_version=1,
        contract_status="SUPERSEDED",
        contract_valid_from=now + 3600,
    )
    res = _broker_post(
        broker_client, eat, rid, contract_id="sales-contract", contract_version=1
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "contract_rejected"
    assert "sales-contract" not in res.text
    assert "secret" not in res.text
    assert "eat_key" not in res.text
