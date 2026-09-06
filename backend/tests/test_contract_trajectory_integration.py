from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import models, schemas
from app.contract_store import save_contract, transition_contract_status
from app.database import Base
from app.engines.enforcement import authorize_request
from app.engines.trajectory import reconstruct_trajectory_state


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
    session.add(models.Organization(id="org-2", name="Beta", slug="beta"))
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
    session.add(
        models.User(
            id="user-2",
            organization_id="org-2",
            email="b@beta.test",
            password_hash="x",
            full_name="Bea",
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
    session.add(
        models.Agent(
            id="agent-2",
            organization_id="org-1",
            owner_id="user-1",
            name="Support",
        )
    )
    session.add(
        models.Agent(
            id="agent-3",
            organization_id="org-2",
            owner_id="user-2",
            name="Other",
        )
    )
    session.flush()
    for kind, action, scope in [
        ("crm", "READ", "customers"),
        ("crm", "DELETE", "*"),
        ("email", "SEND", "internal"),
        ("email", "SEND", "external"),
        ("files", "READ", "/Sales"),
        ("files", "EXPORT", "/Finance"),
    ]:
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


def _agent(db, agent_id="agent-1"):
    return db.query(models.Agent).filter_by(id=agent_id).one()


def _execution(db, execution_id="exec-1", organization_id="org-1", agent_id="agent-1"):
    row = models.Execution(
        id=execution_id,
        organization_id=organization_id,
        agent_id=agent_id,
    )
    db.add(row)
    db.flush()
    return row


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
            "payload_size": {"max_bytes": 256},
        },
        "data_constraints": {
            "allowed_fields": ["id", "name", "to"],
            "denied_fields": ["ssn", "secret"],
        },
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


def _send_internal(**body):
    return {
        "resource_kind": "email",
        "action": "SEND",
        "scope": "internal",
        "destination": "internal",
        "payload": {"id": "1", "to": "ada@acme.test"},
        **body,
    }


# ---------------------------------------------------------------------------
# 1. primo step valido -> ALLOW
# ---------------------------------------------------------------------------


def test_first_valid_step_allows():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(db, _agent(db), execution_id="exec-1")
    assert outcome.event.decision == "ALLOW"


# ---------------------------------------------------------------------------
# 2. step successivo valido -> ALLOW
# ---------------------------------------------------------------------------


def test_next_valid_step_allows():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    first = _authorize(db, _agent(db), execution_id="exec-1")
    assert first.event.decision == "ALLOW"
    nxt = _authorize(db, _agent(db), **_send_internal(execution_id="exec-1"))
    assert nxt.event.decision == "ALLOW"


# ---------------------------------------------------------------------------
# 3. step saltato -> BLOCK
# ---------------------------------------------------------------------------


def test_skipped_step_blocks():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(db, _agent(db), **_send_internal(execution_id="exec-1"))
    assert outcome.event.decision == "BLOCK"
    assert "workflow" in outcome.event.reason.lower() or "skip" in outcome.event.reason.lower()


# ---------------------------------------------------------------------------
# 4. transizione non prevista -> BLOCK
# ---------------------------------------------------------------------------


def test_unexpected_transition_blocks():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    first = _authorize(db, _agent(db), execution_id="exec-1")
    assert first.event.decision == "ALLOW"
    repeat = _authorize(db, _agent(db), execution_id="exec-1")
    assert repeat.event.decision == "BLOCK"
    assert "transition" in repeat.event.reason.lower() or "workflow" in repeat.event.reason.lower()


# ---------------------------------------------------------------------------
# 5. current_step falso dell'Agent -> ignorato / non bypassa
# ---------------------------------------------------------------------------


def test_false_current_step_declaration_is_ignored():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    forged = _authorize(
        db,
        _agent(db),
        **_send_internal(
            execution_id="exec-forged",
            metadata={
                "current_step": "send_email",
                "previous_step": "read_crm",
                "workflow": {"initial_steps": ["send_email"]},
            },
        )
    )
    assert forged.event.decision == "BLOCK"
    assert "workflow" in forged.event.reason.lower() or "skip" in forged.event.reason.lower()


# ---------------------------------------------------------------------------
# 6. BLOCK precedente non soddisfa lo step
# ---------------------------------------------------------------------------


def test_blocked_preceding_step_does_not_satisfy_workflow():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    blocked = _authorize(
        db,
        _agent(db),
        execution_id="exec-blocked",
        payload={"ssn": "000"},
    )
    assert blocked.event.decision == "BLOCK"
    jump = _authorize(db, _agent(db), **_send_internal(execution_id="exec-blocked"))
    assert jump.event.decision == "BLOCK"
    assert "workflow" in jump.event.reason.lower() or "skip" in jump.event.reason.lower()


# ---------------------------------------------------------------------------
# 7. APPROVAL non soddisfa lo step finche' non autorizzata (ALLOW reale)
# ---------------------------------------------------------------------------


def _approval_contract():
    return {
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
            {"kind": "email", "scope": "*"},
        ],
        "constraints": {},
        "data_constraints": {},
        "workflow": {
            "initial_steps": ["read_crm"],
            "steps": [
                {"id": "read_crm", "resource_kind": "crm", "action": "READ", "scope": "customers"},
                {"id": "review", "resource_kind": "email", "action": "SEND", "scope": "external"},
                {"id": "send_email", "resource_kind": "email", "action": "SEND", "scope": "internal"},
            ],
            "transitions": [
                {"from": "read_crm", "to": "review"},
                {"from": "review", "to": "send_email"},
            ],
            "terminal_steps": ["send_email"],
        },
    }


def _send_external(**body):
    return {
        "resource_kind": "email",
        "action": "SEND",
        "scope": "external",
        "destination": "external",
        "payload": {"id": "1", "to": "bob@example.test"},
        **body,
    }


def test_pending_approval_does_not_satisfy_step():
    db = _db()
    save_contract(db, _approval_contract())
    db.add(
        models.Policy(
            organization_id="org-1",
            name="external-review",
            resource_kind="email",
            action="SEND",
            scope_pattern="external",
            destination_pattern="external",
            decision="APPROVAL",
            priority=10,
        )
    )
    db.commit()
    read = _authorize(db, _agent(db), execution_id="exec-1")
    assert read.event.decision == "ALLOW"
    review = _authorize(db, _agent(db), **_send_external(execution_id="exec-1"))
    assert review.event.decision == "APPROVAL"
    terminal = _authorize(db, _agent(db), **_send_internal(execution_id="exec-1"))
    assert terminal.event.decision == "BLOCK"
    assert "workflow" in terminal.event.reason.lower() or "transition" in terminal.event.reason.lower()
    state = reconstruct_trajectory_state(db, "exec-1")
    assert [item.decision for item in state.authorized_actions] == ["ALLOW"]


def test_real_allow_satisfies_step():
    db = _db()
    save_contract(db, _approval_contract())
    db.commit()
    _execution(db, "exec-1")
    db.commit()
    for seq, kind, action, scope, decision in [
        (1, "crm", "READ", "customers", "ALLOW"),
        (2, "email", "SEND", "external", "ALLOW"),
    ]:
        db.add(
            models.Event(
                organization_id="org-1",
                agent_id="agent-1",
                execution_id="exec-1",
                seq=seq,
                resource_kind=kind,
                action=action,
                scope=scope,
                decision=decision,
                request_id=str(uuid4()),
            )
        )
    db.commit()
    terminal = _authorize(db, _agent(db), **_send_internal(execution_id="exec-1"))
    assert terminal.event.decision == "ALLOW"


# ---------------------------------------------------------------------------
# 8/9/10. isolamento trajectory (altra execution / agent / organization)
# ---------------------------------------------------------------------------


def test_trajectory_of_another_execution_is_not_used():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    first = _authorize(db, _agent(db), execution_id="exec-1")
    assert first.event.decision == "ALLOW"
    other = _authorize(db, _agent(db), **_send_internal(execution_id="exec-2"))
    assert other.event.decision == "BLOCK"
    still = _authorize(db, _agent(db), **_send_internal(execution_id="exec-1"))
    assert still.event.decision == "ALLOW"


def test_trajectory_of_another_agent_is_not_used():
    db = _db()
    save_contract(db, _contract())
    db.add(
        models.Permission(
            agent_id="agent-2",
            resource_kind="email",
            action="SEND",
            scope="internal",
            effect="allow",
        )
    )
    db.commit()
    seeded = _authorize(db, _agent(db), execution_id="exec-1")
    assert seeded.event.decision == "ALLOW"
    with pytest.raises(HTTPException) as exc:
        _authorize(db, _agent(db, "agent-2"), **_send_internal(execution_id="exec-1"))
    assert exc.value.status_code == 403


def test_trajectory_of_another_organization_is_not_used():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    seeded = _authorize(db, _agent(db), execution_id="exec-1")
    assert seeded.event.decision == "ALLOW"
    with pytest.raises(HTTPException) as exc:
        _authorize(db, _agent(db, "agent-3"), **_send_internal(execution_id="exec-1"))
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# 11. Contract incompatibile con la trajectory -> BLOCK
# ---------------------------------------------------------------------------


def test_contract_incompatible_with_trajectory_blocks():
    db = _db()
    save_contract(db, _contract(version=1))
    db.commit()
    progressed = _authorize(db, _agent(db), execution_id="exec-1")
    assert progressed.event.decision == "ALLOW"
    transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "SUPERSEDED")
    save_contract(
        db,
        _contract(
            version=2,
            workflow={
                "initial_steps": ["send_email"],
                "steps": [
                    {"id": "send_email", "resource_kind": "email", "action": "SEND"}
                ],
                "transitions": [],
                "terminal_steps": ["send_email"],
            },
        ),
    )
    db.commit()
    blocked = _authorize(db, _agent(db), **_send_internal(execution_id="exec-1"))
    assert blocked.event.decision == "BLOCK"
    fresh = _authorize(db, _agent(db), **_send_internal(execution_id="exec-2"))
    assert fresh.event.decision == "ALLOW"


# ---------------------------------------------------------------------------
# 12. Contract lifecycle non valido -> BLOCK
# ---------------------------------------------------------------------------


def test_invalid_contract_lifecycle_blocks():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    allowed = _authorize(db, _agent(db), execution_id="exec-1")
    assert allowed.event.decision == "ALLOW"
    transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "REVOKED")
    db.commit()
    blocked = _authorize(db, _agent(db), execution_id="exec-1")
    assert blocked.event.decision == "BLOCK"


# ---------------------------------------------------------------------------
# 13/14. Phase10 BLOCK non viene trasformato in ALLOW dal Contract
# ---------------------------------------------------------------------------


def _contract_with_payments():
    return _contract(
        capabilities=[
            {"name": "crm.read", "actions": ["READ"]},
            {"name": "payments.transfer", "actions": ["TRANSFER"]},
        ],
        resources=[
            {"kind": "crm", "scope": "customers"},
            {"kind": "payments", "scope": "*"},
        ],
        workflow=None,
    )


def test_phase10_permission_block_survives_contract():
    db = _db()
    save_contract(db, _contract_with_payments())
    db.commit()
    outcome = _authorize(
        db,
        _agent(db),
        resource_kind="payments",
        action="TRANSFER",
        scope="any",
        execution_id="exec-1",
    )
    assert outcome.event.decision == "BLOCK"


def test_contract_cannot_turn_policy_block_into_allow():
    db = _db()
    save_contract(db, _contract())
    db.add(
        models.Policy(
            organization_id="org-1",
            name="no-email-send",
            resource_kind="email",
            action="SEND",
            scope_pattern="internal",
            decision="BLOCK",
            priority=1,
        )
    )
    db.commit()
    read = _authorize(db, _agent(db), execution_id="exec-1")
    assert read.event.decision == "ALLOW"
    blocked = _authorize(db, _agent(db), **_send_internal(execution_id="exec-1"))
    assert blocked.event.decision == "BLOCK"


# ---------------------------------------------------------------------------
# 15/16. regressione (BLOCK-derived e determinismo trajectory)
# ---------------------------------------------------------------------------


def test_regression_blocked_matching_step_state():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    blocked = _authorize(
        db,
        _agent(db),
        execution_id="exec-blocked-progress",
        payload={"ssn": "000"},
    )
    assert blocked.event.decision == "BLOCK"
    jump = _authorize(db, _agent(db), **_send_internal(execution_id="exec-blocked-progress"))
    assert jump.event.decision == "BLOCK"
    state = reconstruct_trajectory_state(db, "exec-blocked-progress")
    assert {item.decision for item in state.events} == {"BLOCK"}
    assert state.authorized_actions == ()
    assert state.last_valid_progress is None


def test_trajectory_state_is_deterministic():
    db = _db()
    _execution(db)
    for seq, action, request_id in [
        (2, "READ", "req-second"),
        (1, "READ", "req-first"),
    ]:
        db.add(
            models.Event(
                organization_id="org-1",
                agent_id="agent-1",
                execution_id="exec-1",
                seq=seq,
                resource_kind="crm",
                action=action,
                scope="customers",
                decision="ALLOW",
                request_id=request_id,
            )
        )
    db.commit()
    first = reconstruct_trajectory_state(db, "exec-1")
    second = reconstruct_trajectory_state(db, "exec-1")
    assert first == second
    assert [item.request_id for item in first.events] == ["req-first", "req-second"]
