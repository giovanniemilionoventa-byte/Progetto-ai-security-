from uuid import uuid4

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import models, schemas
from app.contract_store import save_contract
from app.database import Base
from app.engines.behavior import reconstruct_trajectory
from app.engines.enforcement import authorize_request
from app.engines.trajectory import (
    reconstruct_trajectory_state,
    state_from_actions,
)


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


def _event(
    db,
    *,
    execution_id="exec-1",
    organization_id="org-1",
    agent_id="agent-1",
    seq=1,
    resource_kind="crm",
    action="READ",
    scope="customers",
    destination=None,
    decision="ALLOW",
    request_id=None,
    reason="",
):
    row = models.Event(
        organization_id=organization_id,
        agent_id=agent_id,
        execution_id=execution_id,
        seq=seq,
        resource_kind=resource_kind,
        action=action,
        scope=scope,
        destination=destination,
        decision=decision,
        reason=reason,
        request_id=request_id or str(uuid4()),
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


def test_empty_execution_has_no_progress():
    db = _db()
    _execution(db)
    db.commit()
    state = reconstruct_trajectory_state(db, "exec-1")
    assert state is not None
    assert state.execution_id == "exec-1"
    assert state.organization_id == "org-1"
    assert state.agent_id == "agent-1"
    assert state.events == ()
    assert state.authorized_actions == ()
    assert state.last_valid_progress is None
    assert state.terminal_status is None
    assert reconstruct_trajectory(db, "exec-1") == []


def test_unknown_execution_has_no_state():
    db = _db()
    db.commit()
    assert reconstruct_trajectory_state(db, "missing") is None


def test_single_allow_is_valid_progress():
    db = _db()
    _execution(db)
    _event(db, decision="ALLOW", request_id="req-allow")
    db.commit()
    state = reconstruct_trajectory_state(db, "exec-1")
    assert len(state.events) == 1
    assert len(state.authorized_actions) == 1
    assert state.last_valid_progress.decision == "ALLOW"
    assert state.last_valid_progress.request_id == "req-allow"
    assert state.last_valid_progress.resource_kind == "crm"
    assert state.last_valid_progress.action == "READ"


def test_sequence_of_allows_preserves_order():
    db = _db()
    _execution(db)
    _event(db, seq=1, action="READ", request_id="req-1")
    _event(
        db,
        seq=2,
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        request_id="req-2",
    )
    db.commit()
    state = reconstruct_trajectory_state(db, "exec-1")
    assert [item.request_id for item in state.authorized_actions] == ["req-1", "req-2"]
    assert state.last_valid_progress.request_id == "req-2"
    steps = reconstruct_trajectory(db, "exec-1")
    assert [step.action for step in steps] == ["READ", "SEND"]


def test_block_is_not_progress():
    db = _db()
    _execution(db)
    _event(db, seq=1, decision="ALLOW", request_id="req-allow")
    _event(
        db,
        seq=2,
        resource_kind="crm",
        action="DELETE",
        scope="all",
        decision="BLOCK",
        request_id="req-block",
    )
    db.commit()
    state = reconstruct_trajectory_state(db, "exec-1")
    assert [item.decision for item in state.events] == ["ALLOW", "BLOCK"]
    assert [item.request_id for item in state.authorized_actions] == ["req-allow"]
    assert state.last_valid_progress.request_id == "req-allow"


def test_approval_is_not_progress_until_allow_event_exists():
    db = _db()
    _execution(db)
    pending = _event(
        db,
        seq=1,
        resource_kind="email",
        action="SEND",
        scope="external",
        destination="external",
        decision="APPROVAL",
        request_id="req-approval",
    )
    approval = models.Approval(
        organization_id="org-1",
        agent_id="agent-1",
        event_id=pending.id,
        resource_kind="email",
        action="SEND",
        scope="external",
        destination="external",
        status="pending",
        reason="human review",
    )
    db.add(approval)
    db.commit()
    before = reconstruct_trajectory_state(db, "exec-1")
    assert [item.decision for item in before.events] == ["APPROVAL"]
    assert before.authorized_actions == ()
    assert before.last_valid_progress is None

    approval.status = "approved"
    db.commit()
    after_review = reconstruct_trajectory_state(db, "exec-1")
    assert after_review.events[0].decision == "APPROVAL"
    assert after_review.authorized_actions == ()
    assert after_review.last_valid_progress is None

    _event(
        db,
        seq=2,
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        decision="ALLOW",
        request_id="req-later-allow",
    )
    db.commit()
    after_allow = reconstruct_trajectory_state(db, "exec-1")
    assert [item.decision for item in after_allow.events] == ["APPROVAL", "ALLOW"]
    assert [item.request_id for item in after_allow.authorized_actions] == [
        "req-later-allow"
    ]
    assert after_allow.last_valid_progress.request_id == "req-later-allow"


def test_events_from_other_execution_are_excluded():
    db = _db()
    _execution(db, "exec-1")
    _execution(db, "exec-2")
    _event(db, execution_id="exec-1", seq=1, request_id="owned")
    _event(db, execution_id="exec-2", seq=1, request_id="foreign-exec")
    db.commit()
    state = reconstruct_trajectory_state(db, "exec-1")
    assert [item.request_id for item in state.events] == ["owned"]
    other = reconstruct_trajectory_state(db, "exec-2")
    assert [item.request_id for item in other.events] == ["foreign-exec"]


def test_events_from_other_organization_are_excluded():
    db = _db()
    _execution(db, "exec-1", organization_id="org-1", agent_id="agent-1")
    _event(db, execution_id="exec-1", organization_id="org-1", request_id="owned")
    _event(
        db,
        execution_id="exec-1",
        organization_id="org-2",
        agent_id="agent-3",
        seq=2,
        request_id="foreign-org",
    )
    db.commit()
    state = reconstruct_trajectory_state(db, "exec-1")
    assert [item.request_id for item in state.events] == ["owned"]
    assert reconstruct_trajectory_state(
        db, "exec-1", organization_id="org-2"
    ) is None


def test_events_from_other_agent_are_excluded():
    db = _db()
    _execution(db, "exec-1", organization_id="org-1", agent_id="agent-1")
    _event(db, execution_id="exec-1", agent_id="agent-1", request_id="owned")
    _event(
        db,
        execution_id="exec-1",
        agent_id="agent-2",
        seq=2,
        request_id="foreign-agent",
    )
    db.commit()
    state = reconstruct_trajectory_state(db, "exec-1")
    assert [item.request_id for item in state.events] == ["owned"]
    assert reconstruct_trajectory_state(db, "exec-1", agent_id="agent-2") is None


def test_reconstruction_is_deterministic():
    db = _db()
    _execution(db)
    _event(db, seq=2, request_id="second", action="READ")
    _event(
        db,
        seq=1,
        resource_kind="crm",
        action="READ",
        request_id="first",
    )
    db.commit()
    first = reconstruct_trajectory_state(db, "exec-1")
    second = reconstruct_trajectory_state(db, "exec-1")
    assert first == second
    assert [item.request_id for item in first.events] == ["first", "second"]
    replayed = state_from_actions(_agent_execution(db, first), first.events)
    assert replayed.events == first.events
    assert replayed.authorized_actions == first.authorized_actions
    assert replayed.last_valid_progress == first.last_valid_progress


def _agent_execution(db, state):
    return (
        db.query(models.Execution)
        .filter(models.Execution.id == state.execution_id)
        .one()
    )


def test_execution_has_no_invented_terminal_status():
    db = _db()
    execution = _execution(db)
    _event(db, decision="BLOCK", request_id="req-block")
    db.commit()
    assert not hasattr(execution, "status")
    state = reconstruct_trajectory_state(db, "exec-1")
    assert state.terminal_status is None
    assert state.last_valid_progress is None


def test_contract_identity_is_bound_from_owner_not_payload():
    db = _db()
    save_contract(db, _contract())
    _execution(db)
    _event(db, decision="ALLOW")
    db.commit()
    state = reconstruct_trajectory_state(db, "exec-1")
    assert state.contract_id == "sales-contract"
    assert state.contract_version == 1

    other = reconstruct_trajectory_state(
        db,
        _execution(db, "exec-other", organization_id="org-1", agent_id="agent-2").id,
    )
    db.commit()
    assert other.contract_id is None
    assert other.contract_version is None


def test_blocked_matching_step_is_not_valid_progress():
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
    jump = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1"},
        execution_id="exec-blocked-progress",
    )
    assert jump.event.decision == "BLOCK"
    assert "workflow" in jump.event.reason.lower() or "skip" in jump.event.reason.lower()

    state = reconstruct_trajectory_state(db, "exec-blocked-progress")
    assert state.organization_id == "org-1"
    assert state.agent_id == "agent-1"
    assert state.contract_id == "sales-contract"
    assert state.contract_version == 1
    assert {item.decision for item in state.events} == {"BLOCK"}
    assert state.authorized_actions == ()
    assert state.last_valid_progress is None
    steps = reconstruct_trajectory(db, "exec-blocked-progress")
    assert all(step.decision == "BLOCK" for step in steps)
