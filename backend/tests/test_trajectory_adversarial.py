"""Phase 12.C - adversarial anti-bypass enforcement tests.

The agent is treated as adversarial: it lies about workflow state, forges
current/previous steps, attempts to convert BLOCK / pending APPROVAL events into
progress, skips steps, mixes executions / agents / organizations / contracts /
versions, replays trajectories across executions, tampers with event ordering
and sequence numbers, mutates payloads after a check, and supplies its own
execution / organization / agent identifiers.

Every test asserts the real fail-closed behaviour of the server-side model:

  ACTUAL REQUEST  ∩  RUNTIME CONTRACT  ∩  SERVER-SIDE TRAJECTORY

No agent-declared value becomes the source of truth.
"""

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
            id="agent-1", organization_id="org-1", owner_id="user-1", name="Sales"
        )
    )
    session.add(
        models.Agent(
            id="agent-2", organization_id="org-1", owner_id="user-1", name="Support"
        )
    )
    session.add(
        models.Agent(
            id="agent-3", organization_id="org-2", owner_id="user-2", name="Other"
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


def _grant(db, agent_id, kind, action, scope):
    db.add(
        models.Permission(
            agent_id=agent_id,
            resource_kind=kind,
            action=action,
            scope=scope,
            effect="allow",
        )
    )


def _agent(db, agent_id="agent-1"):
    return db.query(models.Agent).filter_by(id=agent_id).one()


def _execution(db, execution_id, organization_id="org-1", agent_id="agent-1"):
    row = models.Execution(
        id=execution_id,
        organization_id=organization_id,
        agent_id=agent_id,
    )
    db.add(row)
    db.flush()
    return row


def _add_event(db, execution_id, seq, kind, action, scope, decision, request_id=None):
    db.add(
        models.Event(
            organization_id="org-1",
            agent_id="agent-1",
            execution_id=execution_id,
            seq=seq,
            resource_kind=kind,
            action=action,
            scope=scope,
            decision=decision,
            request_id=request_id or str(uuid4()),
        )
    )


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


def _approval_contract(**overrides):
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
            {"kind": "email", "scope": "*"},
        ],
        "constraints": {},
        "data_constraints": {},
        "workflow": {
            "initial_steps": ["read_crm"],
            "steps": [
                {
                    "id": "read_crm",
                    "resource_kind": "crm",
                    "action": "READ",
                    "scope": "customers",
                },
                {
                    "id": "review",
                    "resource_kind": "email",
                    "action": "SEND",
                    "scope": "external",
                },
                {
                    "id": "send_email",
                    "resource_kind": "email",
                    "action": "SEND",
                    "scope": "internal",
                },
            ],
            "transitions": [
                {"from": "read_crm", "to": "review"},
                {"from": "review", "to": "send_email"},
            ],
            "terminal_steps": ["send_email"],
        },
    }
    payload.update(overrides)
    return payload


def _contract_with_payments(**overrides):
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
        **overrides,
    )


def _authorize(db, agent, **body):
    request = {
        "resource_kind": "crm",
        "action": "READ",
        "scope": "customers",
        "request_id": str(uuid4()),
    }
    request.update(body)
    return authorize_request(db, agent, schemas.AuthorizeRequest(**request))


def _read(**body):
    return {
        "resource_kind": "crm",
        "action": "READ",
        "scope": "customers",
        **body,
    }


def _send_internal(**body):
    return {
        "resource_kind": "email",
        "action": "SEND",
        "scope": "internal",
        "destination": "internal",
        "payload": {"id": "1", "to": "ada@acme.test"},
        **body,
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


def _events(db, execution_id):
    return (
        db.query(models.Event)
        .filter(models.Event.execution_id == execution_id)
        .order_by(models.Event.seq.asc())
        .all()
    )


def _decisions(db, execution_id):
    return [item.decision for item in _events(db, execution_id)]


# ---------------------------------------------------------------------------
# A. FALSE WORKFLOW STATE
# ---------------------------------------------------------------------------


def test_a_false_current_step_does_not_unlock_next_step():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    forged = _authorize(
        db,
        _agent(db),
        **_send_internal(
            execution_id="exec-forged-a",
            metadata={
                "current_step": "send_email",
                "previous_step": "read_crm",
                "workflow": {"initial_steps": ["send_email"]},
            },
        )
    )
    assert forged.event.decision == "BLOCK"
    assert "workflow" in forged.event.reason.lower() or "skip" in forged.event.reason.lower()
    state = reconstruct_trajectory_state(db, "exec-forged-a")
    assert state.authorized_actions == ()
    assert state.last_valid_progress is None
    assert forged.event.agent_id == "agent-1"


def test_a_declared_state_is_never_recorded_as_progress():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    claimed = _authorize(
        db,
        _agent(db),
        **_send_internal(
            execution_id="exec-claim-a",
            metadata={"current_step": "send_email", "previous_step": "read_crm"},
        )
    )
    assert claimed.event.decision == "BLOCK"
    assert all(item.decision == "BLOCK" for item in _events(db, "exec-claim-a"))


# ---------------------------------------------------------------------------
# B. FALSE PREVIOUS STEP
# ---------------------------------------------------------------------------


def test_b_false_previous_step_does_not_bypass():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    forged = _authorize(
        db,
        _agent(db),
        **_send_internal(
            execution_id="exec-forged-b",
            metadata={
                "previous_step": {"resource_kind": "crm", "action": "READ"},
                "completed_steps": ["read_crm"],
            },
        )
    )
    assert forged.event.decision == "BLOCK"
    assert len(_events(db, "exec-forged-b")) == 1
    assert _decisions(db, "exec-forged-b") == ["BLOCK"]


# ---------------------------------------------------------------------------
# C. BLOCK AS PROGRESS
# ---------------------------------------------------------------------------


def test_c_blocked_step_cannot_be_used_as_progress():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    blocked = _authorize(
        db, _agent(db), execution_id="exec-blocked-c", payload={"ssn": "000"}
    )
    assert blocked.event.decision == "BLOCK"
    jump = _authorize(db, _agent(db), **_send_internal(execution_id="exec-blocked-c"))
    assert jump.event.decision == "BLOCK"
    state = reconstruct_trajectory_state(db, "exec-blocked-c")
    assert all(item.decision == "BLOCK" for item in state.events)
    assert state.authorized_actions == ()
    assert state.last_valid_progress is None


# ---------------------------------------------------------------------------
# D. APPROVAL AS PROGRESS
# ---------------------------------------------------------------------------


def test_d_pending_approval_never_counts_as_progress():
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
    read = _authorize(db, _agent(db), execution_id="exec-approval-d")
    assert read.event.decision == "ALLOW"
    review = _authorize(
        db, _agent(db), **_send_external(execution_id="exec-approval-d")
    )
    assert review.event.decision == "APPROVAL"
    assert review.approval_id
    terminal = _authorize(
        db, _agent(db), **_send_internal(execution_id="exec-approval-d")
    )
    assert terminal.event.decision == "BLOCK"
    state = reconstruct_trajectory_state(db, "exec-approval-d")
    assert [item.decision for item in state.authorized_actions] == ["ALLOW"]
    external = [e for e in _events(db, "exec-approval-d") if e.scope == "external"]
    assert len(external) == 1
    assert external[0].decision == "APPROVAL"
    assert state.events[-1].decision == "BLOCK"


def test_d_approval_replay_stays_approval():
    db = _db()
    save_contract(db, _approval_contract())
    db.add(
        models.Policy(
            organization_id="org-1",
            name="external-review-replay",
            resource_kind="email",
            action="SEND",
            scope_pattern="external",
            destination_pattern="external",
            decision="APPROVAL",
            priority=10,
        )
    )
    db.commit()
    read = _authorize(db, _agent(db), execution_id="exec-approval-d2")
    assert read.event.decision == "ALLOW"
    request_id = str(uuid4())
    review = _authorize(
        db,
        _agent(db),
        **_send_external(execution_id="exec-approval-d2", request_id=request_id)
    )
    assert review.event.decision == "APPROVAL"
    replay = _authorize(
        db,
        _agent(db),
        **_send_external(execution_id="exec-approval-d2", request_id=request_id)
    )
    assert replay.event.decision == "APPROVAL"
    assert replay.replayed is True
    external = [
        e
        for e in _events(db, "exec-approval-d2")
        if e.scope == "external" and e.action == "SEND"
    ]
    assert len(external) == 1
    assert external[0].decision == "APPROVAL"


# ---------------------------------------------------------------------------
# E. SKIP STEP
# ---------------------------------------------------------------------------


def test_e_skip_to_terminal_step_blocks():
    db = _db()
    save_contract(db, _approval_contract())
    db.commit()
    skipped = _authorize(db, _agent(db), **_send_internal(execution_id="exec-skip-e"))
    assert skipped.event.decision == "BLOCK"
    assert "workflow" in skipped.event.reason.lower() or "skip" in skipped.event.reason.lower()


# ---------------------------------------------------------------------------
# F. INVALID TRANSITION
# ---------------------------------------------------------------------------


def test_f_invalid_transition_blocks_until_real_middle_step():
    db = _db()
    save_contract(db, _approval_contract())
    db.commit()
    read = _authorize(db, _agent(db), execution_id="exec-transition-f")
    assert read.event.decision == "ALLOW"
    invalid = _authorize(
        db, _agent(db), **_send_internal(execution_id="exec-transition-f")
    )
    assert invalid.event.decision == "BLOCK"
    assert "transition" in invalid.event.reason.lower()
    review = _authorize(
        db, _agent(db), **_send_external(execution_id="exec-transition-f")
    )
    assert review.event.decision == "ALLOW"
    terminal = _authorize(
        db, _agent(db), **_send_internal(execution_id="exec-transition-f")
    )
    assert terminal.event.decision == "ALLOW"
    assert _decisions(db, "exec-transition-f") == [
        "ALLOW",
        "BLOCK",
        "ALLOW",
        "ALLOW",
    ]
    state = reconstruct_trajectory_state(db, "exec-transition-f")
    assert [item.decision for item in state.authorized_actions] == [
        "ALLOW",
        "ALLOW",
        "ALLOW",
    ]


# ---------------------------------------------------------------------------
# G. EXECUTION MIXING
# ---------------------------------------------------------------------------


def test_g_execution_b_cannot_use_execution_a_progress():
    db = _db()
    save_contract(db, _approval_contract())
    db.commit()
    first = _authorize(db, _agent(db), execution_id="exec-a-g")
    assert first.event.decision == "ALLOW"
    middle = _authorize(db, _agent(db), **_send_external(execution_id="exec-a-g"))
    assert middle.event.decision == "ALLOW"
    fresh = _authorize(db, _agent(db), **_send_internal(execution_id="exec-b-g"))
    assert fresh.event.decision == "BLOCK"
    assert len(_events(db, "exec-b-g")) == 1
    assert _decisions(db, "exec-b-g") == ["BLOCK"]
    assert len(_events(db, "exec-a-g")) == 2


# ---------------------------------------------------------------------------
# H. AGENT MIXING
# ---------------------------------------------------------------------------


def test_h_another_agent_cannot_reuse_execution_or_progress():
    db = _db()
    save_contract(db, _contract())
    save_contract(
        db,
        _contract(
            contract_id="sales-contract-2",
            agent_id="agent-2",
            organization_id="org-1",
        ),
    )
    _grant(db, "agent-2", "crm", "READ", "customers")
    _grant(db, "agent-2", "email", "SEND", "internal")
    db.commit()
    seeded = _authorize(db, _agent(db), execution_id="exec-owner-h")
    assert seeded.event.decision == "ALLOW"
    with pytest.raises(HTTPException) as exc:
        _authorize(
            db,
            _agent(db, "agent-2"),
            **_send_internal(execution_id="exec-owner-h"),
        )
    assert exc.value.status_code == 403
    fresh = _authorize(
        db, _agent(db, "agent-2"), **_send_internal(execution_id="exec-agent2-h")
    )
    assert fresh.event.decision == "BLOCK"
    assert _decisions(db, "exec-agent2-h") == ["BLOCK"]


# ---------------------------------------------------------------------------
# I. ORGANIZATION MIXING
# ---------------------------------------------------------------------------


def test_i_another_organization_cannot_reuse_execution_or_contract():
    db = _db()
    save_contract(db, _contract())
    save_contract(
        db,
        _contract(
            organization_id="org-2",
            agent_id="agent-3",
            contract_id="org2-contract",
            version=1,
        ),
    )
    _grant(db, "agent-3", "crm", "READ", "customers")
    _grant(db, "agent-3", "email", "SEND", "internal")
    db.commit()
    seeded = _authorize(db, _agent(db), execution_id="exec-org1-i")
    assert seeded.event.decision == "ALLOW"
    with pytest.raises(HTTPException) as exc:
        _authorize(
            db,
            _agent(db, "agent-3"),
            **_send_internal(execution_id="exec-org1-i"),
        )
    assert exc.value.status_code == 403
    claimed = _authorize(
        db,
        _agent(db, "agent-3"),
        **_send_internal(
            execution_id="exec-org2-i",
            metadata={"contract_id": "sales-contract"},
        ),
    )
    assert claimed.event.decision == "BLOCK"
    assert claimed.event.organization_id == "org-2"
    assert claimed.event.agent_id == "agent-3"


# ---------------------------------------------------------------------------
# J. CONTRACT MIXING
# ---------------------------------------------------------------------------


def test_j_declared_contract_cannot_become_source_of_truth():
    db = _db()
    save_contract(db, _contract())
    save_contract(
        db,
        _contract(
            contract_id="archive-contract",
            version=1,
            status="REVOKED",
        ),
    )
    db.commit()
    claimed = _authorize(
        db,
        _agent(db),
        execution_id="exec-claimed-j",
        metadata={"contract_id": "archive-contract"},
    )
    assert claimed.event.decision == "BLOCK"
    assert "contract" in claimed.event.reason.lower()
    allowed = _authorize(db, _agent(db), execution_id="exec-ok-j")
    assert allowed.event.decision == "ALLOW"


def test_j_claimed_foreign_contract_id_blocks():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    claimed = _authorize(
        db,
        _agent(db),
        execution_id="exec-foreign-j",
        metadata={"contract_id": "does-not-exist"},
    )
    assert claimed.event.decision == "BLOCK"
    assert "contract" in claimed.event.reason.lower()


# ---------------------------------------------------------------------------
# K. CONTRACT VERSION CONFUSION
# ---------------------------------------------------------------------------


def test_k_agent_cannot_select_older_more_permissive_version():
    db = _db()
    save_contract(db, _contract(version=1))
    db.commit()
    seeded = _authorize(db, _agent(db), execution_id="exec-v1-k")
    assert seeded.event.decision == "ALLOW"
    transition_contract_status(db, "org-1", "agent-1", "sales-contract", 1, "SUPERSEDED")
    save_contract(
        db,
        _contract(
            version=2,
            capabilities=[{"name": "crm.read", "actions": ["READ"]}],
            resources=[{"kind": "crm", "scope": "customers"}],
            workflow=None,
        ),
    )
    db.commit()
    blocked = _authorize(
        db,
        _agent(db),
        **_send_internal(
            execution_id="exec-v1-k",
            metadata={"contract_id": "sales-contract"},
        ),
    )
    assert blocked.event.decision == "BLOCK"
    assert "contract" in blocked.event.reason.lower() or "capab" in blocked.event.reason.lower()
    fresh = _authorize(db, _agent(db), execution_id="exec-v2-k")
    assert fresh.event.decision == "ALLOW"


# ---------------------------------------------------------------------------
# L. REPLAY OF VALID TRAJECTORY
# ---------------------------------------------------------------------------


def test_l_replay_cannot_transfer_trajectory_to_another_execution():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    read_req = str(uuid4())
    read = _authorize(
        db, _agent(db), execution_id="exec-src-l", request_id=read_req
    )
    assert read.event.decision == "ALLOW"
    send_req = str(uuid4())
    send = _authorize(
        db,
        _agent(db),
        **_send_internal(execution_id="exec-src-l", request_id=send_req)
    )
    assert send.event.decision == "ALLOW"
    for request_id in (read_req, send_req):
        with pytest.raises(HTTPException) as exc:
            _authorize(
                db,
                _agent(db),
                **_send_internal(execution_id="exec-dst-l", request_id=request_id)
            )
        assert exc.value.status_code == 409
    assert len(_events(db, "exec-dst-l")) == 0
    fresh = _authorize(db, _agent(db), **_send_internal(execution_id="exec-dst-l"))
    assert fresh.event.decision == "BLOCK"
    assert reconstruct_trajectory_state(db, "exec-dst-l").authorized_actions == ()


# ---------------------------------------------------------------------------
# M. EVENT ORDER MANIPULATION
# ---------------------------------------------------------------------------


def test_m_order_is_deterministic_and_block_interleaving_is_inert():
    db = _db()
    save_contract(db, _approval_contract())
    _execution(db, "exec-order-m")
    _add_event(db, "exec-order-m", 0, "crm", "DELETE", "customers", "BLOCK", "req-blk-0")
    _add_event(db, "exec-order-m", 1, "crm", "READ", "customers", "ALLOW", "req-read-1")
    _add_event(db, "exec-order-m", 2, "email", "SEND", "external", "ALLOW", "req-ext-2")
    _add_event(db, "exec-order-m", 3, "email", "SEND", "internal", "BLOCK", "req-blk-3")
    db.commit()
    state = reconstruct_trajectory_state(db, "exec-order-m")
    assert [item.seq for item in state.events] == [0, 1, 2, 3]
    assert [item.decision for item in state.authorized_actions] == ["ALLOW", "ALLOW"]
    assert state.last_valid_progress.request_id == "req-ext-2"
    terminal = _authorize(
        db, _agent(db), **_send_internal(execution_id="exec-order-m")
    )
    assert terminal.event.decision == "ALLOW"
    assert reconstruct_trajectory_state(db, "exec-order-m") == reconstruct_trajectory_state(
        db, "exec-order-m"
    )


# ---------------------------------------------------------------------------
# N. DUPLICATE EVENTS / SEQUENCE ABUSE
# ---------------------------------------------------------------------------


def test_n_duplicate_sequence_never_escalates():
    db = _db()
    save_contract(db, _contract())
    _execution(db, "exec-dup-n")
    _add_event(db, "exec-dup-n", 1, "email", "SEND", "internal", "BLOCK", "req-dup-blk")
    _add_event(db, "exec-dup-n", 1, "crm", "READ", "customers", "ALLOW", "req-dup-allow")
    db.commit()
    first = reconstruct_trajectory_state(db, "exec-dup-n")
    second = reconstruct_trajectory_state(db, "exec-dup-n")
    assert first == second
    assert [item.decision for item in first.authorized_actions] == ["ALLOW"]
    assert len(first.authorized_actions) == 1
    assert first.authorized_actions[0].request_id == "req-dup-allow"
    assert first.last_valid_progress.request_id == "req-dup-allow"


def test_n_server_assigns_unique_monotonic_sequence():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    first = _authorize(db, _agent(db), execution_id="exec-seq-n")
    second = _authorize(db, _agent(db), execution_id="exec-seq-n")
    events = _events(db, "exec-seq-n")
    seqs = [item.seq for item in events]
    assert seqs == [1, 2]
    assert len(set(seqs)) == len(seqs)
    assert first.event.decision == "ALLOW"
    assert second.event.decision == "BLOCK"


# ---------------------------------------------------------------------------
# O. PAYLOAD MANIPULATION
# ---------------------------------------------------------------------------


def test_o_replay_with_mutated_payload_is_rejected():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    request_id = str(uuid4())
    first = _authorize(
        db,
        _agent(db),
        execution_id="exec-payload-o",
        request_id=request_id,
        payload={"id": "1"},
    )
    assert first.event.decision == "ALLOW"
    with pytest.raises(HTTPException) as exc:
        _authorize(
            db,
            _agent(db),
            execution_id="exec-payload-o",
            request_id=request_id,
            payload={"ssn": "999"},
        )
    assert exc.value.status_code == 409
    assert len(_events(db, "exec-payload-o")) == 1
    replay = _authorize(
        db,
        _agent(db),
        execution_id="exec-payload-o",
        request_id=request_id,
        payload={"id": "1"},
    )
    assert replay.event.decision == "ALLOW"
    assert replay.replayed is True
    assert len(_events(db, "exec-payload-o")) == 1


def test_o_mutated_payload_is_reauthorized_from_scratch():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    denied = _authorize(
        db,
        _agent(db),
        execution_id="exec-payload-o2",
        payload={"ssn": "999"},
    )
    assert denied.event.decision == "BLOCK"
    assert len(_events(db, "exec-payload-o2")) == 1
    assert denied.event.reason  # data-constraint reason, not an ALLOW


# ---------------------------------------------------------------------------
# P. PERMISSION -> CONTRACT CONFUSION
# ---------------------------------------------------------------------------


def test_p_contract_never_turns_permission_block_into_allow():
    db = _db()
    save_contract(db, _contract_with_payments())
    db.commit()
    outcome = _authorize(
        db,
        _agent(db),
        resource_kind="payments",
        action="TRANSFER",
        scope="any",
        execution_id="exec-perm-p",
    )
    assert outcome.event.decision == "BLOCK"
    assert "permission" in outcome.event.reason.lower() or "privilege" in outcome.event.reason.lower()
    assert reconstruct_trajectory_state(db, "exec-perm-p").authorized_actions == ()


# ---------------------------------------------------------------------------
# Q. CONTRACT -> TRAJECTORY CONFUSION
# ---------------------------------------------------------------------------


def test_q_contract_permits_action_but_empty_trajectory_blocks():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    blocked = _authorize(db, _agent(db), **_send_internal(execution_id="exec-contract-q"))
    assert blocked.event.decision == "BLOCK"
    assert "workflow" in blocked.event.reason.lower() or "skip" in blocked.event.reason.lower()
    seeded = _authorize(db, _agent(db), execution_id="exec-contract-q")
    assert seeded.event.decision == "ALLOW"
    allowed = _authorize(
        db, _agent(db), **_send_internal(execution_id="exec-contract-q")
    )
    assert allowed.event.decision == "ALLOW"


# ---------------------------------------------------------------------------
# R. EMPTY / MISSING TRAJECTORY
# ---------------------------------------------------------------------------


def test_r_missing_or_empty_trajectory_is_fail_closed():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    no_execution = _authorize(
        db,
        _agent(db),
        **_send_internal(execution_id=None)
    )
    assert no_execution.event.decision == "BLOCK"
    assert no_execution.event.execution_id
    assert reconstruct_trajectory_state(
        db, no_execution.event.execution_id
    ).authorized_actions == ()
    unknown_execution = _authorize(
        db,
        _agent(db),
        **_send_internal(execution_id="exec-never-used-r")
    )
    assert unknown_execution.event.decision == "BLOCK"


# ---------------------------------------------------------------------------
# S. AGENT-SUPPLIED EXECUTION ID
# ---------------------------------------------------------------------------


def test_s_agent_cannot_steal_another_agents_execution():
    db = _db()
    save_contract(db, _contract())
    _grant(db, "agent-2", "crm", "READ", "customers")
    _grant(db, "agent-2", "email", "SEND", "internal")
    save_contract(
        db,
        _contract(
            contract_id="sales-contract-2",
            agent_id="agent-2",
            organization_id="org-1",
        ),
    )
    db.commit()
    seeded = _authorize(db, _agent(db), execution_id="exec-owned-s")
    assert seeded.event.decision == "ALLOW"
    with pytest.raises(HTTPException) as exc:
        _authorize(
            db,
            _agent(db, "agent-2"),
            **_send_internal(execution_id="exec-owned-s"),
        )
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# T. AGENT-SUPPLIED ORGANIZATION / AGENT ID
# ---------------------------------------------------------------------------


def test_t_authenticated_identity_has_precedence_over_payload():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(
        db,
        _agent(db),
        execution_id="exec-identity-t",
        organization_id="org-2",
        agent_id="agent-3",
        request_id=str(uuid4()),
    )
    assert outcome.event.organization_id == "org-1"
    assert outcome.event.agent_id == "agent-1"
    assert outcome.event.decision == "ALLOW"


def test_t_request_model_has_no_identity_fields():
    model = schemas.AuthorizeRequest(
        resource_kind="crm",
        action="READ",
        scope="customers",
        organization_id="org-2",
        agent_id="agent-3",
    )
    assert not hasattr(model, "organization_id")
    assert not hasattr(model, "agent_id")
