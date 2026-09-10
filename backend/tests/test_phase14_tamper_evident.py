"""Phase 14 — Tamper-evident execution evidence.

ATTACK -> OBSERVE -> CLASSIFY. Host pytest is application-level only.
Does not claim L3/runtime isolation. Does not close F-13A-01..05 or F-13D-01.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, event, inspect as sa_inspect, text
from sqlalchemy.orm import sessionmaker

from app import models, schemas
from app.contract_store import save_contract
from app.database import Base
from app.engines.enforcement import (
    _payload_digest,
    authorize_request,
)
from app.engines.trajectory import (
    owned_execution_events,
    reconstruct_trajectory,
    reconstruct_trajectory_state,
)
from app.routers import resources as resources_mod

ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = ROOT / "backend" / "app"


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


def _seed_allow_read(db, execution_id="exec-1"):
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(
        db,
        _agent(db),
        execution_id=execution_id,
        payload={"id": "1", "name": "Ada"},
    )
    assert outcome.event.decision == "ALLOW"
    return outcome


def _event_columns():
    return {column.name for column in models.Event.__table__.columns}


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_a_modify_event_decision_is_not_detected():
    db = _db()
    outcome = _seed_allow_read(db)
    event = db.query(models.Event).filter_by(id=outcome.event.id).one()
    original_hash = event.payload_hash
    event.decision = "BLOCK"
    event.reason = "tampered"
    db.commit()

    reconstructed = reconstruct_trajectory_state(db, event.execution_id)
    assert reconstructed is not None
    assert reconstructed.events[0].decision == "BLOCK"
    assert reconstructed.authorized_actions == ()
    stored = db.query(models.Event).filter_by(id=event.id).one()
    assert stored.payload_hash == original_hash
    assert stored.decision == "BLOCK"


def test_b_delete_event_is_not_detected():
    db = _db()
    outcome = _seed_allow_read(db, execution_id="exec-del")
    event_id = outcome.event.id
    execution_id = outcome.event.execution_id
    db.delete(db.query(models.Event).filter_by(id=event_id).one())
    db.commit()

    assert db.query(models.Event).filter_by(id=event_id).first() is None
    state = reconstruct_trajectory_state(db, execution_id)
    assert state is not None
    assert state.events == ()
    assert reconstruct_trajectory(db, execution_id) == []


def test_c_insert_forged_allow_event_is_not_detected():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    execution = models.Execution(
        id="exec-forge",
        organization_id="org-1",
        agent_id="agent-1",
    )
    db.add(execution)
    db.flush()
    forged = models.Event(
        organization_id="org-1",
        agent_id="agent-1",
        execution_id=execution.id,
        seq=1,
        resource_kind="crm",
        action="READ",
        scope="customers",
        payload_hash=_payload_digest({"id": "forged"}),
        decision="ALLOW",
        reason="forged history",
        request_id="forged-req",
    )
    db.add(forged)
    db.commit()

    state = reconstruct_trajectory_state(db, execution.id)
    assert state is not None
    assert len(state.authorized_actions) == 1
    assert state.authorized_actions[0].decision == "ALLOW"
    assert state.authorized_actions[0].request_id == "forged-req"


def test_d_reorder_events_by_seq_is_not_detected_as_tamper():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    first = _authorize(
        db,
        _agent(db),
        execution_id="exec-ord",
        payload={"id": "1", "name": "Ada"},
    )
    assert first.event.decision == "ALLOW"
    second = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1", "to": "ada@acme.test"},
        execution_id="exec-ord",
    )
    assert second.event.decision == "ALLOW"

    rows = owned_execution_events(db, "exec-ord")
    assert [row.seq for row in rows] == [1, 2]
    rows[0].seq, rows[1].seq = rows[1].seq, rows[0].seq
    db.commit()

    reordered = owned_execution_events(db, "exec-ord")
    assert [row.resource_kind for row in reordered] == ["email", "crm"]
    state = reconstruct_trajectory_state(db, "exec-ord")
    assert state is not None
    assert [item.resource_kind for item in state.events] == ["email", "crm"]


def test_e_replace_payload_hash_is_not_verified_on_reconstruct():
    db = _db()
    outcome = _seed_allow_read(db, execution_id="exec-hash")
    event = db.query(models.Event).filter_by(id=outcome.event.id).one()
    event.payload_hash = "0" * 64
    db.commit()

    state = reconstruct_trajectory_state(db, "exec-hash")
    assert state is not None
    assert len(state.events) == 1
    stored = db.query(models.Event).filter_by(id=event.id).one()
    assert stored.payload_hash == "0" * 64


def test_f_duplicate_request_id_is_accepted_by_store():
    db = _db()
    first = _seed_allow_read(db, execution_id="exec-dup")
    duplicate = models.Event(
        organization_id="org-1",
        agent_id="agent-1",
        execution_id=first.event.execution_id,
        seq=99,
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload_hash=_payload_digest({"id": "1", "to": "ada@acme.test"}),
        decision="ALLOW",
        reason="duplicate request_id",
        request_id=first.event.request_id,
    )
    db.add(duplicate)
    db.commit()
    rows = (
        db.query(models.Event)
        .filter(models.Event.request_id == first.event.request_id)
        .all()
    )
    assert len(rows) == 2


def test_g_reconstruct_succeeds_after_all_tamper_classes():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    first = _authorize(
        db,
        _agent(db),
        execution_id="exec-all",
        payload={"id": "1", "name": "Ada"},
    )
    _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1", "to": "ada@acme.test"},
        execution_id="exec-all",
    )
    events = owned_execution_events(db, "exec-all")
    events[0].decision = "BLOCK"
    events[1].payload_hash = "deadbeef"
    db.add(
        models.Event(
            organization_id="org-1",
            agent_id="agent-1",
            execution_id="exec-all",
            seq=1,
            resource_kind="crm",
            action="READ",
            scope="customers",
            decision="ALLOW",
            request_id="injected",
        )
    )
    db.commit()
    state = reconstruct_trajectory_state(db, "exec-all")
    assert state is not None
    assert len(state.events) >= 2


def test_h_forged_history_can_authorize_next_workflow_step():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    execution = models.Execution(
        id="exec-impact",
        organization_id="org-1",
        agent_id="agent-1",
    )
    db.add(execution)
    db.add(
        models.Event(
            organization_id="org-1",
            agent_id="agent-1",
            execution_id=execution.id,
            seq=1,
            resource_kind="crm",
            action="READ",
            scope="customers",
            payload_hash=_payload_digest({"id": "1", "name": "Ada"}),
            decision="ALLOW",
            reason="forged prior step",
            request_id="forged-read",
        )
    )
    db.commit()

    skipped = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1", "to": "ada@acme.test"},
        execution_id="exec-missing",
    )
    assert skipped.event.decision == "BLOCK"

    nxt = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1", "to": "ada@acme.test"},
        execution_id=execution.id,
    )
    assert nxt.event.decision == "ALLOW"


def test_i_no_event_integrity_verifier_exists():
    names = []
    for path in APP_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                names.append(node.name)
    forbidden = {
        "verify_event",
        "verify_events",
        "verify_event_integrity",
        "verify_evidence",
        "verify_chain",
        "verify_payload_hash",
    }
    assert forbidden.isdisjoint(names)
    source = inspect.getsource(reconstruct_trajectory) + inspect.getsource(
        reconstruct_trajectory_state
    )
    assert "payload_hash" not in source


def test_j_payload_hash_does_not_cover_decision_or_seq():
    digest_a = _payload_digest({"id": "1"})
    digest_b = _payload_digest({"id": "1"})
    assert digest_a == digest_b
    columns = _event_columns()
    for name in (
        "prev_hash",
        "event_hash",
        "chain_hash",
        "signature",
        "hmac",
        "mac",
        "integrity",
    ):
        assert name not in columns
    assert "payload_hash" in columns


def test_payload_hash_is_idempotency_not_tamper_evidence():
    db = _db()
    outcome = _seed_allow_read(db, execution_id="exec-idem")
    event = db.query(models.Event).filter_by(id=outcome.event.id).one()
    event.decision = "APPROVAL"
    event.seq = 7
    event.reason = "mutated fields payload_hash does not cover"
    db.commit()
    replay = _authorize(
        db,
        _agent(db),
        request_id=event.request_id,
        execution_id="exec-idem",
        payload={"id": "1", "name": "Ada"},
    )
    assert replay.replayed is True
    assert replay.event.decision == "APPROVAL"
    assert replay.event.seq == 7


def test_seq_has_no_unique_constraint():
    db = _db()
    _seed_allow_read(db, execution_id="exec-seq")
    db.add(
        models.Event(
            organization_id="org-1",
            agent_id="agent-1",
            execution_id="exec-seq",
            seq=1,
            resource_kind="crm",
            action="READ",
            scope="customers",
            decision="ALLOW",
            request_id=str(uuid4()),
        )
    )
    db.commit()
    rows = (
        db.query(models.Event)
        .filter(models.Event.execution_id == "exec-seq", models.Event.seq == 1)
        .all()
    )
    assert len(rows) == 2
    inspector = sa_inspect(db.get_bind())
    uniques = []
    for constraint in inspector.get_unique_constraints("events"):
        uniques.extend(constraint.get("column_names") or [])
    assert "seq" not in uniques
    assert "request_id" not in uniques


def test_events_http_api_is_read_only():
    router_source = _source(APP_ROOT / "routers" / "resources.py")
    assert "@router.get(\"/events\"" in router_source
    assert "@router.post(\"/events\"" not in router_source
    assert "@router.put(\"/events\"" not in router_source
    assert "@router.delete(\"/events\"" not in router_source
    assert "@router.patch(\"/events\"" not in router_source
    schema_source = _source(APP_ROOT / "schemas.py")
    assert "payload_hash" not in schema_source.split("class EventOut")[1].split("class ")[0]
    list_events = getattr(resources_mod, "list_events")
    assert list_events is not None


def test_gateway_rewrites_committed_allow_event():
    source = _source(APP_ROOT / "routers" / "gateway.py")
    assert "event.decision = \"BLOCK\"" in source
    assert "db.commit()" in source


def test_sqlite_store_is_not_append_only():
    db = _db()
    engine = db.get_bind()
    journal = engine.connect().execute(text("PRAGMA journal_mode")).scalar()
    assert str(journal).lower() in {"delete", "memory", "wal", "off", "persist", "truncate"}
    queryable = engine.connect().execute(text("PRAGMA query_only")).scalar()
    assert int(queryable or 0) == 0


def test_eat_hmac_is_not_bound_to_event_row():
    eat_source = _source(APP_ROOT / "eat.py")
    assert "payload_hash" not in eat_source
    assert "event_id" not in eat_source
    enforcement_source = _source(APP_ROOT / "engines" / "enforcement.py")
    assert "sign_eat" not in enforcement_source
    assert "hmac" not in enforcement_source


def test_legitimate_allow_still_persists_payload_hash():
    db = _db()
    outcome = _seed_allow_read(db, execution_id="exec-legit")
    assert outcome.event.decision == "ALLOW"
    assert outcome.event.payload_hash == _payload_digest({"id": "1", "name": "Ada"})
    assert outcome.event.seq == 1
    assert outcome.event.request_id
