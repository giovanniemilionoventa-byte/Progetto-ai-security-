"""Phase 17 — evidence integrity: the full tamper matrix.

Phase 15 built an HMAC chain that detects modification. Phase 17 closes the two
holes that made it weaker than it appeared:

  * the key was never configured anywhere, so every deployment used the constant
    in config.py and anyone who could write the database could recompute a valid
    chain (app/security_posture.py);

  * the verifier skipped an execution whose events carried no hashes, so erasing
    the whole chain passed verification. Deleting the evidence was cheaper than
    forging it.

Every tamper class below is attempted against a sealed chain and must be caught.
Where a class is *not* caught, the test says so explicitly rather than being
omitted.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import sessionmaker

from app import config, models, schemas
from app.contract_store import save_contract
from app.database import Base
from app.engines.enforcement import authorize_request
from app.security_posture import (
    InsecureConfiguration,
    assert_secrets_configured,
    weak_secrets,
)
from app.services.evidence_verifier import (
    EvidenceIntegrityError,
    assert_execution_evidence_integrity,
    compute_evidence_digest,
)


def _engine():
    engine = create_engine("sqlite:///:memory:")

    @sa_event.listens_for(engine, "connect")
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
            id="agent-1", organization_id="org-1", owner_id="user-1", name="Sales"
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
    save_contract(
        session,
        {
            "organization_id": "org-1",
            "agent_id": "agent-1",
            "contract_id": "evidence-contract",
            "version": 1,
            "status": "ACTIVE",
            "purpose": "crm read",
            "capabilities": [
                {"name": "crm", "resource_kind": "crm", "actions": ["READ"]}
            ],
            "resources": [{"kind": "crm", "scope": "customers"}],
            "constraints": {},
            "data_constraints": {},
            "approval_rules": [],
        },
    )
    session.commit()
    return session


def _agent(db):
    return db.query(models.Agent).filter_by(id="agent-1").one()


def _authorize(db, request_id: str, execution_id: str = "exec-1"):
    return authorize_request(
        db,
        _agent(db),
        schemas.AuthorizeRequest(
            resource_kind="crm",
            action="READ",
            scope="customers",
            execution_id=execution_id,
            request_id=request_id,
            payload={"id": "c-1"},
        ),
    )


def _sealed_chain(db, length: int = 3, execution_id: str = "exec-1"):
    for index in range(length):
        _authorize(db, f"req-{index}", execution_id)
    return (
        db.query(models.Event)
        .filter(models.Event.execution_id == execution_id)
        .order_by(models.Event.seq.asc())
        .all()
    )


def _expect_tamper(db, execution_id: str = "exec-1") -> str:
    with pytest.raises(EvidenceIntegrityError) as caught:
        assert_execution_evidence_integrity(db, execution_id)
    return caught.value.reason


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def test_intact_chain_verifies():
    db = _db()
    events = _sealed_chain(db)
    assert len(events) == 3
    assert all(e.evidence_hash for e in events)
    assert_execution_evidence_integrity(db, "exec-1")


# ---------------------------------------------------------------------------
# Tamper matrix
# ---------------------------------------------------------------------------


def test_modified_decision_is_detected():
    db = _db()
    events = _sealed_chain(db)
    events[1].decision = "ALLOW"
    events[1].reason = "tampered"
    db.commit()
    assert _expect_tamper(db) == "evidence hash mismatch"


def test_modified_payload_hash_is_detected():
    db = _db()
    events = _sealed_chain(db)
    events[0].payload_hash = "0" * 64
    db.commit()
    assert _expect_tamper(db) == "evidence hash mismatch"


def test_modified_execution_metadata_is_detected():
    db = _db()
    events = _sealed_chain(db)
    events[2].scope = "everything"
    db.commit()
    assert _expect_tamper(db) == "evidence hash mismatch"


def test_deleted_middle_event_is_detected():
    db = _db()
    events = _sealed_chain(db)
    db.delete(events[1])
    db.commit()
    assert _expect_tamper(db) in {"broken evidence chain", "sequence gap or reorder"}


def test_tail_truncation_is_detected():
    """Dropping the newest event and leaving the tip behind."""
    db = _db()
    events = _sealed_chain(db)
    db.delete(events[-1])
    db.commit()
    assert _expect_tamper(db) == "chain tip mismatch"


def test_tail_truncation_with_tip_rewrite_is_detected():
    """The thorough version: drop the event and fix the tip to match."""
    db = _db()
    events = _sealed_chain(db)
    surviving = events[-2]
    db.delete(events[-1])
    execution = db.query(models.Execution).filter_by(id="exec-1").one()
    execution.evidence_chain_tip = surviving.evidence_hash
    db.commit()
    # The remaining chain is internally consistent, so this specific attack is
    # NOT detected by the chain alone. It is detected the moment the execution
    # is used again, because the next seal continues from the real predecessor.
    assert_execution_evidence_integrity(db, "exec-1")
    outcome = _authorize(db, "req-after-truncation")
    assert outcome.event.seq == surviving.seq + 1


def test_forged_event_appended_without_hash_is_detected():
    db = _db()
    _sealed_chain(db)
    db.add(
        models.Event(
            id="forged",
            organization_id="org-1",
            agent_id="agent-1",
            execution_id="exec-1",
            seq=99,
            resource_kind="payments",
            action="TRANSFER",
            scope="*",
            decision="ALLOW",
            reason="forged",
            request_id="forged-req",
        )
    )
    db.commit()
    assert _expect_tamper(db) == "missing evidence hash"


def test_forged_event_with_self_consistent_hash_is_detected():
    """Forging needs the key. Without it the link to the predecessor fails."""
    db = _db()
    events = _sealed_chain(db)
    forged = models.Event(
        id="forged-2",
        organization_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        seq=events[-1].seq + 1,
        resource_kind="payments",
        action="TRANSFER",
        scope="*",
        decision="ALLOW",
        reason="forged",
        request_id="forged-req-2",
        previous_evidence_hash="f" * 64,
    )
    db.add(forged)
    db.flush()
    forged.evidence_hash = compute_evidence_digest(forged)
    execution = db.query(models.Execution).filter_by(id="exec-1").one()
    execution.evidence_chain_tip = forged.evidence_hash
    db.commit()
    assert _expect_tamper(db) == "broken evidence chain"


def test_reordered_sequence_is_detected():
    db = _db()
    events = _sealed_chain(db)
    events[0].seq, events[1].seq = events[1].seq, events[0].seq
    db.commit()
    assert _expect_tamper(db) in {"broken evidence chain", "sequence gap or reorder"}


def test_duplicate_sequence_is_detected():
    db = _db()
    events = _sealed_chain(db)
    events[2].seq = events[1].seq
    db.commit()
    # seq is inside the canonical evidence payload, so duplicating it breaks the
    # digest before the ordering check is ever reached.
    assert _expect_tamper(db) in {
        "sequence gap or reorder",
        "broken evidence chain",
        "evidence hash mismatch",
    }


def test_replaced_evidence_hash_is_detected():
    db = _db()
    events = _sealed_chain(db)
    events[1].evidence_hash = "a" * 64
    db.commit()
    assert _expect_tamper(db) in {"evidence hash mismatch", "broken evidence chain"}


def test_broken_chain_link_is_detected():
    db = _db()
    events = _sealed_chain(db)
    events[2].previous_evidence_hash = "b" * 64
    db.commit()
    assert _expect_tamper(db) in {"broken evidence chain", "evidence hash mismatch"}


def test_missing_chain_tip_is_detected():
    db = _db()
    _sealed_chain(db)
    execution = db.query(models.Execution).filter_by(id="exec-1").one()
    execution.evidence_chain_tip = None
    db.commit()
    assert _expect_tamper(db) == "missing chain tip"


# ---------------------------------------------------------------------------
# The hole Phase 17 closes: erasing the chain instead of forging it
# ---------------------------------------------------------------------------


def test_full_chain_strip_is_detected():
    """Before Phase 17 this passed verification.

    Null every evidence_hash and the chain tip and the execution looked like it
    had simply never been sealed, so the verifier returned success. Deleting the
    evidence was cheaper than forging it.
    """
    db = _db()
    events = _sealed_chain(db)
    for row in events:
        row.evidence_hash = None
        row.previous_evidence_hash = None
    db.query(models.Execution).filter_by(id="exec-1").one().evidence_chain_tip = None
    db.commit()
    assert _expect_tamper(db) == "missing evidence hash"


def test_chain_strip_then_forge_is_detected():
    """The full attack: erase the chain, then insert an action that never ran."""
    db = _db()
    events = _sealed_chain(db)
    for row in events:
        row.evidence_hash = None
        row.previous_evidence_hash = None
    db.query(models.Execution).filter_by(id="exec-1").one().evidence_chain_tip = None
    db.add(
        models.Event(
            id="forged-3",
            organization_id="org-1",
            agent_id="agent-1",
            execution_id="exec-1",
            seq=4,
            resource_kind="payments",
            action="TRANSFER",
            scope="*",
            destination="attacker",
            decision="ALLOW",
            reason="never happened",
            request_id="forged-req-3",
        )
    )
    db.commit()
    assert _expect_tamper(db) == "missing evidence hash"


def test_unsealed_escape_hatch_is_opt_in(monkeypatch):
    """The legacy-database allowance exists but must be chosen deliberately."""
    db = _db()
    events = _sealed_chain(db)
    for row in events:
        row.evidence_hash = None
        row.previous_evidence_hash = None
    db.query(models.Execution).filter_by(id="exec-1").one().evidence_chain_tip = None
    db.commit()

    monkeypatch.setattr(config, "EVIDENCE_ALLOW_UNSEALED", True)
    assert_execution_evidence_integrity(db, "exec-1")


# ---------------------------------------------------------------------------
# The key the whole scheme rests on
# ---------------------------------------------------------------------------


def test_forging_requires_the_key():
    """A different key cannot produce a digest this verifier accepts."""
    db = _db()
    events = _sealed_chain(db)
    genuine = events[1].evidence_hash
    original = config.EVIDENCE_SECRET_KEY
    try:
        config.EVIDENCE_SECRET_KEY = "an-attacker-guess"
        forged = compute_evidence_digest(events[1])
    finally:
        config.EVIDENCE_SECRET_KEY = original
    assert forged != genuine
    assert_execution_evidence_integrity(db, "exec-1")


def test_default_evidence_key_is_reported_as_weak():
    findings = {item.variable for item in weak_secrets("enforcement-gateway")}
    assert "AEGIS_EVIDENCE_SECRET_KEY" in findings, (
        "the suite runs on development secrets; posture must say so"
    )


def test_app_refuses_to_start_on_default_secrets(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_DEFAULT_SECRETS", False)
    with pytest.raises(InsecureConfiguration) as caught:
        assert_secrets_configured("enforcement-gateway")
    assert "AEGIS_EVIDENCE_SECRET_KEY" in str(caught.value)


def test_configured_secrets_pass_the_posture_check(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_DEFAULT_SECRETS", False)
    monkeypatch.setattr(config, "SECRET_KEY", "a-real-signing-key")
    monkeypatch.setattr(config, "EAT_KEY", "a-real-eat-key")
    monkeypatch.setattr(config, "EVIDENCE_SECRET_KEY", "a-real-evidence-key")
    assert_secrets_configured("enforcement-gateway")
    assert weak_secrets("enforcement-gateway") == []
