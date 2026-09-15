from __future__ import annotations

import hashlib
import hmac
import json
from typing import Optional

from sqlalchemy.orm import Session

from .. import config, models
from ..engines.trajectory import owned_execution_events

GENESIS_EVIDENCE_HASH = "0" * 64


class EvidenceIntegrityError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _secret_bytes() -> bytes:
    key = (config.EVIDENCE_SECRET_KEY or "").strip()
    if not key:
        raise EvidenceIntegrityError("evidence secret key missing")
    return key.encode("utf-8")


def canonical_evidence_payload(event: models.Event) -> bytes:
    body = {
        "action": event.action or "",
        "agent_id": event.agent_id or "",
        "decision": event.decision or "",
        "destination": event.destination or "",
        "execution_id": event.execution_id or "",
        "id": event.id or "",
        "organization_id": event.organization_id or "",
        "payload_hash": event.payload_hash or "",
        "previous_evidence_hash": event.previous_evidence_hash or GENESIS_EVIDENCE_HASH,
        "reason": event.reason or "",
        "request_id": event.request_id or "",
        "resource_kind": event.resource_kind or "",
        "risk_level": event.risk_level or "",
        "risk_score": float(event.risk_score or 0.0),
        "scope": event.scope or "",
        "seq": int(event.seq or 0),
    }
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def compute_evidence_digest(event: models.Event) -> str:
    return hmac.new(_secret_bytes(), canonical_evidence_payload(event), hashlib.sha256).hexdigest()


def _digests_match(left: Optional[str], right: Optional[str]) -> bool:
    if not left or not right:
        return False
    try:
        return hmac.compare_digest(str(left), str(right))
    except (TypeError, ValueError):
        return False


def record_integrity_failure(
    db: Session,
    *,
    organization_id: str,
    execution_id: Optional[str],
    reason: str,
) -> None:
    db.add(
        models.Alert(
            organization_id=organization_id,
            event_id=None,
            severity="critical",
            title="Execution evidence integrity failure",
            message=f"execution_id={execution_id or '-'}: {reason}",
            status="open",
        )
    )


def seal_execution_event(
    db: Session,
    event: models.Event,
    execution: models.Execution,
) -> None:
    if not event.id:
        raise EvidenceIntegrityError("event id required before sealing")
    predecessor = (
        db.query(models.Event)
        .filter(
            models.Event.execution_id == execution.id,
            models.Event.id != event.id,
            models.Event.evidence_hash.isnot(None),
        )
        .order_by(
            models.Event.seq.desc(),
            models.Event.created_at.desc(),
            models.Event.id.desc(),
        )
        .first()
    )
    if predecessor is None:
        previous = GENESIS_EVIDENCE_HASH
    else:
        previous = predecessor.evidence_hash
        if execution.evidence_chain_tip and not _digests_match(
            execution.evidence_chain_tip, previous
        ):
            raise EvidenceIntegrityError("chain tip does not match predecessor")
    event.previous_evidence_hash = previous
    event.evidence_hash = compute_evidence_digest(event)
    execution.evidence_chain_tip = event.evidence_hash


def reseal_execution_event(db: Session, event: models.Event) -> None:
    if not event.id or not event.execution_id:
        return
    if not event.previous_evidence_hash:
        event.previous_evidence_hash = GENESIS_EVIDENCE_HASH
    event.evidence_hash = compute_evidence_digest(event)
    execution = (
        db.query(models.Execution)
        .filter(models.Execution.id == event.execution_id)
        .first()
    )
    if execution is None:
        return
    last = (
        db.query(models.Event)
        .filter(models.Event.execution_id == execution.id)
        .order_by(
            models.Event.seq.desc(),
            models.Event.created_at.desc(),
            models.Event.id.desc(),
        )
        .first()
    )
    if last is None or last.id == event.id:
        execution.evidence_chain_tip = event.evidence_hash


def backfill_execution_evidence(db: Session, execution_id: str) -> None:
    execution = (
        db.query(models.Execution)
        .filter(models.Execution.id == execution_id)
        .first()
    )
    if execution is None:
        raise EvidenceIntegrityError("execution not found")
    previous = GENESIS_EVIDENCE_HASH
    for event in owned_execution_events(db, execution_id):
        if not event.id:
            raise EvidenceIntegrityError("event id required before sealing")
        event.previous_evidence_hash = previous
        event.evidence_hash = compute_evidence_digest(event)
        previous = event.evidence_hash
    execution.evidence_chain_tip = previous if previous != GENESIS_EVIDENCE_HASH else None


def assert_execution_evidence_integrity(
    db: Session,
    execution_id: Optional[str],
) -> None:
    if not execution_id:
        return
    execution = (
        db.query(models.Execution)
        .filter(models.Execution.id == execution_id)
        .first()
    )
    if execution is None:
        return
    events = owned_execution_events(db, execution_id)
    if not events:
        if execution.evidence_chain_tip:
            raise EvidenceIntegrityError("evidence chain tip present but no events")
        return

    # Phase 17. This used to read:
    #
    #     sealed = bool(chain_tip) or any(event.evidence_hash for event in events)
    #     if not sealed:
    #         return
    #
    # which meant an attacker who erased every evidence_hash and the chain tip
    # turned the execution back into "not sealed yet" and the verifier passed.
    # The chain detected modification but not deletion, so the cheapest attack
    # was to remove the evidence rather than forge it. Events now must be
    # sealed; an unsealed event in a stored execution is a tamper signal.
    unsealed = [event for event in events if not event.evidence_hash]
    if unsealed and config.EVIDENCE_ALLOW_UNSEALED:
        # Explicit opt-in for reading a pre-Phase-15 database.
        return
    previous = GENESIS_EVIDENCE_HASH
    last_seq: Optional[int] = None
    for event in events:
        if not event.evidence_hash:
            raise EvidenceIntegrityError("missing evidence hash")
        linked = event.previous_evidence_hash or GENESIS_EVIDENCE_HASH
        if not _digests_match(linked, previous):
            raise EvidenceIntegrityError("broken evidence chain")
        expected = compute_evidence_digest(event)
        if not _digests_match(event.evidence_hash, expected):
            raise EvidenceIntegrityError("evidence hash mismatch")
        seq = int(event.seq or 0)
        if last_seq is not None and seq != last_seq + 1:
            raise EvidenceIntegrityError("sequence gap or reorder")
        last_seq = seq
        previous = event.evidence_hash
    if not execution.evidence_chain_tip:
        raise EvidenceIntegrityError("missing chain tip")
    if not _digests_match(execution.evidence_chain_tip, events[-1].evidence_hash):
        raise EvidenceIntegrityError("chain tip mismatch")
