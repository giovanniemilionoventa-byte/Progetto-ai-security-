from dataclasses import dataclass, field
import hashlib
import json
from typing import Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .. import config, models, schemas
from ..contract_store import ContractResolutionError, resolve_active_contract_for_agent
from ..security import utcnow
from ..services import approval_grant
from ..services.evidence_verifier import (
    EvidenceIntegrityError,
    assert_execution_evidence_integrity,
    record_integrity_failure,
    seal_execution_event,
)
from . import behavior as behavior_engine
from . import contract as contract_engine
from . import permission as permission_engine
from . import policy as policy_engine
from . import risk as risk_engine
from . import trajectory as trajectory_engine


@dataclass
class AuthorizationOutcome:
    event: models.Event
    approval_id: Optional[str]
    matches: list = field(default_factory=list)
    replayed: bool = False
    contract_id: Optional[str] = None
    contract_version: Optional[int] = None
    authorized_payload: Optional[dict] = None
    # Phase 17: set when this outcome is an execution authorized by a human
    # approval rather than by a direct ALLOW decision.
    approval_granted: bool = False
    approval_reason: Optional[str] = None


def _maybe_alert(db: Session, event: models.Event) -> None:
    if event.decision == "BLOCK" or event.risk_level in {"high", "critical"}:
        db.add(
            models.Alert(
                organization_id=event.organization_id,
                event_id=event.id,
                severity="critical" if event.decision == "BLOCK" else event.risk_level,
                title=f"{event.decision} {event.resource_kind}.{event.action}",
                message=event.reason,
                status="open",
            )
        )


def _effective_payload(body: schemas.AuthorizeRequest) -> Optional[dict]:
    """Payload that actually reaches runtime-contract data checks.

    Mirrors authorize_request resolution: body.payload wins, otherwise the
    metadata payload fallback. Only dict or None is enforceable; anything else
    is treated as absent (the contract layer already filters the same way).
    """
    payload = body.payload
    if payload is None and isinstance(body.metadata, dict):
        payload = body.metadata.get("payload")
    if payload is None or isinstance(payload, dict):
        return payload
    return None


def _payload_digest(payload: Optional[dict]) -> str:
    if payload is None:
        raw = "null"
    else:
        raw = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _idempotent_payload_matches(
    event: models.Event, body: schemas.AuthorizeRequest
) -> bool:
    kind = body.resource_kind.lower()
    act = body.action.upper()
    if event.resource_kind != kind or event.action != act:
        return False
    if event.scope != body.scope:
        return False
    if (event.destination or None) != (body.destination or None):
        return False
    if body.execution_id and event.execution_id and body.execution_id != event.execution_id:
        return False
    if event.payload_hash is not None:
        if event.payload_hash != _payload_digest(_effective_payload(body)):
            return False
    return True


def _resume_approved_request(
    db: Session,
    agent: models.Agent,
    original: models.Event,
    body: schemas.AuthorizeRequest,
) -> Optional[AuthorizationOutcome]:
    """Execute a request that a human has approved, exactly once.

    Returns None when there is no usable grant, so the caller falls back to the
    ordinary replay behaviour (the request stays APPROVAL and nothing runs).

    The approved execution is recorded as a *new* event in the same execution
    chain rather than by rewriting the APPROVAL event. The audit trail then
    reads as it actually happened: the agent asked, a human approved, and the
    action ran under that approval.
    """
    payload_hash = _payload_digest(_effective_payload(body))

    contract_id = None
    contract_version = None
    try:
        contract = resolve_active_contract_for_agent(db, agent)
    except ContractResolutionError:
        contract = None
    if contract is not None:
        contract_id = contract.contract_id
        contract_version = contract.version

    verdict = approval_grant.evaluate_grant(
        db,
        agent=agent,
        event=original,
        resource_kind=body.resource_kind.lower(),
        action=body.action.upper(),
        scope=body.scope,
        destination=body.destination,
        payload_hash=payload_hash,
        contract_id=contract_id,
        contract_version=contract_version,
    )
    if not verdict.granted:
        return None

    # A revoked or expired contract must stop an approved action too: the human
    # approved an action under a contract, not in the abstract.
    if contract is None and config.REQUIRE_RUNTIME_CONTRACT:
        return None

    execution = (
        db.query(models.Execution)
        .filter(models.Execution.id == original.execution_id)
        .first()
    )
    if execution is None:
        return None

    try:
        assert_execution_evidence_integrity(db, execution.id)
    except EvidenceIntegrityError as exc:
        org_id = agent.organization_id
        exec_id = execution.id
        db.rollback()
        record_integrity_failure(
            db, organization_id=org_id, execution_id=exec_id, reason=exc.reason
        )
        db.commit()
        raise

    risk = risk_engine.evaluate(
        original.resource_kind,
        original.action,
        original.scope,
        original.destination,
        "ALLOW",
    )
    event = models.Event(
        organization_id=agent.organization_id,
        agent_id=agent.id,
        execution_id=execution.id,
        seq=behavior_engine.next_seq(db, execution.id),
        resource_kind=original.resource_kind,
        action=original.action,
        scope=original.scope,
        destination=original.destination,
        payload_hash=payload_hash,
        decision="ALLOW",
        risk_score=risk.score,
        risk_level=risk.level,
        reason=(
            f"Executed under human approval {verdict.approval.id} "
            f"reviewed by {verdict.approval.reviewed_by or 'operator'}."
        ),
        request_id=f"{original.request_id}:approved",
        created_at=utcnow(),
    )
    db.add(event)
    db.flush()
    seal_execution_event(db, event, execution)
    approval_grant.consume(db, verdict.approval, event.id)
    db.commit()

    return AuthorizationOutcome(
        event=event,
        approval_id=verdict.approval.id,
        replayed=False,
        contract_id=contract_id,
        contract_version=contract_version,
        authorized_payload=_effective_payload(body),
        approval_granted=True,
        approval_reason=verdict.reason,
    )


def authorize_request(
    db: Session,
    agent: models.Agent,
    body: schemas.AuthorizeRequest,
) -> AuthorizationOutcome:
    request_id = body.request_id or body.client_request_id or str(uuid4())

    existing = (
        db.query(models.Event)
        .filter(
            models.Event.request_id == request_id,
            models.Event.agent_id == agent.id,
        )
        .first()
    )
    if existing:
        if not _idempotent_payload_matches(existing, body):
            raise HTTPException(
                status_code=409,
                detail="Idempotency key reused with a different payload",
            )
        approval = (
            db.query(models.Approval)
            .filter(models.Approval.event_id == existing.id)
            .first()
        )
        if existing.decision == "APPROVAL":
            # Phase 17: re-submitting an approved request is how it executes.
            # The grant is checked against the request as it stands right now,
            # so nothing about it can have moved since the human said yes.
            granted = _resume_approved_request(db, agent, existing, body)
            if granted is not None:
                return granted
        return AuthorizationOutcome(
            event=existing,
            approval_id=approval.id if approval else None,
            replayed=True,
            authorized_payload=_effective_payload(body),
        )

    try:
        execution = behavior_engine.get_or_create_execution(
            db, agent, body.execution_id
        )
    except PermissionError:
        raise HTTPException(
            status_code=403, detail="Execution does not belong to this agent"
        )

    try:
        assert_execution_evidence_integrity(db, execution.id)
    except EvidenceIntegrityError as exc:
        org_id = agent.organization_id
        exec_id = execution.id
        db.rollback()
        record_integrity_failure(
            db,
            organization_id=org_id,
            execution_id=exec_id,
            reason=exc.reason,
        )
        db.commit()
        raise

    kind = body.resource_kind.lower()
    act = body.action.upper()
    payload = body.payload
    if payload is None and isinstance(body.metadata, dict):
        payload = body.metadata.get("payload")
    claimed = contract_engine.claimed_contract_id(body.metadata)
    permitted = permission_engine.allows(agent, kind, act, body.scope)

    previous = behavior_engine.reconstruct_trajectory(db, execution.id)
    current = behavior_engine.TrajectoryStep(
        resource_kind=kind,
        action=act,
        scope=body.scope,
        destination=body.destination,
        decision=None,
    )
    trajectory = previous + [current]
    matches = behavior_engine.evaluate(db, agent, trajectory)

    trajectory_state = trajectory_engine.reconstruct_trajectory_state(
        db,
        execution.id,
        organization_id=agent.organization_id,
        agent_id=agent.id,
    )
    authorized_progress = (
        trajectory_engine.authorized_trajectory(trajectory_state)
        if trajectory_state is not None
        else []
    )

    policy_result = policy_engine.evaluate(
        db,
        agent,
        kind,
        act,
        body.scope,
        body.destination,
        check_permission=False,
    )

    if not permitted:
        decision = "BLOCK"
        reason = (
            "Agent lacks permission for this resource/action/scope (least privilege)."
        )
    else:
        decision = policy_result.decision
        reason = policy_result.reason

    contract = None
    try:
        contract = resolve_active_contract_for_agent(
            db, agent, claimed_contract_id=claimed
        )
    except ContractResolutionError as exc:
        if exc.reason == "not_found":
            if claimed:
                decision = "BLOCK"
                reason = (
                    "Declared contract_id does not match the resolved runtime contract."
                )
            elif config.REQUIRE_RUNTIME_CONTRACT:
                # Phase 17: no contract is not a reason to proceed. Before this,
                # an agent with no contract at all fell through to permission +
                # policy alone, and the policy engine allows anything it has no
                # rule for -- a double default-permit.
                decision = "BLOCK"
                reason = "No runtime contract is active for this agent."
        else:
            decision = "BLOCK"
            reason = {
                "no_active_contract": (
                    "No runtime contract is active for this agent."
                    if not claimed
                    else "Declared contract_id does not match the resolved runtime contract."
                ),
                "contract_not_yet_valid": "Runtime contract is not yet valid.",
                "contract_expired": "Runtime contract has expired.",
                "untrusted_contract_id": (
                    "Declared contract_id does not match the resolved runtime contract."
                ),
                "ambiguous_active_contract": "Runtime contract is ambiguous.",
                "organization_mismatch": "Runtime contract organization mismatch.",
                "agent_mismatch": "Runtime contract agent mismatch.",
            }.get(exc.reason, "Runtime contract cannot be resolved.")
            contract = None
    else:
        verdict = contract_engine.evaluate_contract(
            contract,
            kind=kind,
            action=act,
            scope=body.scope,
            destination=body.destination,
            payload=payload if isinstance(payload, dict) or payload is None else None,
            previous=previous,
            current=current,
            claimed_contract_id=claimed,
            authorized_previous=authorized_progress,
        )
        if not verdict.allowed:
            if decision != "BLOCK":
                reason = verdict.reason
            decision = "BLOCK"

    risk = risk_engine.evaluate(
        kind,
        act,
        body.scope,
        body.destination,
        decision,
        behavior_signals=matches,
    )

    seq = behavior_engine.next_seq(db, execution.id)
    event = models.Event(
        organization_id=agent.organization_id,
        agent_id=agent.id,
        execution_id=execution.id,
        seq=seq,
        resource_kind=kind,
        action=act,
        scope=body.scope,
        destination=body.destination,
        payload_hash=_payload_digest(_effective_payload(body)),
        decision=decision,
        risk_score=risk.score,
        risk_level=risk.level,
        reason=reason,
        request_id=request_id,
        created_at=utcnow(),
    )
    db.add(event)
    db.flush()
    seal_execution_event(db, event, execution)
    behavior_engine.persist_signals(db, agent, execution, event, matches)
    _maybe_alert(db, event)

    approval_id = None
    if decision == "APPROVAL":
        # Phase 17: record everything the grant will later be checked against,
        # so approving this request cannot become authority for a different one.
        approval = models.Approval(
            organization_id=agent.organization_id,
            agent_id=agent.id,
            event_id=event.id,
            resource_kind=event.resource_kind,
            action=event.action,
            scope=event.scope,
            destination=event.destination,
            status="pending",
            reason=reason,
            execution_id=event.execution_id,
            request_id=event.request_id,
            contract_id=contract.contract_id if contract else None,
            contract_version=contract.version if contract else None,
            param_hash=event.payload_hash,
            expires_at=approval_grant.default_expiry(),
        )
        db.add(approval)
        db.flush()
        approval_id = approval.id

    db.commit()
    return AuthorizationOutcome(
        event=event,
        approval_id=approval_id,
        matches=matches,
        contract_id=contract.contract_id if contract else None,
        contract_version=contract.version if contract else None,
        authorized_payload=_effective_payload(body),
    )
