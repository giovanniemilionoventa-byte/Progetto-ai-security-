from dataclasses import dataclass, field
from typing import Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..contract_store import ContractResolutionError, resolve_active_contract_for_agent
from ..security import utcnow
from . import behavior as behavior_engine
from . import contract as contract_engine
from . import permission as permission_engine
from . import policy as policy_engine
from . import risk as risk_engine


@dataclass
class AuthorizationOutcome:
    event: models.Event
    approval_id: Optional[str]
    matches: list = field(default_factory=list)
    replayed: bool = False
    contract_id: Optional[str] = None
    contract_version: Optional[int] = None


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
    return True


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
        return AuthorizationOutcome(
            event=existing,
            approval_id=approval.id if approval else None,
            replayed=True,
        )

    try:
        execution = behavior_engine.get_or_create_execution(
            db, agent, body.execution_id
        )
    except PermissionError:
        raise HTTPException(
            status_code=403, detail="Execution does not belong to this agent"
        )

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
    )
    trajectory = previous + [current]
    matches = behavior_engine.evaluate(db, agent, trajectory)

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
        decision=decision,
        risk_score=risk.score,
        risk_level=risk.level,
        reason=reason,
        request_id=request_id,
        created_at=utcnow(),
    )
    db.add(event)
    db.flush()
    behavior_engine.persist_signals(db, agent, execution, event, matches)
    _maybe_alert(db, event)

    approval_id = None
    if decision == "APPROVAL":
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
    )
