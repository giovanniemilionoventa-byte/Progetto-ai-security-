from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session

from .. import models
from ..contract_store import ContractResolutionError, resolve_active_contract
from .behavior import TrajectoryStep

PROGRESS_DECISION = "ALLOW"


@dataclass(frozen=True)
class TrajectoryAction:
    seq: int
    request_id: str
    resource_kind: str
    action: str
    scope: str
    destination: Optional[str]
    decision: str
    reason: str


@dataclass(frozen=True)
class TrajectoryState:
    execution_id: str
    organization_id: str
    agent_id: str
    contract_id: Optional[str]
    contract_version: Optional[int]
    events: tuple[TrajectoryAction, ...]
    authorized_actions: tuple[TrajectoryAction, ...]
    last_valid_progress: Optional[TrajectoryAction]
    terminal_status: Optional[str]


def is_progress_decision(decision: Optional[str]) -> bool:
    return decision == PROGRESS_DECISION


def owned_execution_events(db: Session, execution_id: str) -> list[models.Event]:
    execution = (
        db.query(models.Execution)
        .filter(models.Execution.id == execution_id)
        .first()
    )
    query = db.query(models.Event).filter(models.Event.execution_id == execution_id)
    if execution is not None:
        query = query.filter(
            models.Event.organization_id == execution.organization_id,
            models.Event.agent_id == execution.agent_id,
        )
    return query.order_by(
        models.Event.seq.asc(),
        models.Event.created_at.asc(),
        models.Event.id.asc(),
    ).all()


def reconstruct_trajectory(db: Session, execution_id: str) -> list[TrajectoryStep]:
    return [
        TrajectoryStep(
            resource_kind=event.resource_kind,
            action=event.action,
            scope=event.scope,
            destination=event.destination,
            decision=event.decision,
        )
        for event in owned_execution_events(db, execution_id)
    ]


def _action_from_event(event: models.Event) -> TrajectoryAction:
    return TrajectoryAction(
        seq=int(event.seq or 0),
        request_id=event.request_id,
        resource_kind=event.resource_kind,
        action=event.action,
        scope=event.scope,
        destination=event.destination,
        decision=event.decision,
        reason=event.reason or "",
    )


def _bound_contract(
    db: Session, execution: models.Execution
) -> tuple[Optional[str], Optional[int]]:
    try:
        contract = resolve_active_contract(
            db, execution.organization_id, execution.agent_id
        )
    except ContractResolutionError:
        return None, None
    return contract.contract_id, contract.version


def state_from_actions(
    execution: models.Execution,
    actions: tuple[TrajectoryAction, ...],
    *,
    contract_id: Optional[str] = None,
    contract_version: Optional[int] = None,
) -> TrajectoryState:
    authorized = tuple(
        item for item in actions if is_progress_decision(item.decision)
    )
    return TrajectoryState(
        execution_id=execution.id,
        organization_id=execution.organization_id,
        agent_id=execution.agent_id,
        contract_id=contract_id,
        contract_version=contract_version,
        events=actions,
        authorized_actions=authorized,
        last_valid_progress=authorized[-1] if authorized else None,
        terminal_status=None,
    )


def reconstruct_trajectory_state(
    db: Session,
    execution_id: str,
    *,
    organization_id: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> Optional[TrajectoryState]:
    execution = (
        db.query(models.Execution)
        .filter(models.Execution.id == execution_id)
        .first()
    )
    if execution is None:
        return None
    if organization_id is not None and execution.organization_id != organization_id:
        return None
    if agent_id is not None and execution.agent_id != agent_id:
        return None
    actions = tuple(
        _action_from_event(event) for event in owned_execution_events(db, execution.id)
    )
    contract_id, contract_version = _bound_contract(db, execution)
    return state_from_actions(
        execution,
        actions,
        contract_id=contract_id,
        contract_version=contract_version,
    )


def authorized_trajectory(state: TrajectoryState) -> list[TrajectoryStep]:
    return [
        TrajectoryStep(
            resource_kind=item.resource_kind,
            action=item.action,
            scope=item.scope,
            destination=item.destination,
            decision=item.decision,
        )
        for item in state.authorized_actions
    ]
