import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..engines import policy as policy_engine
from ..engines import risk as risk_engine
from ..security import get_agent_from_token, utcnow

router = APIRouter(tags=["enforcement"])


def _maybe_alert(db: Session, event: models.Event) -> None:
    if event.decision == "BLOCK" or event.risk_level in {"high", "critical"}:
        severity = "critical" if event.decision == "BLOCK" else event.risk_level
        db.add(
            models.Alert(
                organization_id=event.organization_id,
                event_id=event.id,
                severity=severity,
                title=f"{event.decision} {event.resource_kind}.{event.action}",
                message=event.reason,
                status="open",
            )
        )


@router.post("/authorize", response_model=schemas.AuthorizeResponse)
def authorize(
    body: schemas.AuthorizeRequest,
    agent: models.Agent = Depends(get_agent_from_token),
    db: Session = Depends(get_db),
):
    request_id = str(uuid.uuid4())
    policy_result = policy_engine.evaluate(
        db,
        agent,
        body.resource_kind,
        body.action,
        body.scope,
        body.destination,
    )
    risk = risk_engine.evaluate(
        body.resource_kind,
        body.action,
        body.scope,
        body.destination,
        policy_result.decision,
    )

    event = models.Event(
        organization_id=agent.organization_id,
        agent_id=agent.id,
        resource_kind=body.resource_kind.lower(),
        action=body.action.upper(),
        scope=body.scope,
        destination=body.destination,
        decision=policy_result.decision,
        risk_score=risk.score,
        risk_level=risk.level,
        reason=policy_result.reason,
        request_id=request_id,
    )
    db.add(event)
    db.flush()
    _maybe_alert(db, event)

    approval_id = None
    if policy_result.decision == "APPROVAL":
        approval = models.Approval(
            organization_id=agent.organization_id,
            agent_id=agent.id,
            event_id=event.id,
            resource_kind=event.resource_kind,
            action=event.action,
            scope=event.scope,
            destination=event.destination,
            status="pending",
            reason=policy_result.reason,
        )
        db.add(approval)
        db.flush()
        approval_id = approval.id

    db.commit()
    return schemas.AuthorizeResponse(
        request_id=request_id,
        decision=policy_result.decision,
        risk_score=risk.score,
        risk_level=risk.level,
        reason=policy_result.reason,
        approval_id=approval_id,
        agent_id=agent.id,
        organization_id=agent.organization_id,
    )
