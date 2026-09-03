from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..security import get_current_user

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=list[schemas.PolicyOut])
def list_policies(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(models.Policy)
        .filter(models.Policy.organization_id == user.organization_id)
        .order_by(models.Policy.priority.asc())
        .all()
    )


@router.post("", response_model=schemas.PolicyOut)
def create_policy(
    body: schemas.PolicyCreate,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    decision = body.decision.upper()
    if decision not in {"ALLOW", "BLOCK", "APPROVAL"}:
        raise HTTPException(status_code=400, detail="Decision must be ALLOW, BLOCK or APPROVAL")
    policy = models.Policy(
        organization_id=user.organization_id,
        name=body.name,
        description=body.description,
        resource_kind=body.resource_kind.lower(),
        action=body.action.upper(),
        scope_pattern=body.scope_pattern,
        destination_pattern=body.destination_pattern,
        decision=decision,
        priority=body.priority,
        enabled=body.enabled,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.post("/{policy_id}/toggle", response_model=schemas.PolicyOut)
def toggle_policy(
    policy_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    policy = (
        db.query(models.Policy)
        .filter(
            models.Policy.id == policy_id,
            models.Policy.organization_id == user.organization_id,
        )
        .first()
    )
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.enabled = not policy.enabled
    db.commit()
    db.refresh(policy)
    return policy
