from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..security import get_current_user, utcnow

router = APIRouter(prefix="/approvals", tags=["approvals"])


@router.get("", response_model=list[schemas.ApprovalOut])
def list_approvals(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
    status_filter: str | None = None,
):
    q = db.query(models.Approval).filter(
        models.Approval.organization_id == user.organization_id
    )
    if status_filter:
        q = q.filter(models.Approval.status == status_filter)
    return q.order_by(models.Approval.created_at.desc()).limit(100).all()


@router.post("/{approval_id}/decide", response_model=schemas.ApprovalOut)
def decide(
    approval_id: str,
    body: schemas.ApprovalDecision,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    approval = (
        db.query(models.Approval)
        .filter(
            models.Approval.id == approval_id,
            models.Approval.organization_id == user.organization_id,
        )
        .first()
    )
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.status != "pending":
        raise HTTPException(status_code=400, detail="Already reviewed")
    decision = body.decision.upper()
    if decision not in {"ALLOW", "BLOCK"}:
        raise HTTPException(status_code=400, detail="Decision must be ALLOW or BLOCK")
    approval.status = "approved" if decision == "ALLOW" else "denied"
    approval.reviewed_by = user.id
    approval.reviewed_at = utcnow()
    db.commit()
    db.refresh(approval)
    return approval
