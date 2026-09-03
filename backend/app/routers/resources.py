from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..security import get_current_user

router = APIRouter(tags=["control-plane"])


@router.get("/resources", response_model=list[schemas.ResourceOut])
def list_resources(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(models.Resource)
        .filter(models.Resource.organization_id == user.organization_id)
        .all()
    )


@router.post("/resources", response_model=schemas.ResourceOut)
def create_resource(
    body: schemas.ResourceCreate,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource = models.Resource(
        organization_id=user.organization_id,
        kind=body.kind.lower(),
        name=body.name,
        identifier=body.identifier,
        sensitivity=body.sensitivity,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)
    return resource


@router.get("/devices", response_model=list[schemas.DeviceOut])
def list_devices(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(models.Device)
        .filter(models.Device.organization_id == user.organization_id)
        .all()
    )


@router.get("/events", response_model=list[schemas.EventOut])
def list_events(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 100,
):
    return (
        db.query(models.Event)
        .filter(models.Event.organization_id == user.organization_id)
        .order_by(models.Event.created_at.desc())
        .limit(min(limit, 500))
        .all()
    )


@router.get("/alerts", response_model=list[schemas.AlertOut])
def list_alerts(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(models.Alert)
        .filter(models.Alert.organization_id == user.organization_id)
        .order_by(models.Alert.created_at.desc())
        .limit(100)
        .all()
    )


@router.get("/stats", response_model=schemas.DashboardStats)
def stats(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    oid = user.organization_id
    agents = db.query(models.Agent).filter(models.Agent.organization_id == oid).count()
    events = db.query(models.Event).filter(models.Event.organization_id == oid).count()
    blocked = (
        db.query(models.Event)
        .filter(models.Event.organization_id == oid, models.Event.decision == "BLOCK")
        .count()
    )
    pending = (
        db.query(models.Approval)
        .filter(
            models.Approval.organization_id == oid,
            models.Approval.status == "pending",
        )
        .count()
    )
    alerts = (
        db.query(models.Alert)
        .filter(models.Alert.organization_id == oid, models.Alert.status == "open")
        .count()
    )
    allowed = (
        db.query(models.Event)
        .filter(models.Event.organization_id == oid, models.Event.decision == "ALLOW")
        .count()
    )
    rate = (allowed / events * 100) if events else 0.0
    return schemas.DashboardStats(
        agents=agents,
        events=events,
        blocked=blocked,
        pending_approvals=pending,
        open_alerts=alerts,
        allow_rate=round(rate, 1),
    )
