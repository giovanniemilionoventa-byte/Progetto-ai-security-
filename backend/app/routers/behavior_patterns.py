from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..engines.behavior import (
    PatternValidationError,
    validate_definition,
    validate_description,
    validate_name,
    validate_pattern_type,
    validate_severity,
)
from ..security import get_current_user, utcnow

router = APIRouter(prefix="/behavior-patterns", tags=["behavior-patterns"])


def _visible(db: Session, user: models.User):
    return db.query(models.BehaviorPattern).filter(
        or_(
            models.BehaviorPattern.organization_id.is_(None),
            models.BehaviorPattern.organization_id == user.organization_id,
        )
    )


def _get_visible(
    db: Session, user: models.User, pattern_id: str
) -> models.BehaviorPattern:
    pattern = _visible(db, user).filter(models.BehaviorPattern.id == pattern_id).first()
    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")
    return pattern


def _require_mutable(pattern: models.BehaviorPattern, user: models.User) -> None:
    if pattern.organization_id is None:
        raise HTTPException(status_code=403, detail="Global patterns are immutable")
    if pattern.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Pattern not found")


def _validated_fields(
    *,
    name: str,
    description: str,
    pattern_type: str,
    severity: str,
    definition: dict,
) -> dict:
    try:
        ptype = validate_pattern_type(pattern_type)
        return {
            "name": validate_name(name),
            "description": validate_description(description),
            "type": ptype,
            "severity": validate_severity(severity),
            "definition": validate_definition(ptype, definition),
        }
    except PatternValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc


@router.get("", response_model=list[schemas.BehaviorPatternOut])
def list_patterns(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        _visible(db, user)
        .order_by(
            models.BehaviorPattern.organization_id.isnot(None),
            models.BehaviorPattern.name.asc(),
        )
        .all()
    )


@router.get("/{pattern_id}", response_model=schemas.BehaviorPatternOut)
def get_pattern(
    pattern_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _get_visible(db, user, pattern_id)


@router.post("", response_model=schemas.BehaviorPatternOut, status_code=201)
def create_pattern(
    body: schemas.BehaviorPatternCreate,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    fields = _validated_fields(
        name=body.name,
        description=body.description,
        pattern_type=body.type,
        severity=body.severity,
        definition=body.definition,
    )
    pattern = models.BehaviorPattern(
        organization_id=user.organization_id,
        enabled=body.enabled,
        **fields,
    )
    db.add(pattern)
    db.commit()
    db.refresh(pattern)
    return pattern


@router.patch("/{pattern_id}", response_model=schemas.BehaviorPatternOut)
def update_pattern(
    pattern_id: str,
    body: schemas.BehaviorPatternUpdate,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    pattern = _get_visible(db, user, pattern_id)
    _require_mutable(pattern, user)
    data = body.model_dump(exclude_unset=True)
    name = data.get("name", pattern.name)
    description = data.get("description", pattern.description or "")
    pattern_type = data.get("type", pattern.type)
    severity = data.get("severity", pattern.severity)
    definition = data.get("definition", pattern.definition)
    fields = _validated_fields(
        name=name,
        description=description,
        pattern_type=pattern_type,
        severity=severity,
        definition=definition,
    )
    pattern.name = fields["name"]
    pattern.description = fields["description"]
    pattern.type = fields["type"]
    pattern.severity = fields["severity"]
    pattern.definition = fields["definition"]
    if "enabled" in data:
        pattern.enabled = bool(data["enabled"])
    pattern.updated_at = utcnow()
    db.commit()
    db.refresh(pattern)
    return pattern


@router.delete("/{pattern_id}", status_code=204)
def delete_pattern(
    pattern_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    pattern = _get_visible(db, user, pattern_id)
    _require_mutable(pattern, user)
    db.query(models.BehaviorSignal).filter(
        models.BehaviorSignal.pattern_id == pattern.id
    ).delete()
    db.delete(pattern)
    db.commit()
    return Response(status_code=204)
