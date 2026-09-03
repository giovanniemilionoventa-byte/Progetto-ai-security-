from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..security import create_agent_token, get_current_user, hash_token

router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("", response_model=list[schemas.AgentOut])
def list_agents(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(models.Agent)
        .filter(models.Agent.organization_id == user.organization_id)
        .order_by(models.Agent.created_at.desc())
        .all()
    )


@router.post("", response_model=schemas.AgentCredentialOut)
def create_agent(
    body: schemas.AgentCreate,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    agent = models.Agent(
        organization_id=user.organization_id,
        owner_id=user.id,
        name=body.name,
        provider=body.provider,
        model=body.model,
        description=body.description,
    )
    db.add(agent)
    db.flush()
    token = create_agent_token()
    cred = models.Credential(
        agent_id=agent.id,
        token_hash=hash_token(token),
        token_prefix=token[:16],
        status="active",
    )
    db.add(cred)
    db.commit()
    db.refresh(agent)
    return schemas.AgentCredentialOut(
        agent=agent, token=token, token_prefix=cred.token_prefix
    )


@router.get("/{agent_id}", response_model=schemas.AgentOut)
def get_agent(
    agent_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    agent = (
        db.query(models.Agent)
        .filter(
            models.Agent.id == agent_id,
            models.Agent.organization_id == user.organization_id,
        )
        .first()
    )
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.post("/{agent_id}/revoke", response_model=schemas.AgentOut)
def revoke_agent(
    agent_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    agent = (
        db.query(models.Agent)
        .filter(
            models.Agent.id == agent_id,
            models.Agent.organization_id == user.organization_id,
        )
        .first()
    )
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    now = datetime.now(timezone.utc)
    agent.status = "revoked"
    agent.revoked_at = now
    for cred in agent.credentials:
        cred.status = "revoked"
        cred.revoked_at = now
    db.commit()
    db.refresh(agent)
    return agent


@router.post("/{agent_id}/rotate", response_model=schemas.AgentCredentialOut)
def rotate_credential(
    agent_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    agent = (
        db.query(models.Agent)
        .filter(
            models.Agent.id == agent_id,
            models.Agent.organization_id == user.organization_id,
        )
        .first()
    )
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.status != "active":
        raise HTTPException(status_code=400, detail="Agent is revoked")
    now = datetime.now(timezone.utc)
    for cred in agent.credentials:
        if cred.status == "active":
            cred.status = "rotated"
            cred.revoked_at = now
    token = create_agent_token()
    cred = models.Credential(
        agent_id=agent.id,
        token_hash=hash_token(token),
        token_prefix=token[:16],
        status="active",
    )
    db.add(cred)
    db.commit()
    db.refresh(agent)
    return schemas.AgentCredentialOut(
        agent=agent, token=token, token_prefix=cred.token_prefix
    )


@router.get("/{agent_id}/permissions", response_model=list[schemas.PermissionOut])
def list_permissions(
    agent_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    agent = (
        db.query(models.Agent)
        .filter(
            models.Agent.id == agent_id,
            models.Agent.organization_id == user.organization_id,
        )
        .first()
    )
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent.permissions


@router.post("/{agent_id}/permissions", response_model=schemas.PermissionOut)
def add_permission(
    agent_id: str,
    body: schemas.PermissionCreate,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    agent = (
        db.query(models.Agent)
        .filter(
            models.Agent.id == agent_id,
            models.Agent.organization_id == user.organization_id,
        )
        .first()
    )
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    perm = models.Permission(
        agent_id=agent.id,
        resource_kind=body.resource_kind.lower(),
        action=body.action.upper(),
        scope=body.scope,
        effect=body.effect.lower(),
    )
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return perm
