"""Runtime Contract management API (Phase 17).

Until Phase 17 the Runtime Contract had no HTTP surface at all: the schemas
existed in schemas.py but no router imported them, so the only way to create a
contract was to call contract_store.save_contract() from Python. That is why no
deployment and no benchmark ever ran with a contract active.

This router is that missing surface. It is control-plane only and requires an
authenticated operator; an agent token is rejected by the control-plane
middleware in main.py before it reaches here, so an agent can never author or
alter the contract that governs it.

Identity is taken from the authenticated operator's organization, never from the
request body, so an operator cannot write a contract into another tenant.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from .. import config, models, schemas
from ..contract_store import (
    ContractResolutionError,
    ContractStoreError,
    get_contract,
    list_contract_versions,
    resolve_active_contract,
    save_contract,
    transition_contract_status,
)
from ..database import get_db
from ..runtime_contract import ContractValidationError
from ..security import get_current_user

router = APIRouter(prefix="/agents/{agent_id}/contracts", tags=["runtime-contracts"])


def _agent_or_404(db: Session, user: models.User, agent_id: str) -> models.Agent:
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


@router.get("", response_model=list[schemas.RuntimeContractOut])
def list_contracts(
    agent_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    agent = _agent_or_404(db, user, agent_id)
    return (
        db.query(models.RuntimeContract)
        .filter(
            models.RuntimeContract.organization_id == agent.organization_id,
            models.RuntimeContract.agent_id == agent.id,
        )
        .order_by(
            models.RuntimeContract.contract_id.asc(),
            models.RuntimeContract.version.asc(),
        )
        .all()
    )


@router.get("/active", response_model=schemas.RuntimeContractOut)
def get_active_contract(
    agent_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    agent = _agent_or_404(db, user, agent_id)
    try:
        return resolve_active_contract(db, agent.organization_id, agent.id)
    except ContractResolutionError as exc:
        raise HTTPException(
            status_code=404, detail=f"No active runtime contract: {exc.reason}"
        ) from exc


@router.post("", response_model=schemas.RuntimeContractOut, status_code=201)
def create_contract(
    agent_id: str,
    body: schemas.RuntimeContractDocument,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a contract version.

    organization_id and agent_id are overwritten from the authenticated
    operator and the path, so a body claiming another tenant cannot take effect.
    """
    agent = _agent_or_404(db, user, agent_id)
    document = body.model_dump(mode="json", exclude_none=False)
    document["organization_id"] = agent.organization_id
    document["agent_id"] = agent.id
    # validate_runtime_contract distinguishes "absent" from "present but null":
    # an explicit null for integrity, valid_from or expires_at is an error,
    # while workflow=None legitimately means "no workflow for this contract".
    document = {
        key: value
        for key, value in document.items()
        if value is not None or key == "workflow"
    }
    try:
        row = save_contract(db, document)
    except ContractValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc
    except ContractStoreError as exc:
        raise HTTPException(status_code=409, detail=exc.reason) from exc
    db.commit()
    db.refresh(row)
    return row


@router.get("/{contract_id}/versions", response_model=list[schemas.RuntimeContractOut])
def list_versions(
    agent_id: str,
    contract_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    agent = _agent_or_404(db, user, agent_id)
    rows = list_contract_versions(db, agent.organization_id, agent.id, contract_id)
    if not rows:
        raise HTTPException(status_code=404, detail="Contract not found")
    return rows


@router.get("/{contract_id}/{version}", response_model=schemas.RuntimeContractOut)
def get_one(
    agent_id: str,
    contract_id: str,
    version: int,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    agent = _agent_or_404(db, user, agent_id)
    try:
        return get_contract(db, agent.organization_id, agent.id, contract_id, version)
    except ContractResolutionError as exc:
        raise HTTPException(status_code=404, detail=exc.reason) from exc


@router.post(
    "/{contract_id}/{version}/status", response_model=schemas.RuntimeContractOut
)
def set_status(
    agent_id: str,
    contract_id: str,
    version: int,
    body: schemas.RuntimeContractStatusChange,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Apply a lifecycle transition (DRAFT -> ACTIVE -> SUPERSEDED/REVOKED/EXPIRED).

    Terminal states never return to ACTIVE, and at most one contract may be
    ACTIVE per agent; both rules live in contract_store and are enforced there.
    """
    agent = _agent_or_404(db, user, agent_id)
    try:
        row = transition_contract_status(
            db,
            agent.organization_id,
            agent.id,
            contract_id,
            version,
            body.status,
        )
    except ContractResolutionError as exc:
        raise HTTPException(status_code=404, detail=exc.reason) from exc
    except ContractStoreError as exc:
        raise HTTPException(status_code=409, detail=exc.reason) from exc
    db.commit()
    db.refresh(row)
    return row


@router.delete("/{contract_id}/{version}", status_code=204)
def revoke_contract(
    agent_id: str,
    contract_id: str,
    version: int,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoking is a lifecycle transition, not a delete.

    Evidence refers to contracts by id and version, so rows are never removed.
    """
    agent = _agent_or_404(db, user, agent_id)
    try:
        transition_contract_status(
            db, agent.organization_id, agent.id, contract_id, version, "REVOKED"
        )
    except ContractResolutionError as exc:
        raise HTTPException(status_code=404, detail=exc.reason) from exc
    except ContractStoreError as exc:
        raise HTTPException(status_code=409, detail=exc.reason) from exc
    db.commit()
    return Response(status_code=204)


enforcement_router = APIRouter(tags=["runtime-contracts"])


@enforcement_router.get("/runtime-contract/policy")
def contract_policy():
    """Whether this deployment requires an active contract. Read-only."""
    return {
        "require_runtime_contract": config.REQUIRE_RUNTIME_CONTRACT,
        "mode": "fail-closed" if config.REQUIRE_RUNTIME_CONTRACT else "legacy-passthrough",
    }
