from __future__ import annotations

from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import models
from .runtime_contract import validate_runtime_contract


class ContractStoreError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ContractResolutionError(LookupError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _row_from_validated(validated: dict) -> models.RuntimeContract:
    return models.RuntimeContract(
        organization_id=validated["organization_id"],
        agent_id=validated["agent_id"],
        contract_id=validated["contract_id"],
        version=validated["version"],
        status=validated["status"],
        purpose=validated["purpose"],
        capabilities=validated["capabilities"],
        resources=validated["resources"],
        constraints=validated["constraints"],
        data_constraints=validated["data_constraints"],
        workflow=validated["workflow"],
        approval_rules=validated["approval_rules"],
        valid_from=validated["valid_from"],
        expires_at=validated["expires_at"],
        integrity=validated["integrity"],
    )


def _active_rows(
    db: Session, organization_id: str, agent_id: str
) -> list[models.RuntimeContract]:
    return (
        db.query(models.RuntimeContract)
        .filter(
            models.RuntimeContract.organization_id == organization_id,
            models.RuntimeContract.agent_id == agent_id,
            models.RuntimeContract.status == "ACTIVE",
        )
        .all()
    )


def save_contract(db: Session, document: dict) -> models.RuntimeContract:
    validated = validate_runtime_contract(document)
    if validated["status"] == "ACTIVE":
        active = _active_rows(db, validated["organization_id"], validated["agent_id"])
        conflict = [
            row
            for row in active
            if not (
                row.contract_id == validated["contract_id"]
                and row.version == validated["version"]
            )
        ]
        if conflict:
            raise ContractStoreError("active_contract_exists")
    row = _row_from_validated(validated)
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError as exc:
        raise ContractStoreError("duplicate_identity") from exc
    return row


def get_contract(
    db: Session,
    organization_id: str,
    agent_id: str,
    contract_id: str,
    version: int,
) -> models.RuntimeContract:
    row = (
        db.query(models.RuntimeContract)
        .filter(
            models.RuntimeContract.organization_id == organization_id,
            models.RuntimeContract.agent_id == agent_id,
            models.RuntimeContract.contract_id == contract_id,
            models.RuntimeContract.version == version,
        )
        .first()
    )
    if row:
        return row
    other = (
        db.query(models.RuntimeContract)
        .filter(
            models.RuntimeContract.contract_id == contract_id,
            models.RuntimeContract.version == version,
        )
        .first()
    )
    if other is None:
        raise ContractResolutionError("not_found")
    if other.organization_id != organization_id:
        raise ContractResolutionError("organization_mismatch")
    if other.agent_id != agent_id:
        raise ContractResolutionError("agent_mismatch")
    raise ContractResolutionError("not_found")


def list_contract_versions(
    db: Session,
    organization_id: str,
    agent_id: str,
    contract_id: str,
) -> list[models.RuntimeContract]:
    return (
        db.query(models.RuntimeContract)
        .filter(
            models.RuntimeContract.organization_id == organization_id,
            models.RuntimeContract.agent_id == agent_id,
            models.RuntimeContract.contract_id == contract_id,
        )
        .order_by(models.RuntimeContract.version.asc())
        .all()
    )


def contract_exists(
    db: Session,
    organization_id: str,
    agent_id: str,
    contract_id: str,
    version: Optional[int] = None,
) -> bool:
    query = db.query(models.RuntimeContract).filter(
        models.RuntimeContract.organization_id == organization_id,
        models.RuntimeContract.agent_id == agent_id,
        models.RuntimeContract.contract_id == contract_id,
    )
    if version is not None:
        query = query.filter(models.RuntimeContract.version == version)
    return query.first() is not None


def get_contract_status(
    db: Session,
    organization_id: str,
    agent_id: str,
    contract_id: str,
    version: int,
) -> dict:
    row = get_contract(db, organization_id, agent_id, contract_id, version)
    return {"status": row.status, "version": row.version}


def select_active_contract(
    rows: list[models.RuntimeContract],
    organization_id: str,
    agent_id: str,
    claimed_contract_id: Optional[str] = None,
) -> models.RuntimeContract:
    if not organization_id or not agent_id:
        raise ContractResolutionError("identity_mismatch")
    scoped = [
        row
        for row in rows
        if row.organization_id == organization_id and row.agent_id == agent_id
    ]
    foreign = [
        row
        for row in rows
        if row.organization_id != organization_id or row.agent_id != agent_id
    ]
    if foreign and not scoped:
        other = foreign[0]
        if other.organization_id != organization_id:
            raise ContractResolutionError("organization_mismatch")
        raise ContractResolutionError("agent_mismatch")
    active = [row for row in scoped if row.status == "ACTIVE"]
    if not active:
        if scoped:
            raise ContractResolutionError("no_active_contract")
        raise ContractResolutionError("not_found")
    if len(active) > 1:
        raise ContractResolutionError("ambiguous_active_contract")
    contract = active[0]
    if claimed_contract_id is not None and claimed_contract_id != contract.contract_id:
        raise ContractResolutionError("untrusted_contract_id")
    return contract


def resolve_active_contract(
    db: Session,
    organization_id: str,
    agent_id: str,
    claimed_contract_id: Optional[str] = None,
) -> models.RuntimeContract:
    rows = (
        db.query(models.RuntimeContract)
        .filter(
            models.RuntimeContract.organization_id == organization_id,
            models.RuntimeContract.agent_id == agent_id,
        )
        .all()
    )
    return select_active_contract(
        rows, organization_id, agent_id, claimed_contract_id=claimed_contract_id
    )


def resolve_active_contract_for_agent(
    db: Session,
    agent: models.Agent,
    claimed_contract_id: Optional[str] = None,
) -> models.RuntimeContract:
    return resolve_active_contract(
        db,
        agent.organization_id,
        agent.id,
        claimed_contract_id=claimed_contract_id,
    )
