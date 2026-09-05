from __future__ import annotations

from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import models
from .runtime_contract import (
    CONTRACT_STATUSES,
    contract_lifecycle_verdict,
    validate_runtime_contract,
)


class ContractStoreError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ContractResolutionError(LookupError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


_LEGAL_CONTRACT_TRANSITIONS = {
    "DRAFT": {"ACTIVE", "SUPERSEDED", "REVOKED", "EXPIRED"},
    "ACTIVE": {"SUPERSEDED", "REVOKED", "EXPIRED"},
    "SUPERSEDED": {"REVOKED", "EXPIRED"},
    "REVOKED": set(),
    "EXPIRED": set(),
}


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
    now=None,
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
    verdict = contract_lifecycle_verdict(
        contract.status, contract.valid_from, contract.expires_at, now=now
    )
    if not verdict["current"]:
        raise ContractResolutionError(verdict["reason"] or "contract_not_active")
    if claimed_contract_id is not None and claimed_contract_id != contract.contract_id:
        raise ContractResolutionError("untrusted_contract_id")
    return contract


def resolve_active_contract(
    db: Session,
    organization_id: str,
    agent_id: str,
    claimed_contract_id: Optional[str] = None,
    now=None,
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
        rows,
        organization_id,
        agent_id,
        claimed_contract_id=claimed_contract_id,
        now=now,
    )


def resolve_active_contract_for_agent(
    db: Session,
    agent: models.Agent,
    claimed_contract_id: Optional[str] = None,
    now=None,
) -> models.RuntimeContract:
    return resolve_active_contract(
        db,
        agent.organization_id,
        agent.id,
        claimed_contract_id=claimed_contract_id,
        now=now,
    )


def assert_contract_current_for_dispatch(
    db: Session,
    organization_id: str,
    agent_id: str,
    contract_id: str,
    contract_version: int,
    now=None,
) -> models.RuntimeContract:
    """Re-verify that the authorized contract is still the current ACTIVE one.

    Called by the gateway immediately before an EAT is issued and the broker
    is dispatched, so a REVOKED / EXPIRED / SUPERSEDED contract can never
    produce a usable EAT. No fallback to older contracts is possible.
    """
    resolved = resolve_active_contract(
        db,
        organization_id,
        agent_id,
        claimed_contract_id=contract_id,
        now=now,
    )
    if (
        resolved.contract_id != contract_id
        or resolved.version != contract_version
    ):
        raise ContractResolutionError("untrusted_contract_id")
    return resolved


def transition_contract_status(
    db: Session,
    organization_id: str,
    agent_id: str,
    contract_id: str,
    version: int,
    new_status: str,
) -> models.RuntimeContract:
    """Apply a deterministic lifecycle transition on an existing contract.

    Terminal states (REVOKED, EXPIRED) can never return to ACTIVE, and at most
    one ACTIVE contract may exist per organization_id + agent_id.
    """
    if not isinstance(new_status, str):
        raise ContractStoreError("invalid_status")
    normalized = new_status.strip().upper()
    if normalized not in CONTRACT_STATUSES:
        raise ContractStoreError("invalid_status")
    row = get_contract(db, organization_id, agent_id, contract_id, version)
    if row.status == normalized:
        return row
    allowed = _LEGAL_CONTRACT_TRANSITIONS.get(row.status, set())
    if normalized not in allowed:
        raise ContractStoreError("invalid_transition")
    if normalized == "ACTIVE":
        conflict = [
            active
            for active in _active_rows(db, organization_id, agent_id)
            if active.contract_id != contract_id or active.version != version
        ]
        if conflict:
            raise ContractStoreError("active_contract_exists")
    row.status = normalized
    try:
        db.flush()
    except IntegrityError as exc:
        raise ContractStoreError("active_contract_exists") from exc
    return row
