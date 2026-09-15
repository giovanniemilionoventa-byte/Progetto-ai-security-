"""Phase 17 — turning a human approval into one bounded execution authority.

Before Phase 17 `POST /api/approvals/{id}/decide` set `status='approved'` and
nothing in the codebase ever read that value. An operator could click Allow in
the dashboard and the action would never run: the gateway executes only on
`decision == "ALLOW"`, and replaying the original request returned the stored
APPROVAL event. The human-in-the-loop promise was not implemented.

Closing that loop safely is the hard part. An approval is a grant of authority,
so it has to be as tightly bound as an EAT, and for the same reason: whatever is
not bound can be mutated after the human said yes.

A grant authorizes exactly one request:

    organization, agent, execution, request id,
    resource kind, action, scope, destination,
    payload digest, contract id and version

and it is valid only while it is approved, unexpired and unconsumed. Consumption
is recorded on the row, so the same approval cannot drive a second execution.

The evaluator never mutates anything. `consume` is a separate, explicit step the
caller takes once it has committed the execution event, so a failure between
the two leaves the grant unusable rather than silently re-runnable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from sqlalchemy.orm import Session

from .. import config, models
from ..runtime_contract import coerce_utc
from ..security import utcnow


@dataclass(frozen=True)
class GrantVerdict:
    granted: bool
    reason: str
    approval: Optional[models.Approval] = None


def approval_for_event(db: Session, event_id: str) -> Optional[models.Approval]:
    return (
        db.query(models.Approval)
        .filter(models.Approval.event_id == event_id)
        .order_by(models.Approval.created_at.asc())
        .first()
    )


def default_expiry():
    return utcnow() + timedelta(seconds=config.APPROVAL_TTL_SECONDS)


def _mismatch(field: str) -> GrantVerdict:
    return GrantVerdict(
        granted=False,
        reason=f"Approval does not authorize this request ({field} differs).",
    )


def evaluate_grant(
    db: Session,
    *,
    agent: models.Agent,
    event: models.Event,
    resource_kind: str,
    action: str,
    scope: str,
    destination: Optional[str],
    payload_hash: str,
    contract_id: Optional[str],
    contract_version: Optional[int],
    now=None,
) -> GrantVerdict:
    """Decide whether an approved approval authorizes this exact request."""
    approval = approval_for_event(db, event.id)
    if approval is None:
        return GrantVerdict(False, "No approval exists for this request.")

    status = (approval.status or "").lower()
    if status == "pending":
        return GrantVerdict(False, "Approval is still pending human review.", approval)
    if status != "approved":
        return GrantVerdict(
            False, f"Approval was not granted (status={status}).", approval
        )

    if approval.consumed_at is not None:
        return GrantVerdict(
            False, "Approval has already authorized an execution.", approval
        )

    clock = coerce_utc(now) if now is not None else utcnow()
    expires_at = coerce_utc(approval.expires_at)
    if expires_at is not None and clock >= expires_at:
        return GrantVerdict(False, "Approval has expired.", approval)

    # Identity
    if approval.organization_id != agent.organization_id:
        return _mismatch("organization")
    if approval.agent_id != agent.id:
        return _mismatch("agent")

    # The execution and request this grant was issued against
    if approval.execution_id is not None and approval.execution_id != event.execution_id:
        return _mismatch("execution")
    if approval.request_id is not None and approval.request_id != event.request_id:
        return _mismatch("request")

    # The action itself
    if approval.resource_kind != resource_kind:
        return _mismatch("resource_kind")
    if approval.action != action:
        return _mismatch("action")
    if approval.scope != scope:
        return _mismatch("scope")
    if (approval.destination or None) != (destination or None):
        return _mismatch("destination")

    # Parameters. A grant for one payload is not a grant for another.
    if approval.param_hash is not None and approval.param_hash != payload_hash:
        return _mismatch("parameters")

    # The contract in force when the human approved must still be the one in
    # force now, at the same version.
    if (approval.contract_id or None) != (contract_id or None):
        return _mismatch("contract")
    if approval.contract_version != contract_version:
        return _mismatch("contract_version")

    return GrantVerdict(True, "Authorized by human approval.", approval)


def consume(
    db: Session, approval: models.Approval, execution_event_id: str, now=None
) -> None:
    """Burn the grant. Called only after the execution event is persisted."""
    approval.consumed_at = coerce_utc(now) if now is not None else utcnow()
    approval.consumed_event_id = execution_event_id
    db.flush()
