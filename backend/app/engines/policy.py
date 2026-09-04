from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Optional

from sqlalchemy.orm import Session

from .. import models
from . import permission as permission_engine

DECISIONS = ("BLOCK", "APPROVAL", "ALLOW")
PRIORITY = {"BLOCK": 0, "APPROVAL": 1, "ALLOW": 2}


@dataclass
class PolicyResult:
    decision: str
    reason: str
    matched_policy: Optional[str] = None


def _matches(pattern: Optional[str], value: Optional[str]) -> bool:
    if not pattern or pattern == "*":
        return True
    if value is None:
        return False
    return fnmatch(value.lower(), pattern.lower())


def evaluate(
    db: Session,
    agent: models.Agent,
    resource_kind: str,
    action: str,
    scope: str,
    destination: Optional[str] = None,
    *,
    check_permission: bool = True,
) -> PolicyResult:
    kind = resource_kind.lower()
    act = action.upper()

    if check_permission and not permission_engine.allows(agent, kind, act, scope):
        return PolicyResult(
            decision="BLOCK",
            reason="Agent lacks permission for this resource/action/scope (least privilege).",
        )

    policies = (
        db.query(models.Policy)
        .filter(
            models.Policy.organization_id == agent.organization_id,
            models.Policy.enabled.is_(True),
        )
        .order_by(models.Policy.priority.asc())
        .all()
    )

    matched: list[models.Policy] = []
    for policy in policies:
        if not _matches(policy.resource_kind, kind):
            continue
        if not _matches(policy.action, act):
            continue
        if not _matches(policy.scope_pattern, scope):
            continue
        if policy.destination_pattern and not _matches(
            policy.destination_pattern, destination
        ):
            continue
        matched.append(policy)

    if not matched:
        return PolicyResult(
            decision="ALLOW",
            reason="Permission granted and no matching restrictive policy.",
        )

    best = min(matched, key=lambda p: (PRIORITY.get(p.decision.upper(), 9), p.priority))
    return PolicyResult(
        decision=best.decision.upper(),
        reason=f"Matched policy '{best.name}': {best.description or best.decision}",
        matched_policy=best.id,
    )
