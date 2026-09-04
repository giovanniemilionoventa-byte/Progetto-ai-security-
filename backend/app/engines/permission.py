from fnmatch import fnmatch

from .. import models


def _matches(pattern: str | None, value: str | None) -> bool:
    if not pattern or pattern == "*":
        return True
    if value is None:
        return False
    return fnmatch(value.lower(), pattern.lower())


def allows(agent: models.Agent, kind: str, action: str, scope: str) -> bool:
    perms = agent.permissions
    if not perms:
        return False
    kind = kind.lower()
    action = action.upper()
    denies = [
        p
        for p in perms
        if p.effect.lower() == "deny"
        and _matches(p.resource_kind, kind)
        and _matches(p.action, action)
        and _matches(p.scope, scope)
    ]
    if denies:
        return False
    allows_ = [
        p
        for p in perms
        if p.effect.lower() == "allow"
        and _matches(p.resource_kind, kind)
        and _matches(p.action, action)
        and _matches(p.scope, scope)
    ]
    return bool(allows_)
