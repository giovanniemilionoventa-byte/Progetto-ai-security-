from dataclasses import dataclass
from typing import Any, Optional

IRREVERSIBLE = {
    ("payments", "TRANSFER"),
    ("crm", "DELETE"),
    ("email", "SEND"),
    ("files", "EXPORT"),
    ("files", "DELETE"),
}

EXTERNAL_SCOPES = {"external", "public", "all", "tutti", "qualsiasi", "*"}
SENSITIVE_SCOPES = {"/finance", "finance", "payroll", "secrets", "credentials"}


@dataclass
class RiskResult:
    score: float
    level: str
    factors: list[str]


def evaluate(
    resource_kind: str,
    action: str,
    scope: str,
    destination: Optional[str] = None,
    policy_decision: str = "ALLOW",
    behavior_signals: Optional[list[Any]] = None,
) -> RiskResult:
    score = 10.0
    factors: list[str] = []
    kind = resource_kind.lower()
    act = action.upper()
    scope_l = (scope or "").lower()
    dest_l = (destination or "").lower()

    if (kind, act) in IRREVERSIBLE:
        score += 40
        factors.append("irreversible_action")

    if act in {"DELETE", "TRANSFER", "EXPORT"}:
        score += 20
        factors.append("destructive_or_exfil")

    if scope_l in EXTERNAL_SCOPES or dest_l in {"external", "public"}:
        score += 25
        factors.append("external_destination")

    if any(s in scope_l for s in SENSITIVE_SCOPES):
        score += 20
        factors.append("sensitive_scope")

    if policy_decision == "BLOCK":
        score += 15
        factors.append("policy_block")
    elif policy_decision == "APPROVAL":
        score += 10
        factors.append("requires_human")

    if behavior_signals:
        severities = {
            getattr(signal, "severity", None)
            or (signal.get("severity") if isinstance(signal, dict) else None)
            for signal in behavior_signals
        }
        if "critical" in severities:
            score += 25
            factors.append("behavior_critical")
        elif "high" in severities:
            score += 15
            factors.append("behavior_high")
        else:
            score += 8
            factors.append("behavior_signal")

    score = min(100.0, score)
    if score >= 70:
        level = "critical"
    elif score >= 45:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    if not factors:
        factors.append("baseline")
    return RiskResult(score=score, level=level, factors=factors)
