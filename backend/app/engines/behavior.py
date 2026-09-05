from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from .. import models

PATTERN_TYPES = ("SEQUENCE", "THRESHOLD")
SEVERITIES = ("low", "medium", "high", "critical")
NAME_MAX = 120
DESCRIPTION_MAX = 2000
MAX_SEQUENCE_STEPS = 20
MAX_THRESHOLD_COUNT = 10_000

_FORBIDDEN_KEYS = {
    "eval",
    "exec",
    "compile",
    "code",
    "script",
    "__import__",
    "bytecode",
    "lambda",
    "subprocess",
}
_FORBIDDEN_SNIPPETS = (
    "__import__",
    "eval(",
    "exec(",
    "os.system",
    "subprocess",
    "compile(",
)

SEQUENCE_STEP_KEYS = {"resource_kind", "action", "scope", "destination"}
THRESHOLD_KEYS = {"resource_kind", "action", "scope", "destination", "count", "window"}


@dataclass
class TrajectoryStep:
    resource_kind: str
    action: str
    scope: str
    destination: Optional[str] = None
    decision: Optional[str] = None


@dataclass
class BehaviorMatch:
    pattern: models.BehaviorPattern
    title: str
    message: str


class PatternValidationError(ValueError):
    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


def _matches_field(pattern: Optional[str], value: Optional[str]) -> bool:
    if pattern is None or pattern == "":
        return True
    if pattern == "*":
        return True
    if value is None:
        return False
    return fnmatch(str(value).lower(), str(pattern).lower())


def _step_matches(expected: dict, actual: TrajectoryStep) -> bool:
    return (
        _matches_field(expected.get("resource_kind"), actual.resource_kind)
        and _matches_field(expected.get("action"), actual.action)
        and _matches_field(expected.get("scope"), actual.scope)
        and _matches_field(expected.get("destination"), actual.destination)
    )


def _walk_reject_code(obj: Any) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in _FORBIDDEN_KEYS:
                raise PatternValidationError(
                    "Definition must not contain executable code"
                )
            _walk_reject_code(value)
    elif isinstance(obj, list):
        for item in obj:
            _walk_reject_code(item)
    elif isinstance(obj, str):
        lowered = obj.lower()
        if any(snippet in lowered for snippet in _FORBIDDEN_SNIPPETS):
            raise PatternValidationError(
                "Definition must not contain executable code"
            )


def validate_pattern_type(pattern_type: str) -> str:
    normalized = (pattern_type or "").strip().upper()
    if normalized not in PATTERN_TYPES:
        raise PatternValidationError("Type must be SEQUENCE or THRESHOLD")
    return normalized


def validate_severity(severity: str) -> str:
    normalized = (severity or "").strip().lower()
    if normalized not in SEVERITIES:
        raise PatternValidationError(
            "Severity must be low, medium, high or critical"
        )
    return normalized


def validate_name(name: str) -> str:
    cleaned = (name or "").strip()
    if not cleaned:
        raise PatternValidationError("Name is required")
    if len(cleaned) > NAME_MAX:
        raise PatternValidationError(f"Name must be at most {NAME_MAX} characters")
    return cleaned


def validate_description(description: Optional[str]) -> str:
    text = description or ""
    if len(text) > DESCRIPTION_MAX:
        raise PatternValidationError(
            f"Description must be at most {DESCRIPTION_MAX} characters"
        )
    return text


def validate_definition(pattern_type: str, definition: Any) -> dict:
    if not isinstance(definition, dict) or definition is None:
        raise PatternValidationError("Definition must be a JSON object")
    _walk_reject_code(definition)
    if pattern_type == "SEQUENCE":
        return _validate_sequence(definition)
    if pattern_type == "THRESHOLD":
        return _validate_threshold(definition)
    raise PatternValidationError("Type must be SEQUENCE or THRESHOLD")


def _validate_sequence(definition: dict) -> dict:
    extra = set(definition.keys()) - {"steps"}
    if extra:
        raise PatternValidationError("SEQUENCE definition only allows 'steps'")
    steps = definition.get("steps")
    if not isinstance(steps, list) or len(steps) < 2:
        raise PatternValidationError("SEQUENCE requires at least two steps")
    if len(steps) > MAX_SEQUENCE_STEPS:
        raise PatternValidationError(
            f"SEQUENCE supports at most {MAX_SEQUENCE_STEPS} steps"
        )
    cleaned_steps = []
    for step in steps:
        if not isinstance(step, dict):
            raise PatternValidationError("Each SEQUENCE step must be an object")
        extra_step = set(step.keys()) - SEQUENCE_STEP_KEYS
        if extra_step:
            raise PatternValidationError(
                "SEQUENCE steps may only include resource_kind, action, scope, destination"
            )
        if not step.get("resource_kind") and not step.get("action"):
            raise PatternValidationError(
                "Each SEQUENCE step needs resource_kind or action"
            )
        cleaned = {}
        for key in SEQUENCE_STEP_KEYS:
            if key in step and step[key] is not None:
                if not isinstance(step[key], str):
                    raise PatternValidationError(
                        f"SEQUENCE step field '{key}' must be a string"
                    )
                cleaned[key] = step[key].strip()
        cleaned_steps.append(cleaned)
    return {"steps": cleaned_steps}


def _validate_threshold(definition: dict) -> dict:
    extra = set(definition.keys()) - THRESHOLD_KEYS
    if extra:
        raise PatternValidationError("THRESHOLD definition contains unsupported fields")
    count = definition.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise PatternValidationError("THRESHOLD count must be a positive integer")
    if count > MAX_THRESHOLD_COUNT:
        raise PatternValidationError(
            f"THRESHOLD count must be at most {MAX_THRESHOLD_COUNT}"
        )
    cleaned: dict[str, Any] = {"count": count}
    if "window" in definition and definition["window"] is not None:
        window = definition["window"]
        if not isinstance(window, int) or isinstance(window, bool) or window < 1:
            raise PatternValidationError("THRESHOLD window must be a positive integer")
        if window > MAX_THRESHOLD_COUNT:
            raise PatternValidationError("THRESHOLD window is too large")
        cleaned["window"] = window
    for key in ("resource_kind", "action", "scope", "destination"):
        if key in definition and definition[key] is not None:
            if not isinstance(definition[key], str):
                raise PatternValidationError(f"THRESHOLD field '{key}' must be a string")
            cleaned[key] = definition[key].strip()
    if "resource_kind" not in cleaned and "action" not in cleaned:
        raise PatternValidationError(
            "THRESHOLD requires resource_kind or action"
        )
    return cleaned


def load_enabled_patterns(db: Session, organization_id: str) -> list[models.BehaviorPattern]:
    return (
        db.query(models.BehaviorPattern)
        .filter(
            models.BehaviorPattern.enabled.is_(True),
            or_(
                models.BehaviorPattern.organization_id.is_(None),
                models.BehaviorPattern.organization_id == organization_id,
            ),
        )
        .all()
    )


def reconstruct_trajectory(db: Session, execution_id: str) -> list[TrajectoryStep]:
    events = (
        db.query(models.Event)
        .filter(models.Event.execution_id == execution_id)
        .order_by(models.Event.seq.asc(), models.Event.created_at.asc())
        .all()
    )
    return [
        TrajectoryStep(
            resource_kind=event.resource_kind,
            action=event.action,
            scope=event.scope,
            destination=event.destination,
            decision=event.decision,
        )
        for event in events
    ]


def get_or_create_execution(
    db: Session,
    agent: models.Agent,
    execution_id: Optional[str],
) -> models.Execution:
    if execution_id:
        execution = (
            db.query(models.Execution)
            .filter(models.Execution.id == execution_id)
            .first()
        )
        if execution:
            if (
                execution.organization_id != agent.organization_id
                or execution.agent_id != agent.id
            ):
                raise PermissionError("execution_not_owned")
            return execution
        execution = models.Execution(
            id=execution_id,
            organization_id=agent.organization_id,
            agent_id=agent.id,
        )
        db.add(execution)
        db.flush()
        return execution
    execution = models.Execution(
        organization_id=agent.organization_id,
        agent_id=agent.id,
    )
    db.add(execution)
    db.flush()
    return execution


def next_seq(db: Session, execution_id: str) -> int:
    last = (
        db.query(func.max(models.Event.seq))
        .filter(models.Event.execution_id == execution_id)
        .scalar()
    )
    return int(last or 0) + 1


def _match_sequence(definition: dict, trajectory: list[TrajectoryStep]) -> bool:
    steps = definition.get("steps") or []
    index = 0
    for expected in steps:
        found = False
        while index < len(trajectory):
            actual = trajectory[index]
            index += 1
            if _step_matches(expected, actual):
                found = True
                break
        if not found:
            return False
    return True


def _match_threshold(definition: dict, trajectory: list[TrajectoryStep]) -> bool:
    window = definition.get("window")
    windowed = trajectory[-window:] if window else trajectory
    matched = sum(1 for step in windowed if _step_matches(definition, step))
    return matched >= int(definition["count"])


def evaluate(
    db: Session,
    agent: models.Agent,
    trajectory: list[TrajectoryStep],
) -> list[BehaviorMatch]:
    matches: list[BehaviorMatch] = []
    patterns = load_enabled_patterns(db, agent.organization_id)
    for pattern in patterns:
        definition = pattern.definition or {}
        hit = False
        if pattern.type == "SEQUENCE":
            hit = _match_sequence(definition, trajectory)
        elif pattern.type == "THRESHOLD":
            hit = _match_threshold(definition, trajectory)
        if not hit:
            continue
        matches.append(
            BehaviorMatch(
                pattern=pattern,
                title=f"Behavior pattern '{pattern.name}'",
                message=pattern.description
                or f"Matched {pattern.type} pattern {pattern.name}",
            )
        )
    return matches


def persist_signals(
    db: Session,
    agent: models.Agent,
    execution: models.Execution,
    event: models.Event,
    matches: list[BehaviorMatch],
) -> list[models.BehaviorSignal]:
    created: list[models.BehaviorSignal] = []
    for match in matches:
        existing = (
            db.query(models.BehaviorSignal)
            .filter(
                models.BehaviorSignal.pattern_id == match.pattern.id,
                models.BehaviorSignal.execution_id == execution.id,
            )
            .first()
        )
        if existing:
            created.append(existing)
            continue
        signal = models.BehaviorSignal(
            organization_id=agent.organization_id,
            agent_id=agent.id,
            execution_id=execution.id,
            event_id=event.id,
            pattern_id=match.pattern.id,
            severity=match.pattern.severity,
            title=match.title,
            message=match.message,
        )
        db.add(signal)
        created.append(signal)
    db.flush()
    return created
