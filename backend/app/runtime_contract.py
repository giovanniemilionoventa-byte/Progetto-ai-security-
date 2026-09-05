from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

CONTRACT_STATUSES = ("DRAFT", "ACTIVE", "SUPERSEDED", "REVOKED", "EXPIRED")
CONTRACT_IDENTITY_FIELDS = ("organization_id", "agent_id", "contract_id", "version")
CONTRACT_TOP_LEVEL_FIELDS = {
    "organization_id",
    "agent_id",
    "contract_id",
    "version",
    "status",
    "purpose",
    "capabilities",
    "resources",
    "constraints",
    "data_constraints",
    "workflow",
    "approval_rules",
    "valid_from",
    "expires_at",
    "integrity",
}

WORKFLOW_KEYS = {"initial_steps", "steps", "transitions", "terminal_steps"}
WORKFLOW_STEP_REQUIRED = {"id"}
WORKFLOW_TRANSITION_REQUIRED = {"from", "to"}


class ContractValidationError(ValueError):
    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


def _require_object(value: Any, label: str) -> dict:
    if not isinstance(value, dict) or isinstance(value, bool):
        raise ContractValidationError(f"{label} must be an object")
    return value


def _require_non_empty_str(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ContractValidationError(f"{label} must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise ContractValidationError(f"{label} is required")
    return cleaned


def _optional_str(value: Any, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ContractValidationError(f"{label} must be a string")
    return value.strip()


def _require_list(value: Any, label: str) -> list:
    if not isinstance(value, list):
        raise ContractValidationError(f"{label} must be a list")
    return value


def _require_str_list(value: Any, label: str) -> list[str]:
    items = _require_list(value, label)
    cleaned: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise ContractValidationError(f"{label} must contain non-empty strings")
        cleaned.append(item.strip())
    return cleaned


def _require_positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ContractValidationError(f"{label} must be a positive integer")
    return value


def _parse_datetime(value: Any, label: str) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if not isinstance(value, str):
        raise ContractValidationError(f"{label} must be a timestamp")
    text = value.strip()
    if not text:
        raise ContractValidationError(f"{label} must be a valid timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ContractValidationError(f"{label} must be a valid timestamp") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validate_status(value: Any) -> str:
    if not isinstance(value, str):
        raise ContractValidationError("status is invalid")
    normalized = value.strip().upper()
    if normalized not in CONTRACT_STATUSES:
        raise ContractValidationError("status is invalid")
    return normalized


def _validate_version(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ContractValidationError("version is invalid")
    return value


def _validate_capability(item: Any) -> dict:
    obj = _require_object(item, "capability")
    name = _require_non_empty_str(obj.get("name"), "capability name")
    cleaned = {key: value for key, value in obj.items() if key != "name"}
    if "actions" in obj:
        if obj["actions"] is None:
            raise ContractValidationError("capability actions must be a list")
        actions = _require_str_list(obj["actions"], "capability actions")
        cleaned["actions"] = [action.upper() for action in actions]
    if "description" in obj:
        cleaned["description"] = _optional_str(obj.get("description"), "capability description")
    cleaned["name"] = name
    return cleaned


def _validate_resource(item: Any) -> dict:
    obj = _require_object(item, "resource")
    kind = _require_non_empty_str(obj.get("kind"), "resource kind")
    cleaned = {key: value for key, value in obj.items()}
    cleaned["kind"] = kind.lower()
    if "name" in obj:
        cleaned["name"] = _optional_str(obj.get("name"), "resource name")
    if "identifier" in obj:
        cleaned["identifier"] = _optional_str(obj.get("identifier"), "resource identifier")
    if "scope" in obj:
        scope = obj.get("scope")
        if scope is None:
            cleaned["scope"] = "*"
        else:
            cleaned["scope"] = _require_non_empty_str(scope, "resource scope")
    if "sensitivity" in obj:
        cleaned["sensitivity"] = _optional_str(obj.get("sensitivity"), "resource sensitivity").lower()
    return cleaned


def _validate_destination_restrictions(value: Any) -> dict:
    obj = _require_object(value, "destination_restrictions")
    cleaned = dict(obj)
    if "allow" in obj and obj["allow"] is not None:
        cleaned["allow"] = _require_str_list(obj["allow"], "destination_restrictions.allow")
    if "deny" in obj and obj["deny"] is not None:
        cleaned["deny"] = _require_str_list(obj["deny"], "destination_restrictions.deny")
    return cleaned


def _validate_operation_limits(value: Any) -> dict:
    obj = _require_object(value, "operation_limits")
    cleaned = dict(obj)
    for key in ("max_calls", "window_seconds", "max_operations"):
        if key in obj and obj[key] is not None:
            cleaned[key] = _require_positive_int(obj[key], f"operation_limits.{key}")
    return cleaned


def _validate_payload_size(value: Any) -> dict:
    if isinstance(value, int) and not isinstance(value, bool):
        return {"max_bytes": _require_positive_int(value, "payload_size")}
    obj = _require_object(value, "payload_size")
    cleaned = dict(obj)
    if "max_bytes" in obj and obj["max_bytes"] is not None:
        cleaned["max_bytes"] = _require_positive_int(obj["max_bytes"], "payload_size.max_bytes")
    return cleaned


def _validate_constraints(value: Any) -> dict:
    obj = _require_object(value, "constraints")
    cleaned = dict(obj)
    if "destination_restrictions" in obj and obj["destination_restrictions"] is not None:
        cleaned["destination_restrictions"] = _validate_destination_restrictions(
            obj["destination_restrictions"]
        )
    if "operation_limits" in obj and obj["operation_limits"] is not None:
        cleaned["operation_limits"] = _validate_operation_limits(obj["operation_limits"])
    if "payload_size" in obj and obj["payload_size"] is not None:
        cleaned["payload_size"] = _validate_payload_size(obj["payload_size"])
    return cleaned


def _validate_data_constraints(value: Any) -> dict:
    obj = _require_object(value, "data_constraints")
    cleaned = dict(obj)
    if "allowed_fields" in obj and obj["allowed_fields"] is not None:
        cleaned["allowed_fields"] = _require_str_list(
            obj["allowed_fields"], "data_constraints.allowed_fields"
        )
    if "denied_fields" in obj and obj["denied_fields"] is not None:
        cleaned["denied_fields"] = _require_str_list(
            obj["denied_fields"], "data_constraints.denied_fields"
        )
    return cleaned


def _validate_workflow_steps(value: Any) -> tuple[list[dict], set[str]]:
    steps = _require_list(value, "workflow.steps")
    if not steps:
        raise ContractValidationError("workflow.steps must not be empty")
    cleaned_steps: list[dict] = []
    ids: list[str] = []
    for step in steps:
        obj = _require_object(step, "workflow step")
        missing = WORKFLOW_STEP_REQUIRED - set(obj.keys())
        if missing:
            raise ContractValidationError("workflow step is missing id")
        step_id = _require_non_empty_str(obj.get("id"), "workflow step id")
        ids.append(step_id)
        cleaned = dict(obj)
        cleaned["id"] = step_id
        if "name" in obj:
            cleaned["name"] = _optional_str(obj.get("name"), "workflow step name")
        cleaned_steps.append(cleaned)
    if len(set(ids)) != len(ids):
        raise ContractValidationError("workflow step ids must be unique")
    return cleaned_steps, set(ids)


def _validate_step_refs(values: Any, label: str, known: set[str]) -> list[str]:
    refs = _require_str_list(values, label)
    if not refs:
        raise ContractValidationError(f"{label} must not be empty")
    unknown = [ref for ref in refs if ref not in known]
    if unknown:
        raise ContractValidationError(f"{label} references unknown steps")
    return refs


def _validate_transitions(value: Any, known: set[str]) -> list[dict]:
    transitions = _require_list(value, "workflow.transitions")
    cleaned: list[dict] = []
    for item in transitions:
        obj = _require_object(item, "workflow transition")
        missing = WORKFLOW_TRANSITION_REQUIRED - set(obj.keys())
        if missing:
            raise ContractValidationError("workflow transition requires from and to")
        source = _require_non_empty_str(obj.get("from"), "workflow transition from")
        target = _require_non_empty_str(obj.get("to"), "workflow transition to")
        if source not in known or target not in known:
            raise ContractValidationError("workflow transition references unknown steps")
        entry = dict(obj)
        entry["from"] = source
        entry["to"] = target
        cleaned.append(entry)
    return cleaned


def _validate_workflow(value: Any) -> Optional[dict]:
    if value is None:
        return None
    obj = _require_object(value, "workflow")
    extra = set(obj.keys()) - WORKFLOW_KEYS
    if extra:
        raise ContractValidationError("workflow contains unsupported fields")
    missing = WORKFLOW_KEYS - set(obj.keys())
    if missing:
        raise ContractValidationError("workflow is malformed")
    steps, known = _validate_workflow_steps(obj.get("steps"))
    return {
        "initial_steps": _validate_step_refs(
            obj.get("initial_steps"), "workflow.initial_steps", known
        ),
        "steps": steps,
        "transitions": _validate_transitions(obj.get("transitions"), known),
        "terminal_steps": _validate_step_refs(
            obj.get("terminal_steps"), "workflow.terminal_steps", known
        ),
    }


def _validate_approval_rule(item: Any) -> dict:
    obj = _require_object(item, "approval rule")
    if not obj:
        raise ContractValidationError("approval rule must not be empty")
    cleaned = dict(obj)
    if "action" in obj and obj["action"] is not None:
        cleaned["action"] = _require_non_empty_str(obj.get("action"), "approval rule action").upper()
    if "resource_kind" in obj and obj["resource_kind"] is not None:
        cleaned["resource_kind"] = _require_non_empty_str(
            obj.get("resource_kind"), "approval rule resource_kind"
        ).lower()
    if "require" in obj and obj["require"] is not None:
        cleaned["require"] = _require_non_empty_str(obj.get("require"), "approval rule require")
    if "decision" in obj and obj["decision"] is not None:
        cleaned["decision"] = _require_non_empty_str(
            obj.get("decision"), "approval rule decision"
        ).upper()
    return cleaned


def _validate_approval_rules(value: Any) -> list[dict]:
    rules = _require_list(value, "approval_rules")
    return [_validate_approval_rule(rule) for rule in rules]


def _validate_integrity(value: Any) -> dict:
    obj = _require_object(value, "integrity")
    cleaned = dict(obj)
    for key in ("algorithm", "digest", "signature", "key_id"):
        if key in obj and obj[key] is not None:
            cleaned[key] = _require_non_empty_str(obj.get(key), f"integrity.{key}")
    if "signed_at" in obj:
        signed_at = _parse_datetime(obj.get("signed_at"), "integrity.signed_at")
        if signed_at is not None:
            cleaned["signed_at"] = signed_at.isoformat()
        else:
            cleaned.pop("signed_at", None)
    algorithm = cleaned.get("algorithm")
    digest = cleaned.get("digest")
    if (algorithm and not digest) or (digest and not algorithm):
        raise ContractValidationError("integrity requires algorithm and digest together")
    return cleaned


def validate_runtime_contract(document: Any) -> dict:
    obj = _require_object(document, "contract")
    unknown = set(obj.keys()) - CONTRACT_TOP_LEVEL_FIELDS
    if unknown:
        raise ContractValidationError("contract contains unsupported fields")

    missing = [field for field in CONTRACT_IDENTITY_FIELDS if field not in obj]
    if missing:
        raise ContractValidationError("required identifiers are missing")

    organization_id = _require_non_empty_str(obj.get("organization_id"), "organization_id")
    agent_id = _require_non_empty_str(obj.get("agent_id"), "agent_id")
    contract_id = _require_non_empty_str(obj.get("contract_id"), "contract_id")
    version = _validate_version(obj.get("version"))

    if "status" not in obj or obj.get("status") is None:
        status = "DRAFT"
    else:
        status = _validate_status(obj.get("status"))

    purpose = ""
    if "purpose" in obj:
        purpose = _optional_str(obj.get("purpose"), "purpose")

    if "capabilities" not in obj or obj.get("capabilities") is None:
        if "capabilities" in obj and obj.get("capabilities") is None:
            raise ContractValidationError("capabilities must be a list")
        capabilities: list[dict] = []
    else:
        capabilities = [
            _validate_capability(item)
            for item in _require_list(obj.get("capabilities"), "capabilities")
        ]

    if "resources" not in obj or obj.get("resources") is None:
        if "resources" in obj and obj.get("resources") is None:
            raise ContractValidationError("resources must be a list")
        resources: list[dict] = []
    else:
        resources = [
            _validate_resource(item)
            for item in _require_list(obj.get("resources"), "resources")
        ]

    if "constraints" not in obj or obj.get("constraints") is None:
        if "constraints" in obj and obj.get("constraints") is None:
            raise ContractValidationError("constraints must be an object")
        constraints: dict = {}
    else:
        constraints = _validate_constraints(obj.get("constraints"))

    if "data_constraints" not in obj or obj.get("data_constraints") is None:
        if "data_constraints" in obj and obj.get("data_constraints") is None:
            raise ContractValidationError("data_constraints must be an object")
        data_constraints: dict = {}
    else:
        data_constraints = _validate_data_constraints(obj.get("data_constraints"))

    workflow = None
    if "workflow" in obj:
        workflow = _validate_workflow(obj.get("workflow"))

    if "approval_rules" not in obj or obj.get("approval_rules") is None:
        if "approval_rules" in obj and obj.get("approval_rules") is None:
            raise ContractValidationError("approval_rules must be a list")
        approval_rules: list[dict] = []
    else:
        approval_rules = _validate_approval_rules(obj.get("approval_rules"))

    valid_from = _parse_datetime(obj.get("valid_from"), "valid_from") if "valid_from" in obj else None
    expires_at = _parse_datetime(obj.get("expires_at"), "expires_at") if "expires_at" in obj else None
    if valid_from is not None and expires_at is not None and valid_from >= expires_at:
        raise ContractValidationError("valid_from must be earlier than expires_at")

    integrity = None
    if "integrity" in obj:
        if obj.get("integrity") is None:
            raise ContractValidationError("integrity must be an object")
        integrity = _validate_integrity(obj.get("integrity"))

    return {
        "organization_id": organization_id,
        "agent_id": agent_id,
        "contract_id": contract_id,
        "version": version,
        "status": status,
        "purpose": purpose,
        "capabilities": capabilities,
        "resources": resources,
        "constraints": constraints,
        "data_constraints": data_constraints,
        "workflow": workflow,
        "approval_rules": approval_rules,
        "valid_from": valid_from,
        "expires_at": expires_at,
        "integrity": integrity,
    }
