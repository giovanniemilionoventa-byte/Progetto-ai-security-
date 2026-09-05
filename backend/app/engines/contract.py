from __future__ import annotations

import json
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, Optional

from .. import models
from ..runtime_contract import ContractWorkflow, ContractWorkflowError, load_contract_workflow
from .behavior import TrajectoryStep

KNOWN_CONSTRAINT_KEYS = {
    "destination_restrictions",
    "operation_limits",
    "payload_size",
}
KNOWN_DATA_CONSTRAINT_KEYS = {"allowed_fields", "denied_fields"}
KNOWN_OPERATION_LIMIT_KEYS = {"max_calls", "window_seconds", "max_operations"}


@dataclass
class ContractDecision:
    allowed: bool
    reason: str
    contract: Optional[models.RuntimeContract] = None


def _matches(pattern: Optional[str], value: Optional[str]) -> bool:
    if not pattern or pattern == "*":
        return True
    if value is None:
        return False
    return fnmatch(str(value).lower(), str(pattern).lower())


def _payload_bytes(payload: Optional[dict]) -> int:
    body = payload if isinstance(payload, dict) else {}
    return len(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())


def _capability_matches(capability: dict, kind: str, action: str) -> bool:
    name = str(capability.get("name") or "").strip().lower()
    actions = capability.get("actions")
    cap_kind = capability.get("resource_kind") or capability.get("kind")
    allowed_actions = None
    if actions is not None:
        allowed_actions = {str(item).upper() for item in actions}
        if action not in allowed_actions:
            return False
    if cap_kind is not None:
        if str(cap_kind).strip().lower() != kind:
            return False
        if allowed_actions is not None:
            return True
        return name == f"{kind}.{action.lower()}"
    if name == f"{kind}.{action.lower()}":
        return True
    if name == kind and allowed_actions is not None:
        return True
    return False


def _resource_matches(
    resource: dict, kind: str, scope: str, destination: Optional[str]
) -> bool:
    if str(resource.get("kind") or "").strip().lower() != kind:
        return False
    if "scope" in resource and resource.get("scope") is not None:
        if not _matches(str(resource.get("scope")), scope):
            return False
    if resource.get("identifier"):
        if destination is None or not _matches(str(resource.get("identifier")), destination):
            if scope and _matches(str(resource.get("identifier")), scope):
                return True
            return False
    if "destination" in resource and resource.get("destination") is not None:
        if not _matches(str(resource.get("destination")), destination):
            return False
    return True


def _evaluate_capabilities(contract: models.RuntimeContract, kind: str, action: str) -> Optional[str]:
    capabilities = contract.capabilities or []
    if not capabilities:
        return "Request capability is not authorized by the runtime contract."
    if any(_capability_matches(item, kind, action) for item in capabilities if isinstance(item, dict)):
        return None
    return "Request capability is not authorized by the runtime contract."


def _evaluate_resources(
    contract: models.RuntimeContract,
    kind: str,
    scope: str,
    destination: Optional[str],
) -> Optional[str]:
    resources = contract.resources or []
    if not resources:
        return "Request resource is outside the runtime contract scope."
    if any(
        _resource_matches(item, kind, scope, destination)
        for item in resources
        if isinstance(item, dict)
    ):
        return None
    return "Request resource is outside the runtime contract scope."


def _evaluate_destination_restrictions(restrictions: dict, destination: Optional[str]) -> Optional[str]:
    deny = restrictions.get("deny") or []
    allow = restrictions.get("allow")
    if destination is None:
        return None
    if deny and any(_matches(pattern, destination) for pattern in deny):
        return "Destination is denied by the runtime contract."
    if allow is not None and not any(_matches(pattern, destination) for pattern in allow):
        return "Destination is not allowed by the runtime contract."
    return None


def _evaluate_constraints(
    contract: models.RuntimeContract,
    destination: Optional[str],
    payload: Optional[dict],
    trajectory: list[TrajectoryStep],
) -> Optional[str]:
    constraints = contract.constraints or {}
    if not isinstance(constraints, dict):
        return "Runtime contract constraints cannot be verified."
    extra = set(constraints.keys()) - KNOWN_CONSTRAINT_KEYS
    if extra:
        return "Runtime contract constraint cannot be verified."
    if "destination_restrictions" in constraints and constraints["destination_restrictions"] is not None:
        restrictions = constraints["destination_restrictions"]
        if not isinstance(restrictions, dict):
            return "Destination restriction cannot be verified."
        blocked = _evaluate_destination_restrictions(restrictions, destination)
        if blocked:
            return blocked
    if "payload_size" in constraints and constraints["payload_size"] is not None:
        spec = constraints["payload_size"]
        max_bytes = spec.get("max_bytes") if isinstance(spec, dict) else spec
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            return "Payload size constraint cannot be verified."
        if payload is not None and not isinstance(payload, dict):
            return "Payload size constraint cannot be verified."
        if _payload_bytes(payload if isinstance(payload, dict) else {}) > max_bytes:
            return "Payload exceeds the runtime contract size limit."
    if "operation_limits" in constraints and constraints["operation_limits"] is not None:
        limits = constraints["operation_limits"]
        if not isinstance(limits, dict):
            return "Operation limit cannot be verified."
        extra_limits = set(limits.keys()) - KNOWN_OPERATION_LIMIT_KEYS
        if extra_limits:
            return "Runtime contract constraint cannot be verified."
        max_calls = limits.get("max_calls") or limits.get("max_operations")
        if max_calls is not None:
            if not isinstance(max_calls, int) or isinstance(max_calls, bool) or max_calls < 1:
                return "Operation limit cannot be verified."
            if len(trajectory) > max_calls:
                return "Operation limit exceeded for the runtime contract."
        if "window_seconds" in limits and limits["window_seconds"] is not None:
            return "Runtime contract constraint cannot be verified."
    return None


def _evaluate_data_constraints(
    contract: models.RuntimeContract, payload: Optional[dict]
) -> Optional[str]:
    constraints = contract.data_constraints or {}
    if not isinstance(constraints, dict):
        return "Runtime contract data constraints cannot be verified."
    extra = set(constraints.keys()) - KNOWN_DATA_CONSTRAINT_KEYS
    if extra:
        return "Runtime contract data constraint cannot be verified."
    if not constraints:
        return None
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return "Runtime contract data constraint cannot be verified."
    keys = {str(key) for key in payload.keys()}
    denied = constraints.get("denied_fields")
    if denied is not None:
        denied_set = {str(item) for item in denied}
        if keys & denied_set:
            return "Payload contains fields denied by the runtime contract."
    allowed = constraints.get("allowed_fields")
    if allowed is not None:
        allowed_set = {str(item) for item in allowed}
        if keys - allowed_set:
            return "Payload contains fields outside the runtime contract allow-list."
    return None


def _workflow_step_matches(step: dict, actual: TrajectoryStep) -> bool:
    has_selector = bool(step.get("resource_kind") or step.get("action"))
    if not has_selector:
        return False
    if step.get("resource_kind") and str(step["resource_kind"]).lower() != actual.resource_kind:
        return False
    if step.get("action") and str(step["action"]).upper() != actual.action:
        return False
    if "scope" in step and step.get("scope") is not None:
        if not _matches(str(step.get("scope")), actual.scope):
            return False
    if "destination" in step and step.get("destination") is not None:
        if not _matches(str(step.get("destination")), actual.destination):
            return False
    return True


def _matching_step_ids(workflow: ContractWorkflow, actual: TrajectoryStep) -> list[str]:
    return [step["id"] for step in workflow.steps if _workflow_step_matches(step, actual)]


def _evaluate_workflow(
    contract: models.RuntimeContract,
    previous: list[TrajectoryStep],
    current: TrajectoryStep,
) -> Optional[str]:
    if not contract.workflow:
        return None
    try:
        workflow = load_contract_workflow(contract)
    except (ContractWorkflowError, Exception):
        return "Runtime contract workflow cannot be verified."
    if workflow is None:
        return None
    for step in workflow.steps:
        if not step.get("resource_kind") and not step.get("action"):
            return "Runtime contract workflow cannot be verified."

    possible: set[str] = set()
    started = False
    for actual in previous:
        matches = _matching_step_ids(workflow, actual)
        if not matches:
            return "Request skips a required runtime contract workflow step."
        if not started:
            initial = [item for item in matches if workflow.is_initial(item)]
            if not initial:
                return "Request skips a required runtime contract workflow step."
            possible = set(initial)
            started = True
            continue
        nxt: set[str] = set()
        for source in possible:
            for target in matches:
                if workflow.allows_transition(source, target):
                    nxt.add(target)
        if not nxt:
            return "Request is not an allowed runtime contract workflow transition."
        possible = nxt

    matches = _matching_step_ids(workflow, current)
    if not matches:
        return "Request is outside the authorized runtime contract workflow."
    if not started:
        if not any(workflow.is_initial(item) for item in matches):
            return "Request skips a required runtime contract workflow step."
        return None
    if not any(
        workflow.allows_transition(source, target)
        for source in possible
        for target in matches
    ):
        return "Request is not an allowed runtime contract workflow transition."
    return None


def evaluate_contract(
    contract: models.RuntimeContract,
    *,
    kind: str,
    action: str,
    scope: str,
    destination: Optional[str],
    payload: Optional[dict],
    previous: list[TrajectoryStep],
    current: TrajectoryStep,
    claimed_contract_id: Optional[str] = None,
) -> ContractDecision:
    if claimed_contract_id is not None and claimed_contract_id != contract.contract_id:
        return ContractDecision(
            allowed=False,
            reason="Declared contract_id does not match the resolved runtime contract.",
            contract=contract,
        )
    kind = kind.lower()
    action = action.upper()
    trajectory = list(previous) + [current]
    checks = (
        _evaluate_capabilities(contract, kind, action),
        _evaluate_resources(contract, kind, scope, destination),
        _evaluate_constraints(contract, destination, payload, trajectory),
        _evaluate_data_constraints(contract, payload),
        _evaluate_workflow(contract, previous, current),
    )
    for reason in checks:
        if reason:
            return ContractDecision(allowed=False, reason=reason, contract=contract)
    return ContractDecision(
        allowed=True,
        reason="Request is within the runtime contract.",
        contract=contract,
    )


def claimed_contract_id(metadata: Optional[dict[str, Any]]) -> Optional[str]:
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("contract_id")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
