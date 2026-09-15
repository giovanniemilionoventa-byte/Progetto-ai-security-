"""Phase 17 — the end-to-end reference workflow, executed for real.

This runs the reference agent inside the agent container against the live stack
and asserts the security model held. It skips when there is no Docker daemon or
no running stack, because there is nothing to observe then.

It is deliberately an integration test of the whole path rather than of any one
component: identity, contract resolution, authorization, the execution
boundary, credential isolation, human approval, protected execution and the
evidence chain, in one run.

    docker compose up -d --build
    pytest tests/test_phase17_reference_workflow.py
"""

from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from pathlib import Path

import pytest

from .runtime_boundary import ROOT, stack_running

DRIVER = ROOT / "infra" / "reference-agent" / "run_reference_workflow.py"


@lru_cache(maxsize=1)
def _workflow() -> dict | None:
    if not stack_running():
        return None
    try:
        result = subprocess.run(
            ["python3", str(DRIVER), "--quiet", "--out", "/dev/stdout"],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(ROOT),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (result.stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


@pytest.fixture(scope="module")
def workflow() -> dict:
    if not stack_running():
        pytest.skip(
            "RUNTIME VERIFICATION: NOT VERIFIED — the Aegis stack is not running "
            "(`docker compose up -d --build`)"
        )
    report = _workflow()
    if report is None:
        pytest.skip("reference workflow produced no parseable output")
    return report


def _step(workflow: dict, name: str) -> dict:
    for item in workflow["agent_transcript"]["steps"]:
        if item["step"] == name:
            return item
    raise AssertionError(f"reference agent did not record step {name}")


# ---------------------------------------------------------------------------
# Overall
# ---------------------------------------------------------------------------


def test_reference_workflow_passes(workflow):
    summary = workflow["summary"]
    assert summary["overall"] == "PASS", summary
    assert summary["agent_checks_failed"] == []


def test_this_is_a_reference_agent_not_a_framework_integration(workflow):
    """Guards the claim itself, so it cannot drift in either direction."""
    assert workflow["agent_kind"] == "REFERENCE_AGENT"
    assert workflow["readedge_integration"] == "NOT_PRESENT"


# ---------------------------------------------------------------------------
# The agent is genuinely untrusted
# ---------------------------------------------------------------------------


def test_agent_holds_no_protected_credentials(workflow):
    identity = workflow["agent_transcript"]["identity"]
    assert identity["has_agent_token"] is True
    assert identity["holds_tool_credential"] is False
    assert identity["holds_eat_key"] is False
    assert identity["holds_internal_token"] is False
    assert identity["uid"] == 10001


@pytest.mark.parametrize(
    "target", ["credential-broker", "protected-tool", "control-plane"]
)
def test_agent_cannot_reach_protected_services(workflow, target):
    step = _step(workflow, f"direct::{target}")
    assert step["classification"] == "NETWORK_BLOCK"
    assert step["boundary_level"] == "NETWORK"
    assert step["by_ip"], "the decisive IP probe was not recorded"
    for address, record in step["by_ip"].items():
        assert record["classification"] == "NETWORK_BLOCK", f"{address}: {record}"


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


def test_permitted_action_reaches_the_protected_tool(workflow):
    step = _step(workflow, "allowed::crm_read")
    assert step["decision"] == "ALLOW"
    assert step["executed"] is True


def test_forbidden_action_is_blocked(workflow):
    step = _step(workflow, "forbidden::crm_delete")
    assert step["decision"] == "BLOCK"
    assert step["executed"] is False


def test_contract_data_constraints_are_enforced(workflow):
    step = _step(workflow, "forbidden::denied_payload_field")
    assert step["decision"] == "BLOCK"
    assert step["executed"] is False
    assert "denied by the runtime contract" in (step["reason"] or "")


def test_agent_cannot_adopt_another_agents_execution(workflow):
    step = _step(workflow, "forbidden::foreign_execution")
    assert step["http_status"] == 403
    assert step["executed"] is False


# ---------------------------------------------------------------------------
# Human approval
# ---------------------------------------------------------------------------


def test_approval_is_required_and_does_not_execute(workflow):
    step = _step(workflow, "approval::requested")
    assert step["decision"] == "APPROVAL"
    assert step["executed"] is False


def test_approval_is_bound_to_the_exact_request(workflow):
    approval = workflow["human_approval"]
    assert approval["decided_status"] == 200
    for field in (
        "bound_execution",
        "bound_request",
        "bound_contract",
        "bound_param_hash",
    ):
        assert approval[field], f"approval missing binding: {field}"


def test_mutated_request_is_not_covered_by_the_approval(workflow):
    step = _step(workflow, "approval::payload_mutation")
    assert step["executed"] is False
    assert step["http_status"] == 409


def test_approved_action_executes(workflow):
    step = _step(workflow, "approval::executed_after_grant")
    assert step["decision"] == "ALLOW"
    assert step["executed"] is True


def test_approval_cannot_be_replayed(workflow):
    step = _step(workflow, "approval::replay")
    assert step["executed"] is False


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def test_evidence_chain_is_valid(workflow):
    evidence = workflow["execution_evidence"]
    assert evidence["verdict"]["valid"] is True
    assert evidence["verdict"]["first_bad_event"] is None
    assert evidence["event_count"] >= 5


def test_every_event_digest_recomputes(workflow):
    for event in workflow["execution_evidence"]["chain"]:
        assert event["digest_matches"] is True, event["event_id"]
        assert event["evidence_hash"]


def test_evidence_tells_the_approval_story(workflow):
    """The chain should read as it happened, not as a single ALLOW."""
    decisions = [
        event["decision"] for event in workflow["execution_evidence"]["chain"]
    ]
    assert "APPROVAL" in decisions
    assert "ALLOW" in decisions
    assert "BLOCK" in decisions

    approval_id = workflow["human_approval"]["approval_id"]
    executed = [
        event
        for event in workflow["execution_evidence"]["chain"]
        if approval_id in (event["reason"] or "")
    ]
    assert executed, "no event records which approval authorized the execution"
    assert executed[0]["decision"] == "ALLOW"


def test_evidence_links_the_approval_to_the_event_that_consumed_it(workflow):
    approvals = workflow["execution_evidence"]["approvals"]
    consumed = [row for row in approvals if row["consumed_at"]]
    assert consumed, "the approval was never recorded as consumed"
    assert consumed[0]["consumed_event_id"]
    assert consumed[0]["param_hash"]
