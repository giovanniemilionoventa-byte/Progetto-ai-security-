#!/usr/bin/env python3
"""Phase 17 — end-to-end reference workflow driver.

Runs on the host against a live compose stack and plays the two roles the agent
cannot play for itself:

  the operator  -- provisions the agent (identity, permissions, runtime
                   contract, approval policy) through the control plane;
  the human     -- approves the one action that policy sends for review.

The agent itself runs inside the agent container, on agent_net, with nothing but
its Aegis token. The operator work happens over the control plane's published
port, which is the only service exposed to the host; the agent has no route to
it, and that is asserted by the boundary proof.

Usage:
    python3 infra/reference-agent/run_reference_workflow.py \
        --out docs/evidence/phase17_reference_workflow.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = "http://127.0.0.1:8000"
AGENT_CONTAINER = "aegis-agent"
AGENT_NAME = "Reference Sales Agent"
DEMO_EMAIL = "admin@acme.test"
DEMO_PASSWORD = "aegis-demo"


def _request(method: str, path: str, body=None, token=None, timeout=20.0) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        f"{CONTROL_PLANE}{path}", data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return {"status": int(response.status), "body": json.loads(raw or "{}")}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw or "{}")
        except ValueError:
            parsed = {"raw": raw[:400]}
        return {"status": int(exc.code), "body": parsed}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": None, "body": {"transport_error": str(exc)}}


def login() -> str:
    response = _request(
        "POST", "/api/auth/login", {"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
    )
    if response["status"] != 200:
        raise SystemExit(f"control plane login failed: {response}")
    return response["body"]["access_token"]


def provision(token: str) -> dict:
    """Operator work: identity, least privilege, contract, approval policy."""
    steps = []

    created = _request(
        "POST",
        "/api/agents",
        {
            "name": AGENT_NAME,
            "provider": "reference",
            "model": "deterministic",
            "description": "Phase 17 reference agent",
        },
        token,
    )
    if created["status"] != 200:
        raise SystemExit(f"could not create agent: {created}")
    agent_id = created["body"]["agent"]["id"]
    agent_token = created["body"]["token"]
    steps.append({"step": "create_agent", "agent_id": agent_id, "status": 200})

    # Least privilege: read and update only. No delete, no payments, no files.
    for kind, action, scope in (
        ("crm", "READ", "customers"),
        ("crm", "UPDATE", "customers"),
    ):
        result = _request(
            "POST",
            f"/api/agents/{agent_id}/permissions",
            {
                "resource_kind": kind,
                "action": action,
                "scope": scope,
                "effect": "allow",
            },
            token,
        )
        steps.append(
            {
                "step": "grant_permission",
                "permission": f"{kind}.{action}:{scope}",
                "status": result["status"],
            }
        )

    # The runtime contract: what this agent is for.
    contract = _request(
        "POST",
        f"/api/agents/{agent_id}/contracts",
        {
            "organization_id": "set-by-server",
            "agent_id": "set-by-server",
            "contract_id": "reference-sales-agent",
            "version": 1,
            "status": "ACTIVE",
            "purpose": "Read and correct customer records. Never delete, never pay.",
            "capabilities": [
                {"name": "crm", "resource_kind": "crm", "actions": ["READ", "UPDATE"]}
            ],
            "resources": [{"kind": "crm", "scope": "customers"}],
            "constraints": {"payload_size": {"max_bytes": 4096}},
            "data_constraints": {"denied_fields": ["ssn", "secret", "password"]},
            "approval_rules": [
                {"resource_kind": "crm", "action": "UPDATE", "require": "human"}
            ],
        },
        token,
    )
    if contract["status"] != 201:
        raise SystemExit(f"could not create contract: {contract}")
    steps.append(
        {
            "step": "activate_contract",
            "contract_id": contract["body"]["contract_id"],
            "version": contract["body"]["version"],
            "status": contract["body"]["status"],
        }
    )

    # Policy: a customer record change needs a human.
    policy = _request(
        "POST",
        "/api/policies",
        {
            "name": "Reference agent CRM updates need a human",
            "description": "Customer record changes are reviewed.",
            "resource_kind": "crm",
            "action": "UPDATE",
            "scope_pattern": "*",
            "decision": "APPROVAL",
            "priority": 2,
        },
        token,
    )
    steps.append({"step": "approval_policy", "status": policy["status"]})

    return {
        "agent_id": agent_id,
        "agent_token": agent_token,
        "contract": contract["body"],
        "steps": steps,
    }


def approve_when_pending(token: str, agent_id: str, record: dict) -> None:
    """Play the human. Approve the first pending request from this agent."""
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        listing = _request("GET", "/api/approvals?status_filter=pending", None, token)
        rows = [
            row
            for row in (listing.get("body") or [])
            if row.get("agent_id") == agent_id and row.get("status") == "pending"
        ]
        if rows:
            target = rows[0]
            decided = _request(
                "POST",
                f"/api/approvals/{target['id']}/decide",
                {"decision": "ALLOW"},
                token,
            )
            record["approval"] = {
                "approval_id": target["id"],
                "resource": f"{target['resource_kind']}.{target['action']}",
                "scope": target["scope"],
                "bound_execution": target.get("execution_id"),
                "bound_request": target.get("request_id"),
                "bound_contract": target.get("contract_id"),
                "bound_param_hash": target.get("param_hash"),
                "decided_status": decided["status"],
                "decided_at": datetime.now(timezone.utc).isoformat(),
            }
            return
        time.sleep(1.0)
    record["approval"] = {"error": "no pending approval appeared within 75s"}


def create_foreign_execution(token: str) -> str:
    """Make a real execution owned by a different agent, for the theft attempt.

    Inventing an unused execution_id is legitimate -- agents name their own
    executions -- so the adversarial case has to be an execution that genuinely
    exists under another owner.

    The call has to originate inside the agent network: /api/authorize lives on
    the enforcement gateway, and the gateway is deliberately unreachable from
    the host (see the boundary proof). So we borrow the seeded Sales Copilot's
    token and drive it from the agent container, which is exactly how a second
    tenant agent would behave.
    """
    agents = _request("GET", "/api/agents", None, token)["body"]
    other = next((a for a in agents if a["name"] == "Sales Copilot"), None)
    if other is None:
        return ""
    rotated = _request("POST", f"/api/agents/{other['id']}/rotate", None, token)
    if rotated["status"] != 200:
        return ""
    other_token = rotated["body"]["token"]
    execution_id = f"foreign-exec-{int(time.time())}"

    script = (
        "import json,os,urllib.request,urllib.error\n"
        "req=urllib.request.Request(\n"
        "  os.environ['AEGIS_BASE_URL']+'/api/gateway/tools/crm/read',\n"
        "  data=json.dumps({'scope':'customers','execution_id':os.environ['EXEC'],\n"
        "    'request_id':'foreign-'+os.environ['EXEC'],'payload':{}}).encode(),\n"
        "  headers={'Content-Type':'application/json',\n"
        "           'X-Agent-Token':os.environ['TOK']},method='POST')\n"
        "try:\n"
        "  print(urllib.request.urlopen(req,timeout=20).read().decode())\n"
        "except urllib.error.HTTPError as e:\n"
        "  print(e.code, e.read().decode()[:200])\n"
    )
    result = subprocess.run(
        [
            "docker", "exec",
            "-e", f"TOK={other_token}",
            "-e", f"EXEC={execution_id}",
            AGENT_CONTAINER, "python", "-c", script,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0 or '"decision"' not in (result.stdout or ""):
        return ""
    return execution_id


def _service_ips(container: str) -> str:
    result = subprocess.run(
        [
            "docker", "inspect", container, "-f",
            "{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}},{{end}}",
        ],
        capture_output=True, text=True, timeout=30,
    )
    return ",".join(
        part for part in (result.stdout or "").strip().split(",") if part
    )


def run_agent(agent_token: str, execution_id: str, foreign_execution_id: str = "") -> dict:
    """Execute the reference agent inside the agent container."""
    result = subprocess.run(
        [
            "docker",
            "exec",
            "-e",
            f"AEGIS_AGENT_TOKEN={agent_token}",
            "-e",
            "AEGIS_APPROVAL_WAIT_SECONDS=90",
            "-e",
            f"AEGIS_FOREIGN_EXECUTION_ID={foreign_execution_id}",
            "-e",
            f"AEGIS_BROKER_IPS={_service_ips('aegis-credential-broker')}",
            "-e",
            f"AEGIS_TOOL_IPS={_service_ips('aegis-protected-tool')}",
            "-e",
            f"AEGIS_CONTROL_IPS={_service_ips('aegis-control-plane')}",
            AGENT_CONTAINER,
            "python",
            "/agent/reference_agent.py",
            "--execution-id",
            execution_id,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    text = (result.stdout or "").strip()
    try:
        return json.loads(text)
    except ValueError:
        return {
            "error": "agent output unparseable",
            "returncode": result.returncode,
            "stdout": text[:3000],
            "stderr": (result.stderr or "")[:2000],
        }


def collect_evidence(token: str, execution_id: str) -> dict:
    return _request(
        "GET", f"/api/executions/{execution_id}/evidence", None, token
    )["body"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    token = login()
    provisioning = provision(token)
    execution_id = f"ref-exec-{int(time.time())}"

    # The human approves in the background while the agent waits by re-sending.
    record: dict = {}
    approver = threading.Thread(
        target=approve_when_pending,
        args=(token, provisioning["agent_id"], record),
        daemon=True,
    )
    approver.start()

    foreign_execution_id = create_foreign_execution(token)
    transcript = run_agent(
        provisioning["agent_token"], execution_id, foreign_execution_id
    )
    approver.join(timeout=10)

    evidence = collect_evidence(token, execution_id)

    report = {
        "schema": "aegis.reference_workflow/v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "agent_kind": "REFERENCE_AGENT",
        "readedge_integration": "NOT_PRESENT",
        "provisioning": {
            "agent_id": provisioning["agent_id"],
            "contract_id": provisioning["contract"]["contract_id"],
            "contract_version": provisioning["contract"]["version"],
            "steps": provisioning["steps"],
        },
        "foreign_execution_id": foreign_execution_id,
        "human_approval": record.get("approval"),
        "agent_transcript": transcript,
        "execution_evidence": evidence,
    }

    evaluation = transcript.get("evaluation") or {}
    chain_valid = ((evidence or {}).get("verdict") or {}).get("valid")
    report["summary"] = {
        "agent_verdict": evaluation.get("verdict", "UNKNOWN"),
        "agent_checks_passed": evaluation.get("passed"),
        "agent_checks_total": evaluation.get("total"),
        "agent_checks_failed": evaluation.get("failed", []),
        "evidence_chain_valid": chain_valid,
        "evidence_event_count": (evidence or {}).get("event_count"),
        "overall": (
            "PASS"
            if evaluation.get("verdict") == "PASS" and chain_valid is True
            else "FAIL"
        ),
    }

    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    if not args.quiet:
        print(text)

    print(
        f"\n{report['summary']['overall']}: agent "
        f"{report['summary']['agent_checks_passed']}/"
        f"{report['summary']['agent_checks_total']} checks, "
        f"evidence chain valid={chain_valid}",
        file=sys.stderr,
    )
    return 0 if report["summary"]["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
