#!/usr/bin/env python3
"""Demo AI agent that routes every tool call through Aegis."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python"))

from aegis_sdk import AegisClient, AegisDecision

TOOLS = [
    {
        "name": "crm.read",
        "resource_kind": "crm",
        "action": "READ",
        "scope": "customers",
        "destination": None,
        "description": "Read customer records from CRM",
    },
    {
        "name": "crm.delete",
        "resource_kind": "crm",
        "action": "DELETE",
        "scope": "all",
        "destination": None,
        "description": "Delete all CRM customers (irreversible)",
    },
    {
        "name": "email.send_internal",
        "resource_kind": "email",
        "action": "SEND",
        "scope": "internal",
        "destination": "internal",
        "description": "Send email to internal recipients",
    },
    {
        "name": "email.send_external",
        "resource_kind": "email",
        "action": "SEND",
        "scope": "external",
        "destination": "external",
        "description": "Send email outside the company",
    },
    {
        "name": "files.read_sales",
        "resource_kind": "files",
        "action": "READ",
        "scope": "/Sales",
        "destination": None,
        "description": "Read files under /Sales",
    },
    {
        "name": "files.export_finance",
        "resource_kind": "files",
        "action": "EXPORT",
        "scope": "/Finance",
        "destination": "external",
        "description": "Export finance files off-perimeter",
    },
    {
        "name": "payments.transfer",
        "resource_kind": "payments",
        "action": "TRANSFER",
        "scope": "any",
        "destination": "external",
        "description": "Transfer funds (hard-blocked)",
    },
]


def load_token() -> str:
    env = os.environ.get("AEGIS_AGENT_TOKEN")
    if env:
        return env
    path = Path("/tmp/aegis_demo_token.txt")
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    raise SystemExit("No agent token. Set AEGIS_AGENT_TOKEN or seed the backend.")


def execute_tool(name: str, decision: AegisDecision) -> dict:
    if decision.decision != "ALLOW":
        return {
            "tool": name,
            "executed": False,
            "evidence": {
                "request_id": decision.request_id,
                "decision": decision.decision,
                "reason": decision.reason,
                "risk": decision.risk_level,
            },
        }
    return {
        "tool": name,
        "executed": True,
        "result": f"simulated execution of {name}",
        "evidence": {
            "request_id": decision.request_id,
            "decision": decision.decision,
            "risk": decision.risk_level,
        },
    }


def run_all(base_url: str = "http://127.0.0.1:8000") -> list[dict]:
    client = AegisClient(load_token(), base_url=base_url)
    results = []
    try:
        for tool in TOOLS:
            decision = client.authorize(
                resource_kind=tool["resource_kind"],
                action=tool["action"],
                scope=tool["scope"],
                destination=tool["destination"],
                metadata={"tool": tool["name"]},
            )
            results.append(execute_tool(tool["name"], decision))
            print(
                f"{tool['name']:24} {decision.decision:10} "
                f"risk={decision.risk_level:8} {decision.reason}"
            )
    finally:
        client.close()
    return results


def main() -> None:
    base = os.environ.get("AEGIS_BASE_URL", "http://127.0.0.1:8000")
    results = run_all(base)
    print(json.dumps({"count": len(results), "results": results}, indent=2))


if __name__ == "__main__":
    main()
