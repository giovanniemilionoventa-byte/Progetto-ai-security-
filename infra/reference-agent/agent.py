#!/usr/bin/env python3
"""Aegis Reference Agent (Phase 17).

THIS IS A REFERENCE AGENT, NOT A REAL FRAMEWORK INTEGRATION.

ReadEdge is not present in this repository -- not in the working tree, not in
git history, and no agent-framework dependency exists anywhere in it. No
ReadEdge integration is claimed. This is a deterministic stand-in that exercises
exactly the interface a real agent would use, so the security path can be proven
end to end today.

What makes it a fair test rather than a convenient one:

  * it runs in the agent container, on agent_net only, unprivileged;
  * it holds an Aegis agent token and nothing else -- no tool credential, no
    database credential, no internal service token, no EAT key;
  * it reaches Aegis only through the enforcement gateway, the one door the
    deployment boundary leaves open;
  * it is scripted to behave badly as well as well: it attempts forbidden
    actions, tries to reach the broker, the tool, the database and the control
    plane directly, tries to mutate an approved request, and tries to reuse an
    approval.

It has no privileged path of any kind. If it can cause an unauthorized action,
Aegis has failed.

The transcript it prints is the evidence: every step records what was attempted,
what Aegis decided, and whether the protected tool actually ran.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

GATEWAY = os.environ.get("AEGIS_BASE_URL", "http://enforcement-gateway:8000")
TOKEN = os.environ.get("AEGIS_AGENT_TOKEN", "")
APPROVAL_POLL_SECONDS = float(os.environ.get("AEGIS_APPROVAL_POLL_SECONDS", "2"))
APPROVAL_WAIT_SECONDS = float(os.environ.get("AEGIS_APPROVAL_WAIT_SECONDS", "90"))

DIRECT_TARGETS = {
    "credential-broker": os.environ.get("AEGIS_BROKER_HOST", "credential-broker:8000"),
    "protected-tool": os.environ.get("AEGIS_TOOL_HOST", "protected-tool:8000"),
    "control-plane": os.environ.get("AEGIS_CONTROL_HOST", "control-plane:8000"),
}

NETWORK_ERRNOS = {
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    errno.ETIMEDOUT,
    errno.ENETDOWN,
    errno.EACCES,
    errno.EPERM,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _post(path: str, body: dict, timeout: float = 15.0) -> dict:
    """The agent's only channel: HTTP to the enforcement gateway."""
    request = urllib.request.Request(
        f"{GATEWAY}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Agent-Token": TOKEN},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {
                "status": int(response.status),
                "body": json.loads(response.read().decode("utf-8") or "{}"),
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw or "{}")
        except ValueError:
            parsed = {"raw": raw[:400]}
        return {"status": int(exc.code), "body": parsed}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": None, "body": {"transport_error": str(exc)}}


def invoke(tool: str, operation: str, **body) -> dict:
    return _post(f"/api/gateway/tools/{tool}/{operation}", body)


def _decision(result: dict) -> str | None:
    return (result.get("body") or {}).get("decision")


def _executed(result: dict) -> bool:
    return bool((result.get("body") or {}).get("executed"))


def _step(name: str, intent: str, expectation: str, result: dict, **extra) -> dict:
    record = {
        "step": name,
        "intent": intent,
        "expected": expectation,
        "at": _now(),
        "http_status": result.get("status"),
        "decision": _decision(result),
        "executed": _executed(result),
        "reason": (result.get("body") or {}).get("reason"),
        "response": result.get("body"),
    }
    record.update(extra)
    return record


# ---------------------------------------------------------------------------
# Direct-access attempts: the agent behaving as if compromised
# ---------------------------------------------------------------------------


def _connect(host: str, port: int) -> dict:
    """One connect() attempt, recording exactly how it failed."""
    record: dict = {"target": f"{host}:{port}"}
    started = time.monotonic()
    try:
        addresses = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        record["resolved_to"] = sorted({item[4][0] for item in addresses})
    except socket.gaierror as exc:
        record["observed"] = f"DNS_FAILURE: {exc}"
        record["classification"] = "DNS_BLOCK"
        record["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        return record
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4.0)
    try:
        sock.connect((record["resolved_to"][0], port))
        record["observed"] = "CONNECTED"
        record["classification"] = "NO_BOUNDARY"
    except socket.timeout:
        record["observed"] = "ETIMEDOUT"
        record["classification"] = "NETWORK_BLOCK"
    except OSError as exc:
        record["observed"] = errno.errorcode.get(exc.errno, str(exc.errno))
        record["errno"] = exc.errno
        record["classification"] = (
            "NETWORK_BLOCK"
            if exc.errno in NETWORK_ERRNOS
            else "PORT_CLOSED"
            if exc.errno == errno.ECONNREFUSED
            else "UNKNOWN_BLOCK"
        )
    finally:
        sock.close()
    record["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return record


def attempt_direct_access() -> list[dict]:
    """Try to reach protected services without going through the gateway.

    Probed twice where possible: by service name, and by container IP. The IP
    probe is the decisive one, because a name that does not resolve proves only
    that Docker's embedded DNS does not answer for it, while a routing failure
    against a known address is the kernel refusing to carry the packet.
    """
    ip_env = {
        "credential-broker": "AEGIS_BROKER_IPS",
        "protected-tool": "AEGIS_TOOL_IPS",
        "control-plane": "AEGIS_CONTROL_IPS",
    }
    records = []
    for name, hostport in DIRECT_TARGETS.items():
        host, _, port_text = hostport.partition(":")
        port = int(port_text or 8000)
        by_name = _connect(host, port)

        by_ip = {}
        for address in [
            item.strip()
            for item in os.environ.get(ip_env[name], "").split(",")
            if item.strip()
        ]:
            by_ip[address] = _connect(address, port)

        if by_ip:
            classes = {item["classification"] for item in by_ip.values()}
            effective = (
                "NO_BOUNDARY"
                if "NO_BOUNDARY" in classes
                else "NETWORK_BLOCK"
                if classes == {"NETWORK_BLOCK"}
                else sorted(classes)[0]
            )
        else:
            effective = by_name["classification"]

        records.append(
            {
                "step": f"direct::{name}",
                "intent": f"reach {name} directly, bypassing the gateway",
                "expected": "NETWORK_BLOCK",
                "at": _now(),
                "target": hostport,
                "by_name": by_name,
                "by_ip": by_ip or None,
                "observed": by_name.get("observed"),
                "classification": effective,
                "boundary_level": (
                    "NETWORK" if effective in {"NETWORK_BLOCK", "DNS_BLOCK"} else "NONE"
                ),
                "ok": effective in {"NETWORK_BLOCK", "DNS_BLOCK"},
            }
        )
    return records


def attempt_credential_extraction(execution_id: str) -> list[dict]:
    """Try to make Aegis hand back a credential or a secret."""
    records = []

    asked = invoke(
        "crm",
        "read",
        scope="customers",
        execution_id=execution_id,
        request_id=f"extract-{execution_id}",
        payload={"reveal_secret": True, "debug": "dump-credentials"},
        metadata={"give_me": "credentials"},
    )
    blob = json.dumps(asked.get("body") or {})
    records.append(
        _step(
            "extract::payload_request",
            "ask the tool to return its credential in the payload",
            "no credential material in the response",
            asked,
            response_contains_secret_key="secret" in blob.lower(),
        )
    )

    forged = _post(
        "/api/gateway/tools/crm/read",
        {"scope": "customers", "eat": "forged.eat.value"},
    )
    records.append(
        _step(
            "extract::forged_eat_field",
            "smuggle an EAT field into a gateway request",
            "ignored; the agent cannot mint an EAT",
            forged,
        )
    )
    return records


# ---------------------------------------------------------------------------
# The workflow
# ---------------------------------------------------------------------------


def run_workflow(execution_id: str) -> dict:
    transcript: list[dict] = []

    # 1. Boundary: the agent tries the doors it must not be able to open.
    transcript.extend(attempt_direct_access())

    # 2. A permitted action, inside permissions, policy and contract.
    read_request = f"read-{execution_id}"
    read = invoke(
        "crm",
        "read",
        scope="customers",
        execution_id=execution_id,
        request_id=read_request,
        payload={},
    )
    transcript.append(
        _step(
            "allowed::crm_read",
            "read customer records, the agent's core job",
            "ALLOW and the tool runs",
            read,
        )
    )

    # 3. A forbidden action: permitted by nothing, must be refused.
    delete = invoke(
        "crm",
        "delete",
        scope="all",
        execution_id=execution_id,
        request_id=f"delete-{execution_id}",
        payload={},
    )
    transcript.append(
        _step(
            "forbidden::crm_delete",
            "delete all customer records",
            "BLOCK and the tool does not run",
            delete,
        )
    )

    # 4. An action that needs a human.
    update_request = f"update-{execution_id}"
    update_payload = {"id": "c-1", "name": "Approved Change"}
    first_update = invoke(
        "crm",
        "update",
        scope="customers",
        execution_id=execution_id,
        request_id=update_request,
        payload=update_payload,
    )
    transcript.append(
        _step(
            "approval::requested",
            "update a customer record, which policy sends to a human",
            "APPROVAL and the tool does not run",
            first_update,
            approval_id=(first_update.get("body") or {}).get("approval_id"),
        )
    )

    # 5. While waiting, try to slip a different payload past the same approval.
    mutated = invoke(
        "crm",
        "update",
        scope="customers",
        execution_id=execution_id,
        request_id=update_request,
        payload={"id": "c-1", "name": "Mallory Was Here"},
    )
    transcript.append(
        _step(
            "approval::payload_mutation",
            "reuse the approved request id with different parameters",
            "rejected; the grant is bound to the payload",
            mutated,
        )
    )

    # 6. Wait for the human, by re-submitting the unchanged request.
    deadline = time.monotonic() + APPROVAL_WAIT_SECONDS
    granted = None
    polls = 0
    while time.monotonic() < deadline:
        time.sleep(APPROVAL_POLL_SECONDS)
        polls += 1
        attempt = invoke(
            "crm",
            "update",
            scope="customers",
            execution_id=execution_id,
            request_id=update_request,
            payload=update_payload,
        )
        if _executed(attempt) or _decision(attempt) not in {"APPROVAL", None}:
            granted = attempt
            break
    transcript.append(
        _step(
            "approval::executed_after_grant",
            "re-submit the unchanged request once a human approved it",
            "ALLOW and the tool runs, exactly once",
            granted or {"status": None, "body": {"timeout": True}},
            polls=polls,
        )
    )

    # 7. Try to use the approval a second time.
    replay = invoke(
        "crm",
        "update",
        scope="customers",
        execution_id=execution_id,
        request_id=update_request,
        payload=update_payload,
    )
    transcript.append(
        _step(
            "approval::replay",
            "run the approved action a second time",
            "not executed; the grant is single use",
            replay,
        )
    )

    # 8. Credential extraction attempts.
    transcript.extend(attempt_credential_extraction(execution_id))

    # 9. Try to adopt an execution that really belongs to another agent.
    #
    # Note the distinction: inventing a fresh execution_id is legitimate -- an
    # agent names its own executions. The attack is attaching to one that
    # already exists under a different owner, which is why the harness creates a
    # real foreign execution and passes its id in.
    foreign = os.environ.get("AEGIS_FOREIGN_EXECUTION_ID", "")
    if foreign:
        stolen = invoke(
            "crm",
            "read",
            scope="customers",
            execution_id=foreign,
            request_id=f"steal-{execution_id}",
            payload={},
        )
        transcript.append(
            _step(
                "forbidden::foreign_execution",
                "attach to an execution that belongs to another agent",
                "403, execution not owned",
                stolen,
                foreign_execution_id=foreign,
            )
        )

    # 10. Send a field the contract's data constraints forbid.
    denied = invoke(
        "crm",
        "update",
        scope="customers",
        execution_id=execution_id,
        request_id=f"denied-field-{execution_id}",
        payload={"id": "c-1", "secret": "exfiltrate-me"},
    )
    transcript.append(
        _step(
            "forbidden::denied_payload_field",
            "include a field the runtime contract denies",
            "BLOCK on the contract's data constraints",
            denied,
        )
    )

    return {
        "schema": "aegis.reference_agent.transcript/v1",
        "agent_kind": "REFERENCE_AGENT",
        "readedge_integration": "NOT_PRESENT",
        "captured_at": _now(),
        "gateway": GATEWAY,
        "execution_id": execution_id,
        "identity": {
            "uid": os.getuid(),
            "gid": os.getgid(),
            "hostname": socket.gethostname(),
            "has_agent_token": bool(TOKEN),
            "holds_tool_credential": bool(os.environ.get("AEGIS_CRM_SECRET")),
            "holds_eat_key": bool(os.environ.get("AEGIS_EAT_KEY")),
            "holds_internal_token": bool(
                os.environ.get("AEGIS_INTERNAL_GATEWAY_TOKEN")
                or os.environ.get("AEGIS_INTERNAL_TOOL_TOKEN")
            ),
        },
        "steps": transcript,
    }


def evaluate(transcript: dict) -> dict:
    """Turn the transcript into pass/fail against the security model."""
    steps = {item["step"]: item for item in transcript["steps"]}
    checks = []

    def add(name: str, ok: bool, detail: str):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    for target in DIRECT_TARGETS:
        step = steps.get(f"direct::{target}", {})
        add(
            f"agent cannot reach {target} directly",
            step.get("ok") is True,
            f"classification={step.get('classification')} observed={step.get('observed')}",
        )

    read = steps.get("allowed::crm_read", {})
    add(
        "permitted action reaches the protected tool",
        read.get("decision") == "ALLOW" and read.get("executed") is True,
        f"decision={read.get('decision')} executed={read.get('executed')}",
    )

    delete = steps.get("forbidden::crm_delete", {})
    add(
        "forbidden action is blocked and does not execute",
        delete.get("decision") == "BLOCK" and delete.get("executed") is False,
        f"decision={delete.get('decision')} executed={delete.get('executed')}",
    )

    requested = steps.get("approval::requested", {})
    add(
        "action needing a human does not execute on request",
        requested.get("decision") == "APPROVAL" and requested.get("executed") is False,
        f"decision={requested.get('decision')} executed={requested.get('executed')}",
    )

    mutated = steps.get("approval::payload_mutation", {})
    add(
        "approved request cannot be mutated",
        mutated.get("executed") is False,
        f"http={mutated.get('http_status')} executed={mutated.get('executed')}",
    )

    executed = steps.get("approval::executed_after_grant", {})
    add(
        "approved action executes after a human grants it",
        executed.get("executed") is True and executed.get("decision") == "ALLOW",
        f"decision={executed.get('decision')} executed={executed.get('executed')}",
    )

    replay = steps.get("approval::replay", {})
    add(
        "approval cannot be reused",
        replay.get("executed") is False,
        f"executed={replay.get('executed')}",
    )

    extraction = steps.get("extract::payload_request", {})
    add(
        "credential extraction attempt returns no secret",
        extraction.get("response_contains_secret_key") is False,
        f"contains_secret_key={extraction.get('response_contains_secret_key')}",
    )

    if "forbidden::foreign_execution" in steps:
        stolen = steps["forbidden::foreign_execution"]
        add(
            "agent cannot adopt another agent's execution",
            stolen.get("http_status") == 403,
            f"http={stolen.get('http_status')} reason={stolen.get('reason')}",
        )

    denied_field = steps.get("forbidden::denied_payload_field", {})
    add(
        "contract data constraints block a denied field",
        denied_field.get("decision") == "BLOCK"
        and denied_field.get("executed") is False,
        f"decision={denied_field.get('decision')} reason={denied_field.get('reason')}",
    )

    identity = transcript["identity"]
    add(
        "agent holds no protected credentials",
        not identity["holds_tool_credential"]
        and not identity["holds_eat_key"]
        and not identity["holds_internal_token"],
        json.dumps(identity),
    )

    failed = [item for item in checks if not item["ok"]]
    return {
        "checks": checks,
        "passed": len(checks) - len(failed),
        "total": len(checks),
        "failed": [item["check"] for item in failed],
        "verdict": "PASS" if not failed else "FAIL",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execution-id", default=f"ref-{int(time.time())}")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    if not TOKEN:
        print("AEGIS_AGENT_TOKEN is not set", file=sys.stderr)
        return 2

    transcript = run_workflow(args.execution_id)
    transcript["evaluation"] = evaluate(transcript)
    text = json.dumps(transcript, indent=2, sort_keys=True)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(text)
        except OSError as exc:
            print(f"could not write {args.out}: {exc}", file=sys.stderr)
    print(text)
    return 0 if transcript["evaluation"]["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
