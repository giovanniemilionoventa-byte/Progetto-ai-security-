#!/usr/bin/env python3
"""Phase 17 — execution-boundary runtime proof harness.

Runs on the host against a live `docker compose` stack and produces a single
evidence document showing, for every path in the Phase 10 trust matrix, whether
the block is enforced by the *network* or merely by *application code*.

The distinction is the entire point. Earlier phases could only assert that the
compose YAML declared a topology; this harness observes what the kernel
actually does from inside each container.

Usage:
    python3 infra/boundary/boundary_proof.py --out docs/evidence/boundary.json

Exit code is non-zero if any path does not match its expectation, so this is
usable as a gate in CI wherever a Docker daemon is available.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

AGENT = "aegis-agent"
GATEWAY = "aegis-enforcement-gateway"
BROKER = "aegis-credential-broker"
TOOL = "aegis-protected-tool"
CONTROL = "aegis-control-plane"

SERVICE_CONTAINERS = {
    "enforcement-gateway": GATEWAY,
    "credential-broker": BROKER,
    "protected-tool": TOOL,
    "control-plane": CONTROL,
}

# source container, destination service, expected verdict, why it matters
MATRIX = [
    (AGENT, "enforcement-gateway", "ALLOW", "the only door the agent may use"),
    (AGENT, "credential-broker", "DENY", "agent must never reach the broker"),
    (AGENT, "protected-tool", "DENY", "agent must never reach the tool directly"),
    (AGENT, "control-plane", "DENY", "agent must never reach the control plane"),
    (GATEWAY, "credential-broker", "ALLOW", "gateway dispatches through the broker"),
    (GATEWAY, "protected-tool", "DENY", "gateway must not bypass the broker"),
    (BROKER, "protected-tool", "ALLOW", "broker executes against the tool"),
    (BROKER, "control-plane", "DENY", "broker has no control-plane access"),
]

# container -> expected filesystem visibility of the SQLite volume
DB_MATRIX = [
    (AGENT, "DENY", "agent has no aegis-data volume"),
    (BROKER, "DENY", "broker has no aegis-data volume"),
    (TOOL, "DENY", "protected tool has no aegis-data volume"),
    (CONTROL, "ALLOW", "control plane legitimately owns the database"),
    (GATEWAY, "ALLOW", "gateway shares the database (known Phase 10 limitation)"),
]

# Inline prober for containers that do not ship probe.py. Mirrors the
# classification logic in infra/agent/probe.py exactly.
INLINE_TCP = r"""
import errno, json, socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
NET = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT, errno.ENETDOWN,
       errno.EACCES, errno.EPERM}
rec = {"host": host, "port": port, "connected": False, "errno": None,
       "errno_name": None, "error": None, "dns_error": False, "resolved_to": None}
t0 = time.monotonic()
try:
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    rec["resolved_to"] = sorted({i[4][0] for i in infos})
except socket.gaierror as e:
    rec["dns_error"] = True
    rec["error"] = "getaddrinfo: %s" % e
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4.0)
    try:
        s.connect((rec["resolved_to"][0], port))
        rec["connected"] = True
    except socket.timeout:
        rec["errno"] = errno.ETIMEDOUT
        rec["errno_name"] = "ETIMEDOUT"
        rec["error"] = "connect timed out"
    except OSError as e:
        rec["errno"] = e.errno
        rec["errno_name"] = errno.errorcode.get(e.errno, "errno_%s" % e.errno)
        rec["error"] = str(e)
    finally:
        try:
            s.close()
        except OSError:
            pass
rec["elapsed_ms"] = round((time.monotonic() - t0) * 1000, 2)
if rec["connected"]:
    rec["classification"] = "ALLOW"
elif rec["dns_error"]:
    rec["classification"] = "DNS_BLOCK"
elif rec["errno"] in NET:
    rec["classification"] = "NETWORK_BLOCK"
elif rec["errno"] == errno.ECONNREFUSED:
    rec["classification"] = "PORT_CLOSED"
else:
    rec["classification"] = "UNKNOWN_BLOCK"
print(json.dumps(rec))
"""

INLINE_DB = r"""
import json, os
paths = {}
for p in ("/data/aegis.db", "/data"):
    paths[p] = {"exists": os.path.exists(p), "readable": os.access(p, os.R_OK)}
try:
    mounts = open("/proc/self/mounts").read().splitlines()
except OSError:
    mounts = []
rel = [m for m in mounts if "aegis" in m or " /data " in m]
reachable = any(v["exists"] and v["readable"] for v in paths.values())
print(json.dumps({"paths": paths, "aegis_related_mounts": rel,
                  "classification": "FILESYSTEM_ALLOW" if reachable else "FILESYSTEM_BLOCK",
                  "verdict": "ALLOW" if reachable else "DENY"}))
"""


def run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_available() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker CLI not installed"
    probe = run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    if probe.returncode != 0:
        return False, "docker daemon not reachable"
    return True, probe.stdout.strip()


def inspect_ip(container: str, network: str | None = None) -> dict[str, str]:
    fmt = "{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}};{{end}}"
    result = run(["docker", "inspect", container, "-f", fmt])
    if result.returncode != 0:
        return {}
    out = {}
    for chunk in result.stdout.strip().split(";"):
        if "=" in chunk:
            key, _, value = chunk.partition("=")
            if value:
                out[key] = value
    return out


def container_exists(name: str) -> bool:
    return run(["docker", "inspect", name, "-f", "{{.Id}}"]).returncode == 0


def exec_json(container: str, script: str, args: list[str]) -> dict:
    result = run(
        ["docker", "exec", container, "python", "-c", script, *args], timeout=90
    )
    text = (result.stdout or "").strip()
    try:
        return json.loads(text.splitlines()[-1]) if text else {
            "error": "no output", "stderr": (result.stderr or "")[:400]
        }
    except (ValueError, IndexError):
        return {"error": "unparseable", "stdout": text[:400],
                "stderr": (result.stderr or "")[:400]}


def agent_probe(target_ips: dict[str, str]) -> dict:
    """Run the project's own probe.py inside the agent container."""
    env_args: list[str] = []
    mapping = {
        "enforcement-gateway": "AEGIS_GATEWAY_IP",
        "control-plane": "AEGIS_CONTROL_IP",
        "credential-broker": "AEGIS_BROKER_IP",
        "protected-tool": "AEGIS_TOOL_IP",
    }
    for service, var in mapping.items():
        ip = target_ips.get(service, "")
        if ip:
            env_args += ["-e", f"{var}={ip}"]
    result = run(
        ["docker", "exec", *env_args, AGENT, "python", "/agent/probe.py"], timeout=180
    )
    text = (result.stdout or "").strip()
    try:
        return json.loads(text)
    except ValueError:
        return {"error": "probe output unparseable",
                "stdout": text[:2000], "stderr": (result.stderr or "")[:800]}


def topology() -> dict:
    nets = {}
    listing = run(["docker", "network", "ls", "--format", "{{.Name}}"])
    for name in listing.stdout.split():
        if not name.startswith("aegis"):
            continue
        info = run([
            "docker", "network", "inspect", name, "-f",
            "{{.Internal}}|{{range .IPAM.Config}}{{.Subnet}}{{end}}|"
            "{{range $k,$v := .Containers}}{{$v.Name}},{{end}}",
        ])
        parts = info.stdout.strip().split("|")
        if len(parts) >= 3:
            nets[name] = {
                "internal": parts[0] == "true",
                "subnet": parts[1],
                "attached": [c for c in parts[2].split(",") if c],
            }
    return nets


def host_published_ports() -> dict:
    out = {}
    for container in (CONTROL, GATEWAY, BROKER, TOOL, AGENT):
        if not container_exists(container):
            continue
        result = run(["docker", "port", container])
        out[container] = [line for line in result.stdout.splitlines() if line.strip()]
    return out


def build_evidence() -> dict:
    ok, server = docker_available()
    if not ok:
        return {
            "schema": "aegis.execution_boundary.proof/v1",
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "status": "NOT_VERIFIED",
            "reason": server,
            "checks": [],
        }

    missing = [c for c in (AGENT, GATEWAY, BROKER, TOOL, CONTROL) if not container_exists(c)]
    if missing:
        return {
            "schema": "aegis.execution_boundary.proof/v1",
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "status": "NOT_VERIFIED",
            "reason": f"stack not running, missing containers: {missing}",
            "checks": [],
        }

    ips = {svc: inspect_ip(name) for svc, name in SERVICE_CONTAINERS.items()}
    # Every address a service owns, so a DENY target must fail on all of them and
    # an ALLOW target is not judged by an address on a network we do not share.
    flat_ip = {svc: ",".join(sorted(addrs.values())) for svc, addrs in ips.items()}

    checks = []
    for source, service, expected, rationale in MATRIX:
        dest_container = SERVICE_CONTAINERS[service]
        dest_ips = ips[service]
        source_nets = inspect_ip(source)
        # Probe every IP the destination owns; the agent must fail on all of them.
        per_ip = {}
        for net, ip in sorted(dest_ips.items()):
            per_ip[f"{net}:{ip}"] = exec_json(source, INLINE_TCP, [ip, "8000"])
        by_name = exec_json(source, INLINE_TCP, [dest_container.replace("aegis-", ""), "8000"])

        classes = {rec.get("classification") for rec in per_ip.values()}
        if "ALLOW" in classes:
            effective = "ALLOW"
        elif classes == {"NETWORK_BLOCK"}:
            effective = "NETWORK_BLOCK"
        elif "PORT_CLOSED" in classes:
            effective = "PORT_CLOSED"
        else:
            effective = sorted(classes)[0] if classes else "UNKNOWN_BLOCK"

        observed = "ALLOW" if effective == "ALLOW" else "DENY"
        checks.append({
            "source": source,
            "source_networks": source_nets,
            "destination": dest_container,
            "destination_service": service,
            "destination_ips": dest_ips,
            "expected": expected,
            "observed": observed,
            "classification": effective,
            "boundary_level": (
                "NETWORK" if effective in ("NETWORK_BLOCK", "DNS_BLOCK")
                else "APPLICATION" if effective == "APPLICATION_BLOCK"
                else "NONE"
            ),
            "by_ip": per_ip,
            "by_name": by_name,
            "rationale": rationale,
            "ok": observed == expected,
        })

    db_checks = []
    for container, expected, rationale in DB_MATRIX:
        record = exec_json(container, INLINE_DB, [])
        observed = record.get("verdict", "UNKNOWN")
        db_checks.append({
            "source": container,
            "destination": "sqlite volume aegis-data",
            "transport": "filesystem",
            "expected": expected,
            "observed": observed,
            "evidence": record,
            "rationale": rationale,
            "ok": observed == expected,
        })

    probe_payload = agent_probe(flat_ip)

    all_checks = checks + db_checks
    failed = [c for c in all_checks if not c["ok"]]
    network_enforced = [
        f"{c['source']} -> {c['destination']}"
        for c in checks
        if c["classification"] == "NETWORK_BLOCK"
    ]
    application_only = [
        f"{c['source']} -> {c['destination']}"
        for c in checks
        if c["classification"] == "APPLICATION_BLOCK"
    ]

    return {
        "schema": "aegis.execution_boundary.proof/v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "status": "VERIFIED" if not failed else "FAILED",
        "docker_server_version": server,
        "topology": topology(),
        "host_published_ports": host_published_ports(),
        "checks": checks,
        "database_checks": db_checks,
        "agent_probe": probe_payload,
        "summary": {
            "total": len(all_checks),
            "passed": len(all_checks) - len(failed),
            "failed": [f"{c['source']} -> {c['destination']}" for c in failed],
            "network_level_blocks": sorted(network_enforced),
            "application_level_only": sorted(application_only),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="", help="write the evidence JSON here")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    evidence = build_evidence()
    text = json.dumps(evidence, indent=2, sort_keys=True)
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    if not args.quiet:
        print(text)

    status = evidence.get("status")
    if status == "NOT_VERIFIED":
        print(f"\nNOT VERIFIED: {evidence.get('reason')}", file=sys.stderr)
        return 2
    if status != "VERIFIED":
        print(f"\nFAILED: {evidence['summary']['failed']}", file=sys.stderr)
        return 1
    print(
        "\nVERIFIED: {p}/{t} paths match. network-level blocks: {n}".format(
            p=evidence["summary"]["passed"],
            t=evidence["summary"]["total"],
            n=len(evidence["summary"]["network_level_blocks"]),
        ),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
