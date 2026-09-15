"""Reachability probe run inside the unprivileged agent container.

Phase 17 — this probe is the execution-boundary evidence collector.

It answers one question that an application-level test cannot: when the agent
container tries to open a socket to a protected service, does the *kernel*
refuse to route the packet, or does the packet arrive and get rejected by
application code?

Those two outcomes are not equivalent and are never reported as the same thing:

  NETWORK_BLOCK      the connect() failed at L3/L4 (ENETUNREACH, EHOSTUNREACH,
                     timeout). The agent has no route. This is a deployment
                     boundary.
  PORT_CLOSED        the connect() was refused (ECONNREFUSED). The host WAS
                     routable; something just was not listening. This is NOT a
                     boundary and must never be reported as one.
  DNS_BLOCK          the service name did not resolve. Evidence of non
                     attachment to a shared network, but weaker than a direct
                     IP probe, so every DENY target is probed by IP as well.
  APPLICATION_BLOCK  the socket connected and the application answered 401/403.
                     This is an application control, NOT a boundary.
  ALLOW              the socket connected and the service answered.

Every DENY target is probed twice: once by service name, once by the container
IP supplied by the harness (AEGIS_<NAME>_IP). The IP probe is the decisive one,
because it cannot be satisfied by a DNS failure.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

TARGETS = {
    "enforcement-gateway": os.environ.get("AEGIS_GATEWAY_HOST", "enforcement-gateway:8000"),
    "control-plane": os.environ.get("AEGIS_CONTROL_HOST", "control-plane:8000"),
    "credential-broker": os.environ.get("AEGIS_BROKER_HOST", "credential-broker:8000"),
    "protected-tool": os.environ.get("AEGIS_TOOL_HOST", "protected-tool:8000"),
}

EXPECTED = {
    "enforcement-gateway": "ALLOW",
    "control-plane": "DENY",
    "credential-broker": "DENY",
    "protected-tool": "DENY",
}

# Direct container IPs, supplied by the harness from `docker inspect`. Probing
# these bypasses DNS entirely, so a failure here is a routing failure.
# A service may hold several addresses (one per attached network); each value is
# a comma-separated list and EVERY address is probed. A DENY target must be
# unreachable on all of them; an ALLOW target needs only one to succeed.
TARGET_IPS = {
    "enforcement-gateway": os.environ.get("AEGIS_GATEWAY_IP", ""),
    "control-plane": os.environ.get("AEGIS_CONTROL_IP", ""),
    "credential-broker": os.environ.get("AEGIS_BROKER_IP", ""),
    "protected-tool": os.environ.get("AEGIS_TOOL_IP", ""),
}

NETWORK_ERRNOS = {
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    errno.ETIMEDOUT,
    errno.ENETDOWN,
    errno.EACCES,
    errno.EPERM,
}

CONNECT_TIMEOUT = float(os.environ.get("AEGIS_PROBE_TIMEOUT", "4.0"))


def _errno_name(num: int | None) -> str | None:
    if num is None:
        return None
    return errno.errorcode.get(num, f"errno_{num}")


def _split(hostport: str) -> tuple[str, int]:
    host, _, port = hostport.partition(":")
    return host, int(port or "8000")


def _tcp_probe(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> dict:
    """One connect() attempt, recording exactly how it failed."""
    record: dict = {
        "host": host,
        "port": port,
        "connected": False,
        "errno": None,
        "errno_name": None,
        "error": None,
        "dns_error": False,
        "resolved_to": None,
        "elapsed_ms": None,
    }
    started = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        record["resolved_to"] = sorted({info[4][0] for info in infos})
    except socket.gaierror as exc:
        record["dns_error"] = True
        record["error"] = f"getaddrinfo: {exc}"
        record["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        return record
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((record["resolved_to"][0], port))
        record["connected"] = True
    except socket.timeout:
        record["errno"] = errno.ETIMEDOUT
        record["errno_name"] = "ETIMEDOUT"
        record["error"] = "connect timed out"
    except OSError as exc:
        record["errno"] = exc.errno
        record["errno_name"] = _errno_name(exc.errno)
        record["error"] = str(exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    record["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return record


def _classify(tcp: dict, http_status: int | None) -> str:
    if tcp["connected"]:
        if http_status in (401, 403):
            return "APPLICATION_BLOCK"
        return "ALLOW"
    if tcp["dns_error"]:
        return "DNS_BLOCK"
    if tcp["errno"] in NETWORK_ERRNOS:
        return "NETWORK_BLOCK"
    if tcp["errno"] == errno.ECONNREFUSED:
        # Routable. Not a boundary. Never report this as isolation.
        return "PORT_CLOSED"
    return "UNKNOWN_BLOCK"


def _http(hostport: str, path: str, timeout: float = CONNECT_TIMEOUT) -> int | None:
    url = f"http://{hostport}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def _can_import_protected() -> bool:
    try:
        __import__("app.protected.crm")
        return True
    except Exception:
        return False


def _read(path: str, limit: int = 8000) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return None


def _routes() -> list[dict]:
    """Parse /proc/net/route so the evidence shows why a route was absent."""
    raw = _read("/proc/net/route")
    if not raw:
        return []
    rows = []
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue

        def _ip(hexstr: str) -> str:
            value = int(hexstr, 16)
            return ".".join(str((value >> (8 * i)) & 0xFF) for i in range(4))

        rows.append(
            {
                "iface": parts[0],
                "destination": _ip(parts[1]),
                "gateway": _ip(parts[2]),
                "mask": _ip(parts[7]),
            }
        )
    return rows


def _own_addresses() -> list[str]:
    addrs = []
    try:
        for _, name in socket.if_nameindex():
            if name == "lo":
                continue
            addrs.append(name)
    except OSError:
        pass
    found = []
    for probe_target in ("172.16.0.1", "10.0.0.1", "8.8.8.8"):
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.settimeout(0.2)
            udp.connect((probe_target, 9))
            found.append(udp.getsockname()[0])
            udp.close()
        except OSError:
            continue
    return sorted(set(found)) or addrs


def _proc_status_fields() -> dict:
    raw = _read("/proc/self/status") or ""
    keep = {"Uid", "Gid", "CapEff", "CapPrm", "CapBnd", "NoNewPrivs", "Seccomp"}
    out = {}
    for line in raw.splitlines():
        key, _, value = line.partition(":")
        if key in keep:
            out[key] = value.strip()
    return out


def _database_access() -> dict:
    """The database is a SQLite file on a Docker volume, not a network service.

    'Agent -> DB DENY' therefore means: the volume is not mounted into this
    container and the file is not readable. Evidence is the mount table.
    """
    candidates = ["/data/aegis.db", "/data", "/app/aegis.db", "./aegis.db"]
    visible = {}
    for path in candidates:
        try:
            visible[path] = {
                "exists": os.path.exists(path),
                "readable": os.access(path, os.R_OK),
            }
        except OSError as exc:
            visible[path] = {"exists": False, "readable": False, "error": str(exc)}
    mounts = _read("/proc/self/mounts") or ""
    aegis_mounts = [
        line for line in mounts.splitlines() if "aegis" in line or " /data " in line
    ]
    reachable = any(item.get("readable") and item.get("exists") for item in visible.values())
    return {
        "target": "sqlite volume aegis-data",
        "transport": "filesystem (not a network service)",
        "paths": visible,
        "aegis_related_mounts": aegis_mounts,
        "classification": "FILESYSTEM_ALLOW" if reachable else "FILESYSTEM_BLOCK",
        "verdict": "ALLOW" if reachable else "DENY",
        "expected": "DENY",
        "ok": not reachable,
    }


def _probe_target(name: str, hostport: str) -> dict:
    host, port = _split(hostport)
    by_name = _tcp_probe(host, port)
    http_status = _http(hostport, "/api/health") if by_name["connected"] else None
    name_class = _classify(by_name, http_status)

    ips = [item.strip() for item in (TARGET_IPS.get(name) or "").split(",") if item.strip()]
    by_ip: dict[str, dict] = {}
    ip_http = None
    for ip in ips:
        record = _tcp_probe(ip, port)
        status = _http(f"{ip}:{port}", "/api/health") if record["connected"] else None
        if status is not None:
            ip_http = status
        record["http_status"] = status
        record["classification"] = _classify(record, status)
        by_ip[ip] = record

    ip_class = None
    if by_ip:
        classes = {rec["classification"] for rec in by_ip.values()}
        if "ALLOW" in classes:
            ip_class = "ALLOW"
        elif classes == {"NETWORK_BLOCK"}:
            ip_class = "NETWORK_BLOCK"
        elif "APPLICATION_BLOCK" in classes:
            ip_class = "APPLICATION_BLOCK"
        elif "PORT_CLOSED" in classes:
            ip_class = "PORT_CLOSED"
        else:
            ip_class = sorted(classes)[0]

    # The direct-IP probe is authoritative when we have one: it cannot be
    # satisfied by DNS failure alone.
    effective = ip_class or name_class
    verdict = "ALLOW" if effective == "ALLOW" else "DENY"
    expected = EXPECTED[name]

    return {
        "target": hostport,
        "target_ips": ips or None,
        "by_name": {**by_name, "http_status": http_status, "classification": name_class},
        "by_ip": by_ip or None,
        "classification": effective,
        "boundary_level": (
            "NETWORK" if effective in ("NETWORK_BLOCK", "DNS_BLOCK") else
            "APPLICATION" if effective == "APPLICATION_BLOCK" else
            "NONE"
        ),
        # Backwards-compatible fields (Phase 10 consumers read these).
        "reachable": effective == "ALLOW",
        "http_status": ip_http if by_ip else http_status,
        "verdict": verdict,
        "expected": expected,
        "ok": verdict == expected,
    }


def vantage() -> dict:
    return {
        "hostname": socket.gethostname(),
        "container_id_hint": _read("/etc/hostname", 128),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "proc_status": _proc_status_fields(),
        "addresses": _own_addresses(),
        "routes": _routes(),
        "probe_timeout_seconds": CONNECT_TIMEOUT,
    }


def probe() -> dict:
    results = {}
    for name, hostport in TARGETS.items():
        results[name] = _probe_target(name, hostport)
    results["database"] = _database_access()
    import_blocked = not _can_import_protected()
    results["in_process_import"] = {
        "imported": not import_blocked,
        "expected": False,
        "ok": import_blocked,
        "classification": "IMPORT_BLOCK" if import_blocked else "IMPORT_ALLOWED",
    }
    return results


def evidence() -> dict:
    results = probe()
    rows = [row for row in results.values() if "ok" in row]
    network_blocks = [
        name
        for name, row in results.items()
        if row.get("classification") == "NETWORK_BLOCK"
    ]
    application_blocks = [
        name
        for name, row in results.items()
        if row.get("classification") == "APPLICATION_BLOCK"
    ]
    return {
        "schema": "aegis.execution_boundary.evidence/v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "vantage": vantage(),
        "targets": results,
        "summary": {
            "total": len(rows),
            "ok": sum(1 for row in rows if row.get("ok")),
            "failed": sorted(
                name for name, row in results.items() if "ok" in row and not row["ok"]
            ),
            "network_blocks": sorted(network_blocks),
            "application_blocks": sorted(application_blocks),
        },
    }


def main() -> int:
    payload = evidence()
    text = json.dumps(payload, indent=2, sort_keys=True)
    out_path = os.environ.get("AEGIS_PROBE_OUT")
    for index, arg in enumerate(sys.argv):
        if arg == "--out" and index + 1 < len(sys.argv):
            out_path = sys.argv[index + 1]
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as handle:
                handle.write(text)
        except OSError as exc:
            print(f"could not write {out_path}: {exc}", file=sys.stderr)
    print(text)
    failed = payload["summary"]["failed"]
    if os.environ.get("AEGIS_PROBE_STRICT") == "1" and failed:
        return 1
    if "--wait" in sys.argv:
        while True:
            time.sleep(3600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
