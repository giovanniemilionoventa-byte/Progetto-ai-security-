"""Reachability probe run inside the unprivileged agent container."""

from __future__ import annotations

import json
import os
import socket
import sys
import urllib.error
import urllib.request

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


def _tcp(hostport: str, timeout: float = 1.0) -> bool:
    host, _, port = hostport.partition(":")
    try:
        with socket.create_connection((host, int(port or "8000")), timeout=timeout):
            return True
    except OSError:
        return False


def _http(hostport: str, path: str, timeout: float = 1.0) -> int | None:
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


def probe() -> dict:
    results = {}
    for name, hostport in TARGETS.items():
        reachable = _tcp(hostport)
        status = _http(hostport, "/api/health") if reachable else None
        verdict = "ALLOW" if reachable else "DENY"
        results[name] = {
            "target": hostport,
            "reachable": reachable,
            "http_status": status,
            "verdict": verdict,
            "expected": EXPECTED[name],
            "ok": verdict == EXPECTED[name],
        }
    import_ok = not _can_import_protected()
    results["in_process_import"] = {
        "imported": not import_ok,
        "expected": False,
        "ok": import_ok,
    }
    return results


def main() -> int:
    payload = probe()
    print(json.dumps(payload, indent=2))
    failed = [name for name, row in payload.items() if not row.get("ok")]
    if os.environ.get("AEGIS_PROBE_STRICT") == "1" and failed:
        return 1
    if "--wait" in sys.argv:
        import time

        while True:
            time.sleep(3600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
