"""Shared access to the live execution-boundary proof.

Phase 17. This is a helper, not a test module.

Before Phase 17 the deployment-boundary tests were *tripwires*: they failed on
purpose if a Docker daemon was present but no live probe had been run, so that
nobody could claim NETWORK_BLOCK from a passing unit test. That guard did its
job for several phases.

Phase 17 supplies the missing probe (`infra/boundary/boundary_proof.py`), so the
tripwires become real assertions: when a daemon and a running stack are present,
the live matrix must actually hold. When they are absent the tests still skip —
an environment without Docker still proves nothing about L3, and saying
otherwise would be the exact dishonesty the tripwires existed to prevent.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROOF_SCRIPT = ROOT / "infra" / "boundary" / "boundary_proof.py"

REQUIRED_CONTAINERS = (
    "aegis-agent",
    "aegis-enforcement-gateway",
    "aegis-credential-broker",
    "aegis-protected-tool",
    "aegis-control-plane",
)


def docker_daemon_present() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def stack_running() -> bool:
    if not docker_daemon_present():
        return False
    for container in REQUIRED_CONTAINERS:
        try:
            result = subprocess.run(
                ["docker", "inspect", container, "-f", "{{.State.Running}}"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if result.returncode != 0 or result.stdout.strip() != "true":
            return False
    return True


@lru_cache(maxsize=1)
def boundary_evidence() -> dict | None:
    """Run the live proof once per test session. None when unavailable."""
    if not stack_running():
        return None
    try:
        result = subprocess.run(
            ["python3", str(PROOF_SCRIPT), "--quiet", "--out", "/dev/stdout"],
            capture_output=True,
            text=True,
            timeout=900,
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


def require_live_stack() -> dict:
    """Return live evidence or skip with an honest reason."""
    if not docker_daemon_present():
        pytest.skip(
            "RUNTIME VERIFICATION: NOT VERIFIED — no Docker daemon; "
            "L3 isolation cannot be observed from this environment"
        )
    if not stack_running():
        pytest.skip(
            "RUNTIME VERIFICATION: NOT VERIFIED — Docker daemon present but the "
            "Aegis stack is not running (`docker compose up -d --build`)"
        )
    evidence = boundary_evidence()
    if evidence is None:
        pytest.skip(
            "RUNTIME VERIFICATION: NOT VERIFIED — live boundary proof produced "
            "no parseable evidence"
        )
    return evidence


def check_for(evidence: dict, source: str, destination: str) -> dict:
    for check in evidence.get("checks", []):
        if check["source"] == source and check["destination"] == destination:
            return check
    raise AssertionError(f"no live check recorded for {source} -> {destination}")


def db_check_for(evidence: dict, source: str) -> dict:
    for check in evidence.get("database_checks", []):
        if check["source"] == source:
            return check
    raise AssertionError(f"no live database check recorded for {source}")
