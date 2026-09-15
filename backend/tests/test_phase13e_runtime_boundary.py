"""Phase 13.E — residual findings inventory. Not L3 proof.

Host pytest and YAML reads are APPLICATION/STATIC only.
Live Agent-namespace connectivity is skipped when Docker is absent.
"""

from pathlib import Path

import pytest

from app.network_policy import NETWORKS, compose_path

COMPOSE_FILE = compose_path()


def _docker_present() -> bool:
    if Path("/var/run/docker.sock").exists():
        return True
    import socket

    try:
        live = socket.create_connection(("127.0.0.1", 2375), timeout=0.2)
        live.close()
        return True
    except OSError:
        return False


def test_yaml_agent_net_internal_is_configuration_not_runtime():
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    assert "internal: true" in text
    assert NETWORKS["agent_net"]["internal"] is True


def test_runtime_agent_namespace_verified_when_stack_is_live():
    """Phase 13.E's residual finding, discharged by Phase 17.

    13.E could only read YAML and record that the Agent namespace had never been
    observed. With a live stack we now observe it directly: the agent container
    holds exactly one network attachment and its route table has no path to the
    protected services.
    """
    from .runtime_boundary import require_live_stack

    evidence = require_live_stack()
    probe = evidence.get("agent_probe") or {}
    vantage = probe.get("vantage") or {}

    # The agent is unprivileged and confined to a single network.
    assert vantage.get("uid") == 10001
    assert vantage.get("proc_status", {}).get("CapEff") == "0000000000000000"
    assert vantage.get("proc_status", {}).get("NoNewPrivs") == "1"

    routes = vantage.get("routes") or []
    assert routes, "agent route table was not captured"
    destinations = {row["destination"] for row in routes}
    assert len(destinations) == 1, f"agent should hold one route, saw {destinations}"

    targets = probe.get("targets") or {}
    for name in ("credential-broker", "protected-tool", "control-plane"):
        assert targets[name]["classification"] == "NETWORK_BLOCK"
        assert targets[name]["ok"] is True
    assert targets["enforcement-gateway"]["classification"] == "ALLOW"
    assert targets["database"]["classification"] == "FILESYSTEM_BLOCK"
    assert targets["in_process_import"]["ok"] is True
