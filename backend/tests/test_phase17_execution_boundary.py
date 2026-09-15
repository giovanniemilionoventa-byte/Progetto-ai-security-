"""Phase 17 — execution boundary, proven against the live Docker runtime.

Every assertion here is backed by an observation made from inside a running
container, not by reading docker-compose.yml. The whole file skips when no
daemon or no running stack is available, because an environment that cannot
observe L3 proves nothing about L3.

Run the stack first:
    docker compose up -d --build
"""

from __future__ import annotations

import pytest

from .runtime_boundary import (
    check_for,
    db_check_for,
    require_live_stack,
)

AGENT = "aegis-agent"
GATEWAY = "aegis-enforcement-gateway"
BROKER = "aegis-credential-broker"
TOOL = "aegis-protected-tool"
CONTROL = "aegis-control-plane"


@pytest.fixture(scope="module")
def evidence() -> dict:
    return require_live_stack()


def test_proof_status_is_verified(evidence):
    assert evidence["status"] == "VERIFIED", evidence.get("summary")
    assert evidence["summary"]["failed"] == []


# ---------------------------------------------------------------------------
# The agent's boundary: one door in, everything else refused by the kernel
# ---------------------------------------------------------------------------


def test_agent_to_gateway_is_allowed(evidence):
    check = check_for(evidence, AGENT, GATEWAY)
    assert check["observed"] == "ALLOW"


@pytest.mark.parametrize("destination", [BROKER, TOOL, CONTROL])
def test_agent_cannot_reach_protected_services(evidence, destination):
    check = check_for(evidence, AGENT, destination)
    assert check["observed"] == "DENY"
    assert check["classification"] == "NETWORK_BLOCK"
    assert check["boundary_level"] == "NETWORK"


@pytest.mark.parametrize("destination", [BROKER, TOOL, CONTROL])
def test_agent_denials_are_route_failures_on_every_address(evidence, destination):
    """A DENY must hold for every address the destination owns, and must be a
    routing failure — not a connection refused, which would mean the host was
    reachable and merely had nothing listening."""
    check = check_for(evidence, AGENT, destination)
    assert check["by_ip"], "no direct-IP probe recorded"
    for label, record in check["by_ip"].items():
        assert record["connected"] is False, f"{label} was reachable"
        assert record["classification"] == "NETWORK_BLOCK", (
            f"{label} classified {record['classification']} "
            f"(errno={record.get('errno_name')})"
        )
        assert record.get("errno_name") in {
            "ENETUNREACH",
            "EHOSTUNREACH",
            "ETIMEDOUT",
        }, f"{label} failed with {record.get('errno_name')}, not a routing error"


def test_agent_name_resolution_also_fails_for_denied_services(evidence):
    """Defence in depth: the protected service names do not even resolve from
    the agent, because Docker's embedded DNS only answers for shared networks."""
    for destination in (BROKER, TOOL, CONTROL):
        check = check_for(evidence, AGENT, destination)
        assert check["by_name"]["classification"] in {"DNS_BLOCK", "NETWORK_BLOCK"}


# ---------------------------------------------------------------------------
# Legitimate internal paths
# ---------------------------------------------------------------------------


def test_gateway_reaches_broker(evidence):
    assert check_for(evidence, GATEWAY, BROKER)["observed"] == "ALLOW"


def test_broker_reaches_tool(evidence):
    assert check_for(evidence, BROKER, TOOL)["observed"] == "ALLOW"


def test_gateway_cannot_reach_tool_directly(evidence):
    """The gateway must not be able to skip the broker. This is what makes
    credential isolation structural rather than a matter of code discipline."""
    check = check_for(evidence, GATEWAY, TOOL)
    assert check["observed"] == "DENY"
    assert check["classification"] == "NETWORK_BLOCK"


def test_broker_cannot_reach_control_plane(evidence):
    check = check_for(evidence, BROKER, CONTROL)
    assert check["observed"] == "DENY"
    assert check["classification"] == "NETWORK_BLOCK"


# ---------------------------------------------------------------------------
# Database reachability is a filesystem question, not a network one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("container", [AGENT, BROKER, TOOL])
def test_database_volume_not_mounted(evidence, container):
    check = db_check_for(evidence, container)
    assert check["observed"] == "DENY"
    assert check["evidence"]["classification"] == "FILESYSTEM_BLOCK"
    assert check["evidence"]["aegis_related_mounts"] == []


def test_control_plane_owns_the_database(evidence):
    check = db_check_for(evidence, CONTROL)
    assert check["observed"] == "ALLOW"


def test_gateway_shares_database_known_limitation(evidence):
    """Documented Phase 10 limitation, asserted so it cannot regress silently.

    Control plane and gateway share one SQLite volume, so there is no SQL-level
    privilege separation between them. This is a real limitation and is recorded
    as such; the test exists to make any change to it visible.
    """
    check = db_check_for(evidence, GATEWAY)
    assert check["observed"] == "ALLOW"


# ---------------------------------------------------------------------------
# Container hardening, observed rather than declared
# ---------------------------------------------------------------------------


def test_agent_runs_unprivileged_with_no_capabilities(evidence):
    vantage = evidence["agent_probe"]["vantage"]
    assert vantage["uid"] == 10001
    assert vantage["gid"] == 10001
    assert vantage["proc_status"]["CapEff"] == "0000000000000000"
    assert vantage["proc_status"]["NoNewPrivs"] == "1"


def test_agent_has_exactly_one_network_attachment(evidence):
    check = check_for(evidence, AGENT, GATEWAY)
    assert len(check["source_networks"]) == 1, check["source_networks"]
    assert "aegis_agent_net" in check["source_networks"]


def test_agent_cannot_import_protected_tool_code(evidence):
    assert evidence["agent_probe"]["targets"]["in_process_import"]["ok"] is True
    assert evidence["agent_probe"]["targets"]["in_process_import"]["imported"] is False


def test_no_deny_path_relies_on_application_code(evidence):
    """The headline claim of this phase, stated as a single assertion."""
    assert evidence["summary"]["application_level_only"] == []
    assert len(evidence["summary"]["network_level_blocks"]) >= 5


# ---------------------------------------------------------------------------
# Host exposure
# ---------------------------------------------------------------------------


def test_only_control_plane_is_published_to_the_host(evidence):
    """The enforcement gateway declares `8001:8000` in compose, but it is
    attached only to internal networks, so Docker never realises the binding.
    The gateway is therefore unreachable from the host. That is the desired
    posture; this test records it so a future change to the networks cannot
    quietly expose the gateway.
    """
    published = evidence["host_published_ports"]
    assert published[CONTROL], "control plane should be reachable from the host"
    for container in (GATEWAY, BROKER, TOOL, AGENT):
        assert published.get(container) == [], (
            f"{container} unexpectedly publishes a host port: "
            f"{published.get(container)}"
        )
