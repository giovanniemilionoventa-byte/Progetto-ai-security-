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


def test_runtime_agent_namespace_not_verified_without_docker():
    if _docker_present():
        pytest.fail(
            "Docker present but Phase 13.E did not run live Agent-namespace "
            "probes in this path; do not mark L3 VERIFIED from pytest"
        )
    pytest.skip(
        "RUNTIME VERIFICATION: NOT VERIFIED — Docker daemon absent; "
        "Agent container not running"
    )
