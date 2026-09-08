"""Phase 13.A — Execution Boundary Attack Matrix.

This module ATTACKS and CLASSIFIES the existing boundary. It does not
rewrite architecture. Live Docker L3 probes are executed only when a
daemon is present; otherwise those paths stay NOT_VERIFIED.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.credentials import _INTERNAL_SECRETS
from app.eat import sign_eat
from app.main import create_app
from app.network_policy import (
    MATRIX,
    NETWORKS,
    SERVICES,
    compose_path,
    expected_verdict,
    reachable,
)
from app.seed import DEMO_EMAIL, DEMO_PASSWORD

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = compose_path()

APPLICATION_BLOCK = "APPLICATION_BLOCK"
NETWORK_BLOCK = "NETWORK_BLOCK"
PROCESS_CONTAINER_BLOCK = "PROCESS/CONTAINER_BLOCK"
NOT_VERIFIED = "NOT_VERIFIED"
VULNERABLE = "VULNERABLE"

ATTACK_MATRIX = [
    {
        "id": "A",
        "source": "agent",
        "destination": "enforcement-gateway",
        "expected": "ALLOW",
        "observed": "Compose attaches both to agent_net; L3 not probed",
        "classification": NOT_VERIFIED,
        "app_layer": "ALLOW",
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "B",
        "source": "agent",
        "destination": "credential-broker",
        "expected": "DENY",
        "observed": "No shared Compose network; HTTP 401 if reachable; L3 not probed",
        "classification": NOT_VERIFIED,
        "app_layer": APPLICATION_BLOCK,
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "C",
        "source": "agent",
        "destination": "protected-tool",
        "expected": "DENY",
        "observed": "No shared Compose network; HTTP 401 if reachable; L3 not probed",
        "classification": NOT_VERIFIED,
        "app_layer": APPLICATION_BLOCK,
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "D",
        "source": "agent",
        "destination": "db",
        "expected": "DENY",
        "observed": "No aegis-data volume on agent; runtime mount not probed",
        "classification": NOT_VERIFIED,
        "app_layer": PROCESS_CONTAINER_BLOCK,
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "E",
        "source": "agent",
        "destination": "control-plane",
        "expected": "DENY",
        "observed": "No shared Compose network; HTTP 403 with agent token; L3 not probed",
        "classification": NOT_VERIFIED,
        "app_layer": APPLICATION_BLOCK,
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "F",
        "source": "enforcement-gateway",
        "destination": "credential-broker",
        "expected": "ALLOW",
        "observed": "Shared broker_net; AEGIS_BROKER_URL set; L3 not probed",
        "classification": NOT_VERIFIED,
        "app_layer": "ALLOW",
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "G",
        "source": "enforcement-gateway",
        "destination": "protected-tool",
        "expected": "DENY",
        "observed": "Gateway not on tool_net; AEGIS_TOOL_URL absent; L3 not probed",
        "classification": NOT_VERIFIED,
        "app_layer": PROCESS_CONTAINER_BLOCK,
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "H",
        "source": "credential-broker",
        "destination": "protected-tool",
        "expected": "ALLOW",
        "observed": "Shared tool_net; AEGIS_TOOL_URL set; L3 not probed",
        "classification": NOT_VERIFIED,
        "app_layer": "ALLOW",
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "I",
        "source": "agent",
        "destination": "sensitive-volume",
        "expected": "DENY",
        "observed": "Compose: no aegis-data on agent; runtime mount not probed",
        "classification": NOT_VERIFIED,
        "app_layer": PROCESS_CONTAINER_BLOCK,
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "J",
        "source": "agent",
        "destination": "docker-socket",
        "expected": "DENY",
        "observed": "Compose does not mount docker.sock; runtime not probed",
        "classification": NOT_VERIFIED,
        "app_layer": PROCESS_CONTAINER_BLOCK,
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "K",
        "source": "agent",
        "destination": "host-network",
        "expected": "DENY",
        "observed": "network_mode host absent; runtime not probed",
        "classification": NOT_VERIFIED,
        "app_layer": PROCESS_CONTAINER_BLOCK,
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "L",
        "source": "agent",
        "destination": "docker-dns-internal-hosts",
        "expected": "DENY",
        "observed": "Agent env lists broker/tool/CP hostnames; DNS isolation not probed",
        "classification": NOT_VERIFIED,
        "app_layer": "INFO_LEAK_IN_ENV",
        "security_boundary_proven": False,
        "status": "DECLARED",
    },
    {
        "id": "M",
        "source": "agent",
        "destination": "host-published-ports",
        "expected": "DENY",
        "observed": "CP :8000 and Gateway :8001 published; hairpin not probed",
        "classification": NOT_VERIFIED,
        "app_layer": "CONFIG_RESIDUAL_RISK",
        "security_boundary_proven": False,
        "status": "FINDING",
    },
]


def _parse_compose(text: str) -> dict:
    networks: dict[str, dict] = {}
    services: dict[str, dict] = {}
    volumes: list[str] = []
    section = None
    current_service = None
    current_network = None
    list_key = None
    in_environment = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0 and line.endswith(":"):
            section = line[:-1]
            current_service = None
            current_network = None
            list_key = None
            in_environment = False
            continue
        if section == "volumes" and indent == 2 and line.endswith(":"):
            volumes.append(line[:-1])
            continue
        if section == "networks" and indent == 2 and line.endswith(":"):
            current_network = line[:-1]
            networks[current_network] = {"internal": False, "driver": None}
            continue
        if section == "networks" and current_network and indent >= 4:
            if line.startswith("internal:"):
                networks[current_network]["internal"] = (
                    line.split(":", 1)[1].strip() == "true"
                )
            if line.startswith("driver:"):
                networks[current_network]["driver"] = line.split(":", 1)[1].strip()
            continue
        if section == "services" and indent == 2 and line.endswith(":"):
            current_service = line[:-1]
            services[current_service] = {
                "networks": [],
                "environment": {},
                "volumes": [],
                "ports": [],
                "user": None,
                "privileged": None,
                "cap_drop": [],
                "cap_add": [],
                "security_opt": [],
                "read_only": None,
                "tmpfs": [],
                "network_mode": None,
                "extra_hosts": [],
                "pid": None,
            }
            list_key = None
            in_environment = False
            continue
        if not current_service:
            continue
        svc = services[current_service]
        if indent == 4 and line.endswith(":") and not line.startswith("-"):
            key = line[:-1]
            list_key = (
                key
                if key
                in {
                    "networks",
                    "volumes",
                    "ports",
                    "cap_drop",
                    "cap_add",
                    "security_opt",
                    "tmpfs",
                    "extra_hosts",
                }
                else None
            )
            in_environment = key == "environment"
            continue
        if indent == 4 and ":" in line and not line.startswith("-"):
            key, value = line.split(":", 1)
            value = value.strip().strip('"')
            if key in {
                "user",
                "privileged",
                "read_only",
                "network_mode",
                "pid",
            }:
                svc[key] = value
            list_key = None
            in_environment = False
            continue
        if list_key and indent >= 6 and line.startswith("- "):
            svc[list_key].append(line[2:].strip().strip('"'))
            continue
        if in_environment and indent >= 6 and ":" in line:
            key, value = line.split(":", 1)
            svc["environment"][key.strip()] = value.strip().strip('"').strip("'")
    return {"networks": networks, "services": services, "volumes": volumes}


def _docker_daemon_present() -> bool:
    sock = Path("/var/run/docker.sock")
    if sock.exists():
        return True
    try:
        live = socket.create_connection(("127.0.0.1", 2375), timeout=0.2)
        live.close()
        return True
    except OSError:
        return False


def _eat(**overrides) -> str:
    kwargs = dict(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-1",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={},
    )
    kwargs.update(overrides)
    return sign_eat(**kwargs)


@pytest.fixture(scope="module")
def compose():
    assert COMPOSE_FILE.exists()
    return _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def compose_text():
    return COMPOSE_FILE.read_text(encoding="utf-8")


def _login(client: TestClient) -> str:
    res = client.post(
        "/api/auth/login", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
    )
    assert res.status_code == 200
    return res.json()["access_token"]


def _sales_token(client: TestClient) -> str:
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    agents = client.get("/api/agents", headers=headers).json()
    sales = next(a for a in agents if a["name"] == "Sales Copilot")
    rotated = client.post(f"/api/agents/{sales['id']}/rotate", headers=headers)
    assert rotated.status_code == 200
    return rotated.json()["token"]


def test_attack_matrix_covers_required_paths():
    ids = {row["id"] for row in ATTACK_MATRIX}
    assert ids == set("ABCDEFGHIJKLM")
    deny_ids = {row["id"] for row in ATTACK_MATRIX if row["expected"] == "DENY"}
    assert {"B", "C", "D", "E", "G", "I", "J", "K", "L", "M"} <= deny_ids
    allow_ids = {row["id"] for row in ATTACK_MATRIX if row["expected"] == "ALLOW"}
    assert allow_ids == {"A", "F", "H"}


def test_no_row_claims_network_block_without_runtime_probe():
    for row in ATTACK_MATRIX:
        assert row["classification"] != NETWORK_BLOCK
        assert row["security_boundary_proven"] is False
        assert row["classification"] in {
            NOT_VERIFIED,
            APPLICATION_BLOCK,
            PROCESS_CONTAINER_BLOCK,
            VULNERABLE,
        }


def test_declared_compose_matrix_still_matches_policy():
    for (src, dst), verdict in MATRIX.items():
        got = "ALLOW" if reachable(src, dst) else "DENY"
        assert got == verdict
        assert expected_verdict(src, dst) == verdict


def test_observed_topology_matches_compose(compose):
    assert set(compose["networks"]) == set(NETWORKS)
    assert compose["networks"]["broker_net"]["internal"] is True
    assert compose["networks"]["tool_net"]["internal"] is True
    assert compose["networks"]["agent_net"]["internal"] is True
    assert compose["networks"]["public_net"]["internal"] is False
    for service, nets in SERVICES.items():
        assert set(compose["services"][service]["networks"]) == nets


def test_published_ports_and_internal_services(compose):
    assert compose["services"]["control-plane"]["ports"] == ["8000:8000"]
    assert compose["services"]["enforcement-gateway"]["ports"] == ["8001:8000"]
    assert compose["services"]["credential-broker"]["ports"] == []
    assert compose["services"]["protected-tool"]["ports"] == []
    assert compose["services"]["agent"]["ports"] == []


def test_internal_urls_are_role_scoped(compose):
    gw = compose["services"]["enforcement-gateway"]["environment"]
    broker = compose["services"]["credential-broker"]["environment"]
    tool = compose["services"]["protected-tool"]["environment"]
    agent = compose["services"]["agent"]["environment"]
    assert gw["AEGIS_BROKER_URL"] == "http://credential-broker:8000/api"
    assert "AEGIS_TOOL_URL" not in gw
    assert broker["AEGIS_TOOL_URL"] == "http://protected-tool:8000/api"
    assert "AEGIS_BROKER_URL" not in tool
    assert agent["AEGIS_BASE_URL"] == "http://enforcement-gateway:8000"
    assert agent["AEGIS_GATEWAY_HOST"] == "enforcement-gateway:8000"
    assert agent["AEGIS_CONTROL_HOST"] == "control-plane:8000"
    assert agent["AEGIS_BROKER_HOST"] == "credential-broker:8000"
    assert agent["AEGIS_TOOL_HOST"] == "protected-tool:8000"


def test_agent_to_gateway_application_path_allow():
    with TestClient(create_app("enforcement-gateway")) as client:
        paths = {getattr(route, "path", "") for route in client.app.routes}
        assert "/api/authorize" in paths
        assert "/api/gateway/tools/{tool}/{operation}" in paths
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["layer"] == "enforcement-gateway"


def test_agent_to_broker_is_application_block_not_network():
    with TestClient(create_app("credential-broker")) as client:
        eat = _eat()
        body = {
            "eat": eat,
            "tool": "crm",
            "operation": "read",
            "scope": "customers",
            "payload": {},
            "org_id": "org-1",
            "agent_id": "agent-1",
            "execution_id": "exec-1",
            "request_id": "req-1",
        }
        missing = client.post("/api/internal/broker/execute", json=body)
        assert missing.status_code == 401
        agent_header = client.post(
            "/api/internal/broker/execute",
            headers={"X-Agent-Token": "aegis_forged"},
            json=body,
        )
        assert agent_header.status_code == 401
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["layer"] == "credential-broker"
        assert _INTERNAL_SECRETS["crm"] not in missing.text
    row = next(r for r in ATTACK_MATRIX if r["id"] == "B")
    assert row["app_layer"] == APPLICATION_BLOCK
    assert row["classification"] != NETWORK_BLOCK


def test_agent_to_tool_is_application_block_not_network():
    with TestClient(create_app("protected-tool")) as client:
        res = client.post(
            "/api/internal/tools/crm/read",
            json={"secret": "guess", "scope": "customers"},
        )
        assert res.status_code == 401
        with_agent = client.post(
            "/api/internal/tools/crm/read",
            headers={"X-Agent-Token": "aegis_forged"},
            json={"secret": "guess", "scope": "customers"},
        )
        assert with_agent.status_code == 401
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["layer"] == "protected-tool"
    row = next(r for r in ATTACK_MATRIX if r["id"] == "C")
    assert row["app_layer"] == APPLICATION_BLOCK
    assert row["classification"] != NETWORK_BLOCK


def test_agent_to_control_plane_is_application_block_not_network():
    with TestClient(create_app("all")) as client:
        token = _sales_token(client)
        forbidden = client.get("/api/agents", headers={"X-Agent-Token": token})
        assert forbidden.status_code == 403
        assert "control plane" in forbidden.json()["detail"].lower()
        health = client.get("/api/health")
        assert health.status_code == 200
    with TestClient(create_app("control-plane")) as cp:
        paths = {getattr(route, "path", "") for route in cp.app.routes}
        assert "/api/authorize" not in paths
        assert "/api/gateway/tools/{tool}/{operation}" not in paths
        assert "/api/internal/broker/execute" not in paths
        assert "/api/agents" in paths
        denied = cp.get("/api/agents", headers={"X-Agent-Token": "aegis_forged"})
        assert denied.status_code == 403
    row = next(r for r in ATTACK_MATRIX if r["id"] == "E")
    assert row["app_layer"] == APPLICATION_BLOCK
    assert row["classification"] != NETWORK_BLOCK


def test_403_is_not_proof_of_execution_boundary():
    row_e = next(r for r in ATTACK_MATRIX if r["id"] == "E")
    row_b = next(r for r in ATTACK_MATRIX if r["id"] == "B")
    assert row_e["security_boundary_proven"] is False
    assert row_b["security_boundary_proven"] is False
    assert row_e["classification"] == NOT_VERIFIED
    assert row_b["classification"] == NOT_VERIFIED


def test_gateway_cannot_call_tool_url_in_compose(compose):
    env = compose["services"]["enforcement-gateway"]["environment"]
    assert "AEGIS_TOOL_URL" not in env
    assert "tool_net" not in compose["services"]["enforcement-gateway"]["networks"]
    assert reachable("enforcement-gateway", "protected-tool") is False


def test_broker_has_no_db_volume(compose):
    assert not any(
        "aegis-data" in item
        for item in compose["services"]["credential-broker"]["volumes"]
    )
    assert reachable("credential-broker", "db") is False


def test_agent_has_no_db_or_backend_volume(compose):
    agent = compose["services"]["agent"]
    assert agent["volumes"] == []
    assert reachable("agent", "db") is False
    dockerfile = (ROOT / "infra" / "agent" / "Dockerfile").read_text(encoding="utf-8")
    assert "backend/app" not in dockerfile
    assert "USER 10001" in dockerfile


def test_side_channel_compose_contract(compose, compose_text):
    agent = compose["services"]["agent"]
    assert agent["user"] in {"10001:10001", "10001"}
    assert agent["privileged"] == "false"
    assert "ALL" in agent["cap_drop"]
    assert agent["cap_add"] == []
    assert any("no-new-privileges" in opt for opt in agent["security_opt"])
    assert agent["read_only"] == "true"
    assert "/tmp" in agent["tmpfs"]
    assert agent["network_mode"] is None
    assert agent["extra_hosts"] == []
    assert agent["pid"] is None
    assert "network_mode: host" not in compose_text
    assert "docker.sock" not in compose_text
    assert "cap_add" not in compose_text
    assert "privileged: true" not in compose_text
    joined = " ".join(f"{k}={v}" for k, v in agent["environment"].items()).lower()
    assert "crm_secret" not in joined
    assert "eat_key" not in joined
    assert "internal_" not in joined
    assert "database" not in joined
    assert "sqlite" not in joined
    assert "secret_key" not in joined


def test_finding_host_published_ports_may_bypass_l3_intent(compose):
    """Documented residual risk. Not remediated in Phase 13.A."""
    cp_ports = compose["services"]["control-plane"]["ports"]
    gw_ports = compose["services"]["enforcement-gateway"]["ports"]
    assert any(p == "8000:8000" or p.endswith(":8000") for p in cp_ports)
    assert any(p == "8001:8000" or p.startswith("8001:") for p in gw_ports)
    unbound = [p for p in cp_ports + gw_ports if not p.startswith("127.0.0.1:")]
    assert unbound, "expected host-wide publish as current residual risk"
    row = next(r for r in ATTACK_MATRIX if r["id"] == "M")
    assert row["status"] == "FINDING"
    assert row["classification"] == NOT_VERIFIED


def test_finding_shared_sqlite_volume_between_cp_and_gateway(compose):
    cp_vols = compose["services"]["control-plane"]["volumes"]
    gw_vols = compose["services"]["enforcement-gateway"]["volumes"]
    assert any("aegis-data" in item for item in cp_vols)
    assert any("aegis-data" in item for item in gw_vols)
    assert reachable("enforcement-gateway", "db") is True
    assert reachable("control-plane", "db") is True


def test_finding_agent_env_names_internal_hosts(compose):
    env = compose["services"]["agent"]["environment"]
    assert "credential-broker" in env["AEGIS_BROKER_HOST"]
    assert "protected-tool" in env["AEGIS_TOOL_HOST"]
    assert "control-plane" in env["AEGIS_CONTROL_HOST"]
    row = next(r for r in ATTACK_MATRIX if r["id"] == "L")
    assert row["app_layer"] == "INFO_LEAK_IN_ENV"


def test_finding_agent_net_is_not_internal(compose):
    """Phase 13.C remediates F-13A-05: agent_net is internal."""
    assert compose["networks"]["agent_net"]["internal"] is True


def test_unauthenticated_health_on_internal_roles():
    for role in ("credential-broker", "protected-tool", "enforcement-gateway"):
        with TestClient(create_app(role)) as client:
            res = client.get("/api/health")
            assert res.status_code == 200
            assert res.json()["product"] == "aegis"


def test_monolith_does_not_expose_broker_or_tool_routes():
    with TestClient(create_app("all")) as client:
        paths = {getattr(route, "path", "") for route in client.app.routes}
        assert "/api/internal/broker/execute" not in paths
        assert "/api/internal/tools/{tool}/{operation}" not in paths
        token = _sales_token(client)
        missing_broker = client.post(
            "/api/internal/broker/execute",
            headers={"X-Agent-Token": token},
            json={},
        )
        assert missing_broker.status_code in {403, 404}
        missing_tool = client.post(
            "/api/internal/tools/crm/read",
            headers={"X-Agent-Token": token},
            json={"secret": "x", "scope": "customers"},
        )
        assert missing_tool.status_code in {403, 404}


def _tcp_open(host: str, port: int) -> bool:
    sock = socket.socket()
    sock.settimeout(0.3)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def test_live_runtime_probe_records_environment_limitation():
    """Observational. A closed port here is ENVIRONMENT LIMITATION, not PASS."""
    listeners = {
        "127.0.0.1:8000": _tcp_open("127.0.0.1", 8000),
        "127.0.0.1:8001": _tcp_open("127.0.0.1", 8001),
        "127.0.0.1:2375": _tcp_open("127.0.0.1", 2375),
        "docker.sock": Path("/var/run/docker.sock").exists(),
    }
    dns = {}
    for name in (
        "enforcement-gateway",
        "credential-broker",
        "protected-tool",
        "control-plane",
    ):
        try:
            socket.getaddrinfo(name, 8000)
            dns[name] = True
        except socket.gaierror:
            dns[name] = False
    if not any(listeners.values()) and not any(dns.values()):
        pytest.skip(
            "No Aegis runtime or Docker DNS in this environment; "
            "Execution Boundary: NOT VERIFIED at L3/runtime level."
        )


def test_l3_runtime_isolation_not_verified_without_docker():
    if _docker_daemon_present():
        pytest.fail(
            "Docker daemon present but Phase 13.A live namespace probe "
            "was not implemented in this environment path; do not claim NETWORK_BLOCK"
        )
    assert not Path("/var/run/docker.sock").exists()
    pytest.skip("Execution Boundary: NOT VERIFIED at L3/runtime level.")


def test_attack_matrix_json_is_stable():
    payload = json.dumps(ATTACK_MATRIX, sort_keys=True)
    assert "NETWORK_BLOCK" not in payload
    assert payload.count(NOT_VERIFIED) >= 10
