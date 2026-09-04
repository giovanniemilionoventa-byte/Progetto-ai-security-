import ast
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import config
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
from app.protected.crm import protected_crm
from app.seed import DEMO_EMAIL, DEMO_PASSWORD

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = compose_path()


def _parse_compose(text: str) -> dict:
    networks: dict[str, dict] = {}
    services: dict[str, dict] = {}
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
        if section == "networks" and indent == 2 and line.endswith(":"):
            current_network = line[:-1]
            networks[current_network] = {"internal": False}
            continue
        if section == "networks" and current_network and indent >= 4:
            if line.startswith("internal:"):
                networks[current_network]["internal"] = (
                    line.split(":", 1)[1].strip() == "true"
                )
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
                "security_opt": [],
                "read_only": None,
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
                if key in {"networks", "volumes", "ports", "cap_drop", "security_opt"}
                else None
            )
            in_environment = key == "environment"
            continue
        if indent == 4 and ":" in line and not line.startswith("-"):
            key, value = line.split(":", 1)
            value = value.strip().strip('"')
            if key == "user":
                svc["user"] = value
            elif key == "privileged":
                svc["privileged"] = value
            elif key == "read_only":
                svc["read_only"] = value
            list_key = None
            in_environment = False
            continue
        if list_key and indent >= 6 and line.startswith("- "):
            svc[list_key].append(line[2:].strip().strip('"'))
            continue
        if in_environment and indent >= 6 and ":" in line:
            key, value = line.split(":", 1)
            svc["environment"][key.strip()] = value.strip().strip('"').strip("'")
    return {"networks": networks, "services": services}


@pytest.fixture(scope="module")
def compose():
    assert COMPOSE_FILE.exists()
    return _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def monolith():
    with TestClient(create_app("all")) as client:
        yield client


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


def test_network_matrix_matches_shared_networks():
    for (src, dst), verdict in MATRIX.items():
        got = "ALLOW" if reachable(src, dst) else "DENY"
        assert got == verdict, f"{src}->{dst} expected {verdict} got {got}"
        assert expected_verdict(src, dst) == verdict


def test_compose_declares_required_networks(compose):
    for name, spec in NETWORKS.items():
        assert name in compose["networks"], name
        assert compose["networks"][name]["internal"] is spec["internal"]


def test_compose_service_network_attachments(compose):
    for service, nets in SERVICES.items():
        assert service in compose["services"], service
        attached = set(compose["services"][service]["networks"])
        assert attached == nets, f"{service}: {attached} != {nets}"


def test_gateway_not_on_tool_network(compose):
    attached = set(compose["services"]["enforcement-gateway"]["networks"])
    assert "tool_net" not in attached
    assert "broker_net" in attached
    assert "tool_net" in compose["services"]["credential-broker"]["networks"]
    assert "tool_net" in compose["services"]["protected-tool"]["networks"]


def test_agent_cannot_share_db_volume(compose):
    assert not any("aegis-data" in v for v in compose["services"]["agent"]["volumes"])
    assert not any(
        "aegis-data" in v for v in compose["services"]["credential-broker"]["volumes"]
    )
    assert not any(
        "aegis-data" in v for v in compose["services"]["protected-tool"]["volumes"]
    )
    assert any("aegis-data" in v for v in compose["services"]["control-plane"]["volumes"])
    assert any(
        "aegis-data" in v for v in compose["services"]["enforcement-gateway"]["volumes"]
    )


def test_agent_container_is_unprivileged(compose):
    agent = compose["services"]["agent"]
    assert agent["user"] in {"10001:10001", "10001"}
    assert agent["privileged"] == "false"
    assert "ALL" in agent["cap_drop"]
    assert any("no-new-privileges" in opt for opt in agent["security_opt"])
    assert agent["read_only"] == "true"
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    assert "network_mode: host" not in text
    assert "docker.sock" not in text
    assert "NET_ADMIN" not in text
    assert "cap_add" not in text


def test_agent_environment_has_no_secrets(compose):
    env = compose["services"]["agent"]["environment"]
    joined = " ".join(f"{k}={v}" for k, v in env.items()).lower()
    assert "crm_secret" not in joined
    assert "eat_key" not in joined
    assert "internal_" not in joined
    assert "database" not in joined
    assert "sqlite" not in joined


def test_broker_and_tool_are_internal_only(compose):
    assert compose["services"]["credential-broker"]["ports"] == []
    assert compose["services"]["protected-tool"]["ports"] == []
    assert compose["networks"]["broker_net"]["internal"] is True
    assert compose["networks"]["tool_net"]["internal"] is True


def test_compose_gateway_has_no_tool_url(compose):
    env = compose["services"]["enforcement-gateway"]["environment"]
    assert "AEGIS_TOOL_URL" not in env
    assert "credential-broker" in env.get("AEGIS_BROKER_URL", "")
    assert env.get("AEGIS_ROLE") == "enforcement-gateway"
    assert "AEGIS_CRM_SECRET" not in env


def test_role_split_control_plane_hides_enforcement():
    with TestClient(create_app("control-plane")) as client:
        paths = {getattr(route, "path", "") for route in client.app.routes}
        assert "/api/agents" in paths
        assert "/api/gateway/tools/{tool}/{operation}" not in paths
        assert "/api/authorize" not in paths
        assert "/api/internal/broker/execute" not in paths


def test_role_split_gateway_hides_control_and_tool():
    with TestClient(create_app("enforcement-gateway")) as client:
        paths = {getattr(route, "path", "") for route in client.app.routes}
        assert "/api/authorize" in paths
        assert "/api/gateway/tools/{tool}/{operation}" in paths
        assert "/api/agents" not in paths
        assert "/api/internal/tools/{tool}/{operation}" not in paths
        assert "/api/internal/broker/execute" not in paths
        health = client.get("/api/health").json()
        assert health["layer"] == "enforcement-gateway"


def test_role_split_broker_and_tool_have_no_agent_api():
    with TestClient(create_app("credential-broker")) as broker_client:
        paths = {getattr(route, "path", "") for route in broker_client.app.routes}
        assert "/api/internal/broker/execute" in paths
        assert "/api/authorize" not in paths
        assert "/api/gateway/tools/{tool}/{operation}" not in paths
    with TestClient(create_app("protected-tool")) as tool_client:
        paths = {getattr(route, "path", "") for route in tool_client.app.routes}
        assert "/api/internal/tools/{tool}/{operation}" in paths
        assert "/api/authorize" not in paths
        assert "/api/agents" not in paths


def test_monolith_does_not_expose_internal_routes(monolith):
    paths = {getattr(route, "path", "") for route in monolith.app.routes}
    assert "/api/internal/broker/execute" not in paths
    assert "/api/internal/tools/{tool}/{operation}" not in paths


def test_broker_rejects_missing_internal_token(monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")
    with TestClient(create_app("credential-broker")) as client:
        eat = _eat()
        missing = client.post(
            "/api/internal/broker/execute",
            json={
                "eat": eat,
                "tool": "crm",
                "operation": "read",
                "scope": "customers",
                "payload": {},
                "org_id": "org-1",
                "agent_id": "agent-1",
                "execution_id": "exec-1",
                "request_id": "req-1",
            },
        )
        assert missing.status_code == 401
        assert _INTERNAL_SECRETS["crm"] not in missing.text


def test_broker_rejects_invalid_eat_and_does_not_call_tool(monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")
    protected_crm.reset()
    before = protected_crm.call_count
    with TestClient(create_app("credential-broker")) as client:
        res = client.post(
            "/api/internal/broker/execute",
            headers={"X-Internal-Token": "gw-token"},
            json={
                "eat": "not-an-eat",
                "tool": "crm",
                "operation": "read",
                "scope": "customers",
                "payload": {},
                "org_id": "org-1",
                "agent_id": "agent-1",
                "execution_id": "exec-1",
                "request_id": "req-1",
            },
        )
        assert res.status_code == 401
        assert res.json()["detail"] == "eat_rejected"
        assert protected_crm.call_count == before
        assert _INTERNAL_SECRETS["crm"] not in res.text


@pytest.mark.parametrize(
    "mutate",
    [
        {"tool": "email"},
        {"operation": "delete"},
        {"org_id": "other-org"},
        {"agent_id": "other-agent"},
        {"execution_id": "other-exec"},
        {"scope": "all"},
        {"payload": {"x": 1}},
    ],
)
def test_broker_rejects_claim_mismatch(monkeypatch, mutate):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")
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
    body.update(mutate)
    with TestClient(create_app("credential-broker")) as client:
        res = client.post(
            "/api/internal/broker/execute",
            headers={"X-Internal-Token": "gw-token"},
            json=body,
        )
        assert res.status_code == 401
        assert res.json()["detail"] == "eat_rejected"
        assert _INTERNAL_SECRETS["crm"] not in res.text


def test_broker_executes_with_valid_eat_and_hides_secret(monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")
    monkeypatch.setattr(config, "TOOL_URL", "")
    protected_crm.reset()
    eat = _eat(jti="unique-valid-eat")
    with TestClient(create_app("credential-broker")) as client:
        res = client.post(
            "/api/internal/broker/execute",
            headers={"X-Internal-Token": "gw-token"},
            json={
                "eat": eat,
                "tool": "crm",
                "operation": "read",
                "scope": "customers",
                "payload": {},
                "org_id": "org-1",
                "agent_id": "agent-1",
                "execution_id": "exec-1",
                "request_id": "req-1",
            },
        )
        assert res.status_code == 200
        assert res.json()["ok"] is True
        assert "secret" not in res.json()
        assert _INTERNAL_SECRETS["crm"] not in res.text
        replay = client.post(
            "/api/internal/broker/execute",
            headers={"X-Internal-Token": "gw-token"},
            json={
                "eat": eat,
                "tool": "crm",
                "operation": "read",
                "scope": "customers",
                "payload": {},
                "org_id": "org-1",
                "agent_id": "agent-1",
                "execution_id": "exec-1",
                "request_id": "req-1",
            },
        )
        assert replay.status_code == 401


def test_gateway_secret_not_in_response_or_events(monolith):
    token = _sales_token(monolith)
    secret = _INTERNAL_SECRETS["crm"]
    res = monolith.post(
        "/api/gateway/tools/crm/read",
        headers={"X-Agent-Token": token},
        json={"scope": "customers"},
    )
    assert res.status_code == 200
    assert secret not in res.text
    assert res.json()["executed"] is True
    headers = {"Authorization": f"Bearer {_login(monolith)}"}
    events = monolith.get("/api/events", headers=headers).json()
    blob = str(events).lower()
    assert secret.lower() not in blob


def test_gateway_still_fail_closed_on_block(monolith):
    token = _sales_token(monolith)
    before = protected_crm.call_count
    blocked = monolith.post(
        "/api/gateway/tools/crm/delete",
        headers={"X-Agent-Token": token},
        json={"scope": "all"},
    )
    assert blocked.status_code == 200
    assert blocked.json()["decision"] == "BLOCK"
    assert blocked.json()["executed"] is False
    assert protected_crm.call_count == before


def test_tampered_agent_token_rejected_on_gateway(monolith):
    token = _sales_token(monolith)
    res = monolith.post(
        "/api/gateway/tools/crm/read",
        headers={"X-Agent-Token": token + "x"},
        json={"scope": "customers"},
    )
    assert res.status_code == 401
    assert _INTERNAL_SECRETS["crm"] not in res.text


def test_agent_image_has_no_backend_or_secret():
    dockerfile = (ROOT / "infra" / "agent" / "Dockerfile").read_text(encoding="utf-8")
    assert "USER 10001" in dockerfile
    assert "backend/app" not in dockerfile
    probe = (ROOT / "infra" / "agent" / "probe.py").read_text(encoding="utf-8")
    tree = ast.parse(probe)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert "app.protected.crm" not in imported
    assert "app.credentials" not in imported


def test_agent_probe_expected_denies():
    probe_path = ROOT / "infra" / "agent" / "probe.py"
    namespace: dict = {"__name__": "probe"}
    exec(
        compile(probe_path.read_text(encoding="utf-8"), str(probe_path), "exec"),
        namespace,
    )
    expected = namespace["EXPECTED"]
    assert expected["enforcement-gateway"] == "ALLOW"
    assert expected["protected-tool"] == "DENY"
    assert expected["credential-broker"] == "DENY"
    assert expected["control-plane"] == "DENY"


def test_in_process_bypass_impossible_from_agent_layout():
    agent_dir = ROOT / "infra" / "agent"
    assert (agent_dir / "probe.py").exists()
    assert not (agent_dir / "app").exists()
    for path in (ROOT / "infra" / "agent", ROOT / "demo-agent", ROOT / "sdk" / "python"):
        assert not (path / "app" / "protected" / "crm.py").exists()


def test_docker_runtime_isolation_skipped_without_daemon():
    sock = Path("/var/run/docker.sock")
    try:
        live = socket.create_connection(("127.0.0.1", 2375), timeout=0.2)
        live.close()
        daemon = True
    except OSError:
        daemon = False
    if not daemon and not sock.exists():
        pytest.skip(
            "Docker daemon not present; L3 network isolation = NOT VERIFIED"
        )
