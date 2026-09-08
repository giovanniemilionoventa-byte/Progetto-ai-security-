"""Phase 13.C — static deployment contract after execution-boundary remediation.

These tests lock Compose/YAML properties. They are not L3/runtime proof.
"""

from pathlib import Path

from app.network_policy import NETWORKS, compose_path

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
                "cap_add": [],
                "security_opt": [],
                "read_only": None,
                "network_mode": None,
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
                }
                else None
            )
            in_environment = key == "environment"
            continue
        if indent == 4 and ":" in line and not line.startswith("-"):
            key, value = line.split(":", 1)
            value = value.strip().strip('"')
            if key in {"user", "privileged", "read_only", "network_mode"}:
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
    return {"networks": networks, "services": services}


def test_agent_net_is_internal_static_contract():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    assert compose["networks"]["agent_net"]["internal"] is True
    assert NETWORKS["agent_net"]["internal"] is True
    assert compose["networks"]["broker_net"]["internal"] is True
    assert compose["networks"]["tool_net"]["internal"] is True
    assert compose["networks"]["public_net"]["internal"] is False


def test_agent_does_not_mount_db_volume():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    agent = compose["services"]["agent"]
    assert agent["volumes"] == []
    blob = " ".join(agent["volumes"]).lower()
    assert "aegis-data" not in blob
    assert "aegis.db" not in blob


def test_agent_does_not_mount_docker_socket():
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    compose = _parse_compose(text)
    assert "docker.sock" not in text
    assert not any("docker.sock" in item for item in compose["services"]["agent"]["volumes"])


def test_agent_does_not_use_host_network():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    agent = compose["services"]["agent"]
    assert agent["network_mode"] is None
    assert agent["networks"] == ["agent_net"]
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    assert "network_mode: host" not in text


def test_agent_has_no_unnecessary_secrets():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    env = compose["services"]["agent"]["environment"]
    secret_keys = {
        "AEGIS_SECRET_KEY",
        "AEGIS_EAT_KEY",
        "AEGIS_INTERNAL_GATEWAY_TOKEN",
        "AEGIS_INTERNAL_TOOL_TOKEN",
        "AEGIS_CRM_SECRET",
        "AEGIS_DATABASE_URL",
        "USER_LLM_API_KEY",
    }
    assert secret_keys.isdisjoint(env)
    joined = " ".join(f"{k}={v}" for k, v in env.items()).lower()
    assert "secret" not in joined
    assert "token" not in joined
    assert "sqlite" not in joined


def test_agent_runtime_env_points_only_at_gateway_for_calls():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    env = compose["services"]["agent"]["environment"]
    assert env["AEGIS_BASE_URL"] == "http://enforcement-gateway:8000"
    assert "AEGIS_BROKER_URL" not in env
    assert "AEGIS_TOOL_URL" not in env


def test_host_ports_are_operator_entry_not_agent_attachment():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    assert compose["services"]["control-plane"]["ports"] == ["8000:8000"]
    assert compose["services"]["enforcement-gateway"]["ports"] == ["8001:8000"]
    assert "public_net" in compose["services"]["control-plane"]["networks"]
    assert "agent_net" not in compose["services"]["control-plane"]["networks"]
    assert "agent_net" in compose["services"]["agent"]["networks"]
    assert "public_net" not in compose["services"]["agent"]["networks"]
    assert compose["services"]["credential-broker"]["ports"] == []
    assert compose["services"]["protected-tool"]["ports"] == []
    assert compose["services"]["agent"]["ports"] == []


def test_shared_sqlite_volume_excludes_agent_and_broker():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    assert any(
        "aegis-data" in item for item in compose["services"]["control-plane"]["volumes"]
    )
    assert any(
        "aegis-data" in item
        for item in compose["services"]["enforcement-gateway"]["volumes"]
    )
    assert not any(
        "aegis-data" in item for item in compose["services"]["agent"]["volumes"]
    )
    assert not any(
        "aegis-data" in item
        for item in compose["services"]["credential-broker"]["volumes"]
    )
    assert not any(
        "aegis-data" in item for item in compose["services"]["protected-tool"]["volumes"]
    )


def test_agent_hardening_flags_remain():
    compose = _parse_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    agent = compose["services"]["agent"]
    assert agent["user"] in {"10001:10001", "10001"}
    assert agent["privileged"] == "false"
    assert "ALL" in agent["cap_drop"]
    assert agent["cap_add"] == []
    assert agent["read_only"] == "true"
    dockerfile = (ROOT / "infra" / "agent" / "Dockerfile").read_text(encoding="utf-8")
    assert "USER 10001" in dockerfile
    assert "backend/app" not in dockerfile
