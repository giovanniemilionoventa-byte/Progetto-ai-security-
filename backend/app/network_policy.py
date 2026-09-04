"""Declarative trust-domain contract for Compose and tests.

Docker network attachments enforce the frozen Phase 10B matrix.
internal:true blocks Internet, not peers on the same bridge.
"""

from pathlib import Path

AGENT_NETWORK = "agent_net"
BROKER_NETWORK = "broker_net"
TOOL_NETWORK = "tool_net"
PUBLIC_NETWORK = "public_net"

NETWORKS = {
    AGENT_NETWORK: {"internal": False, "purpose": "agent to gateway only"},
    BROKER_NETWORK: {
        "internal": True,
        "purpose": "gateway to credential broker",
    },
    TOOL_NETWORK: {
        "internal": True,
        "purpose": "broker to protected tool",
    },
    PUBLIC_NETWORK: {"internal": False, "purpose": "host access to control plane"},
}

SERVICES = {
    "agent": {AGENT_NETWORK},
    "enforcement-gateway": {AGENT_NETWORK, BROKER_NETWORK},
    "control-plane": {PUBLIC_NETWORK},
    "credential-broker": {BROKER_NETWORK, TOOL_NETWORK},
    "protected-tool": {TOOL_NETWORK},
}

DB_VOLUMES = {
    "agent": set(),
    "enforcement-gateway": {"aegis-data"},
    "control-plane": {"aegis-data"},
    "credential-broker": set(),
    "protected-tool": set(),
}

MATRIX = {
    ("agent", "enforcement-gateway"): "ALLOW",
    ("agent", "protected-tool"): "DENY",
    ("agent", "credential-broker"): "DENY",
    ("agent", "control-plane"): "DENY",
    ("agent", "db"): "DENY",
    ("enforcement-gateway", "credential-broker"): "ALLOW",
    ("enforcement-gateway", "protected-tool"): "DENY",
    ("enforcement-gateway", "control-plane"): "DENY",
    ("enforcement-gateway", "db"): "ALLOW",
    ("credential-broker", "protected-tool"): "ALLOW",
    ("credential-broker", "db"): "DENY",
    ("control-plane", "db"): "ALLOW",
    ("control-plane", "protected-tool"): "DENY",
    ("control-plane", "credential-broker"): "DENY",
}


def reachable(source: str, destination: str) -> bool:
    if destination == "db":
        return bool(DB_VOLUMES.get(source))
    src = SERVICES.get(source, set())
    dst = SERVICES.get(destination, set())
    return bool(src & dst)


def expected_verdict(source: str, destination: str) -> str:
    return MATRIX.get((source, destination), "UNKNOWN")


def compose_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docker-compose.yml"
