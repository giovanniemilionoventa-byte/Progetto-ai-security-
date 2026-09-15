"""Phase 17 — the Runtime Contract management API.

Before Phase 17 the Runtime Contract had no HTTP surface: the DTOs existed in
schemas.py but no router imported them, so a contract could only be created by
calling contract_store from Python. That is why no deployment and no benchmark
ever ran with one active.

These tests cover the new surface and, more importantly, the authority rules
around it: the agent governed by a contract must never be able to read or write
it, and an operator must never be able to write one into another tenant.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import config as app_config
from app.main import create_app
from app.seed import DEMO_EMAIL, DEMO_PASSWORD


@pytest.fixture(scope="module")
def client():
    with TestClient(create_app("all")) as instance:
        yield instance


def _login(client: TestClient) -> str:
    response = client.post(
        "/api/auth/login", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def _headers(client: TestClient) -> dict:
    return {"Authorization": f"Bearer {_login(client)}"}


def _sales_agent(client: TestClient) -> dict:
    agents = client.get("/api/agents", headers=_headers(client)).json()
    return next(agent for agent in agents if agent["name"] == "Sales Copilot")


def _new_agent(client: TestClient, name: str) -> tuple[str, str]:
    created = client.post(
        "/api/agents",
        headers=_headers(client),
        json={"name": name, "provider": "demo", "model": "m", "description": ""},
    ).json()
    return created["agent"]["id"], created["token"]


def _contract_doc(**overrides) -> dict:
    document = {
        "organization_id": "will-be-overwritten",
        "agent_id": "will-be-overwritten",
        "contract_id": "api-contract",
        "version": 1,
        "status": "ACTIVE",
        "purpose": "crm read only",
        "capabilities": [
            {"name": "crm", "resource_kind": "crm", "actions": ["READ"]}
        ],
        "resources": [{"kind": "crm", "scope": "customers"}],
        "constraints": {},
        "data_constraints": {},
        "approval_rules": [],
    }
    document.update(overrides)
    return document


# ---------------------------------------------------------------------------
# The surface exists
# ---------------------------------------------------------------------------


def test_seeded_agent_has_an_active_contract(client):
    agent = _sales_agent(client)
    response = client.get(
        f"/api/agents/{agent['id']}/contracts/active", headers=_headers(client)
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ACTIVE"
    assert body["contract_id"] == "sales-copilot"


def test_create_list_and_fetch_contract(client):
    agent_id, _ = _new_agent(client, "Contract CRUD")
    headers = _headers(client)

    created = client.post(
        f"/api/agents/{agent_id}/contracts",
        headers=headers,
        json=_contract_doc(contract_id="crud-1"),
    )
    assert created.status_code == 201
    assert created.json()["contract_id"] == "crud-1"

    listed = client.get(f"/api/agents/{agent_id}/contracts", headers=headers)
    assert listed.status_code == 200
    assert [row["contract_id"] for row in listed.json()] == ["crud-1"]

    fetched = client.get(
        f"/api/agents/{agent_id}/contracts/crud-1/1", headers=headers
    )
    assert fetched.status_code == 200
    assert fetched.json()["version"] == 1

    versions = client.get(
        f"/api/agents/{agent_id}/contracts/crud-1/versions", headers=headers
    )
    assert versions.status_code == 200
    assert len(versions.json()) == 1


def test_identity_comes_from_operator_not_body(client):
    """A body claiming another tenant must not take effect."""
    agent_id, _ = _new_agent(client, "Identity Override")
    created = client.post(
        f"/api/agents/{agent_id}/contracts",
        headers=_headers(client),
        json=_contract_doc(
            contract_id="identity-1",
            organization_id="attacker-org",
            agent_id="attacker-agent",
        ),
    )
    assert created.status_code == 201
    body = created.json()
    assert body["agent_id"] == agent_id
    assert body["organization_id"] != "attacker-org"


# ---------------------------------------------------------------------------
# Enforcement follows the contract
# ---------------------------------------------------------------------------


def test_agent_without_contract_is_denied(client):
    agent_id, token = _new_agent(client, "No Contract")
    client.post(
        f"/api/agents/{agent_id}/permissions",
        headers=_headers(client),
        json={
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "effect": "allow",
        },
    )
    response = client.post(
        "/api/authorize",
        headers={"X-Agent-Token": token},
        json={"resource_kind": "crm", "action": "READ", "scope": "customers"},
    )
    assert response.json()["decision"] == "BLOCK"
    assert "no runtime contract" in response.json()["reason"].lower()


def test_contract_grants_then_revocation_removes_authority(client):
    agent_id, token = _new_agent(client, "Grant Then Revoke")
    headers = _headers(client)
    client.post(
        f"/api/agents/{agent_id}/permissions",
        headers=headers,
        json={
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "effect": "allow",
        },
    )
    request = {"resource_kind": "crm", "action": "READ", "scope": "customers"}
    agent_headers = {"X-Agent-Token": token}

    assert (
        client.post("/api/authorize", headers=agent_headers, json=request).json()[
            "decision"
        ]
        == "BLOCK"
    )

    client.post(
        f"/api/agents/{agent_id}/contracts",
        headers=headers,
        json=_contract_doc(contract_id="grant-1"),
    )
    assert (
        client.post("/api/authorize", headers=agent_headers, json=request).json()[
            "decision"
        ]
        == "ALLOW"
    )

    revoked = client.post(
        f"/api/agents/{agent_id}/contracts/grant-1/1/status",
        headers=headers,
        json={"status": "REVOKED"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "REVOKED"

    after = client.post("/api/authorize", headers=agent_headers, json=request).json()
    assert after["decision"] == "BLOCK"
    assert "no runtime contract" in after["reason"].lower()


def test_action_outside_contract_capabilities_is_blocked(client):
    """Permission and policy both allow it; the contract does not."""
    agent_id, token = _new_agent(client, "Outside Contract")
    headers = _headers(client)
    for kind, action, scope in (
        ("crm", "READ", "customers"),
        ("files", "READ", "/Sales"),
    ):
        client.post(
            f"/api/agents/{agent_id}/permissions",
            headers=headers,
            json={
                "resource_kind": kind,
                "action": action,
                "scope": scope,
                "effect": "allow",
            },
        )
    client.post(
        f"/api/agents/{agent_id}/contracts",
        headers=headers,
        json=_contract_doc(contract_id="narrow-1"),
    )
    agent_headers = {"X-Agent-Token": token}

    inside = client.post(
        "/api/authorize",
        headers=agent_headers,
        json={"resource_kind": "crm", "action": "READ", "scope": "customers"},
    ).json()
    assert inside["decision"] == "ALLOW"

    outside = client.post(
        "/api/authorize",
        headers=agent_headers,
        json={"resource_kind": "files", "action": "READ", "scope": "/Sales"},
    ).json()
    assert outside["decision"] == "BLOCK"
    assert "contract" in outside["reason"].lower()


# ---------------------------------------------------------------------------
# Lifecycle rules
# ---------------------------------------------------------------------------


def test_second_active_contract_is_rejected(client):
    agent_id, _ = _new_agent(client, "Two Active")
    headers = _headers(client)
    first = client.post(
        f"/api/agents/{agent_id}/contracts",
        headers=headers,
        json=_contract_doc(contract_id="active-a"),
    )
    assert first.status_code == 201
    second = client.post(
        f"/api/agents/{agent_id}/contracts",
        headers=headers,
        json=_contract_doc(contract_id="active-b"),
    )
    assert second.status_code == 409
    assert second.json()["detail"] == "active_contract_exists"


def test_revoked_contract_cannot_return_to_active(client):
    agent_id, _ = _new_agent(client, "Terminal State")
    headers = _headers(client)
    client.post(
        f"/api/agents/{agent_id}/contracts",
        headers=headers,
        json=_contract_doc(contract_id="terminal-1"),
    )
    client.post(
        f"/api/agents/{agent_id}/contracts/terminal-1/1/status",
        headers=headers,
        json={"status": "REVOKED"},
    )
    attempt = client.post(
        f"/api/agents/{agent_id}/contracts/terminal-1/1/status",
        headers=headers,
        json={"status": "ACTIVE"},
    )
    assert attempt.status_code == 409
    assert attempt.json()["detail"] == "invalid_transition"


def test_delete_is_a_revocation_not_a_removal(client):
    agent_id, _ = _new_agent(client, "Soft Delete")
    headers = _headers(client)
    client.post(
        f"/api/agents/{agent_id}/contracts",
        headers=headers,
        json=_contract_doc(contract_id="soft-1"),
    )
    removed = client.delete(
        f"/api/agents/{agent_id}/contracts/soft-1/1", headers=headers
    )
    assert removed.status_code == 204
    # The row survives, because evidence refers to contracts by id and version.
    fetched = client.get(
        f"/api/agents/{agent_id}/contracts/soft-1/1", headers=headers
    )
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "REVOKED"


def test_invalid_contract_document_is_rejected(client):
    agent_id, _ = _new_agent(client, "Bad Doc")
    response = client.post(
        f"/api/agents/{agent_id}/contracts",
        headers=_headers(client),
        json=_contract_doc(contract_id="bad-1", version=0),
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Authority: the governed agent is never the author
# ---------------------------------------------------------------------------


def test_agent_token_cannot_read_or_write_contracts(client):
    agent_id, token = _new_agent(client, "Agent Self Service")
    agent_headers = {"X-Agent-Token": token}

    listed = client.get(f"/api/agents/{agent_id}/contracts", headers=agent_headers)
    assert listed.status_code == 403

    written = client.post(
        f"/api/agents/{agent_id}/contracts",
        headers=agent_headers,
        json=_contract_doc(contract_id="self-1"),
    )
    assert written.status_code == 403

    transitioned = client.post(
        f"/api/agents/{agent_id}/contracts/self-1/1/status",
        headers=agent_headers,
        json={"status": "ACTIVE"},
    )
    assert transitioned.status_code == 403


def test_unauthenticated_access_is_rejected(client):
    agent_id, _ = _new_agent(client, "Anonymous")
    assert client.get(f"/api/agents/{agent_id}/contracts").status_code == 401


def test_operator_cannot_write_into_another_tenant(client):
    """An operator from another organization cannot see or govern this agent."""
    agent_id, _ = _new_agent(client, "Tenant Isolated")
    other = client.post(
        "/api/auth/register",
        json={
            "organization_name": "Rival Corp",
            "full_name": "Rae Rival",
            "email": "rae@rival.test",
            "password": "rival-pass",
        },
    )
    assert other.status_code == 200
    rival_headers = {"Authorization": f"Bearer {other.json()['access_token']}"}

    assert (
        client.get(f"/api/agents/{agent_id}/contracts", headers=rival_headers).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/agents/{agent_id}/contracts",
            headers=rival_headers,
            json=_contract_doc(contract_id="rival-1"),
        ).status_code
        == 404
    )


def test_contract_policy_endpoint_reports_fail_closed_default():
    assert app_config.REQUIRE_RUNTIME_CONTRACT is True
