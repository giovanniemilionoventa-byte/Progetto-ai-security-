"""Phase 17 — per-tenant credential isolation.

Until Phase 17 `broker.issue()` checked that organization_id was non-empty and
then discarded it, returning the same AEGIS_CRM_SECRET to every caller. Every
tenant in a deployment shared one credential to the protected system, and the
mock CRM held one record list, so cross-tenant credential misuse was not merely
undetected -- there was nothing tenant-specific to detect.

Credentials are now derived per tenant and the protected tool verifies the
credential against the organization the call claims to be for.

Scope note, stated plainly: the provider still holds the master key and can
derive any tenant's credential. This is per-tenant separation, not the
"CAN USE != CAN READ" property the handoff asks for. Nothing here should be
read as customer-managed keys.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import config
from app.credentials import (
    CredentialAccessDenied,
    broker,
    contains_any_tool_secret,
    derive_tool_credential,
)
from app.main import create_app
from app.protected.crm import InvalidToolCredential, protected_crm

ORG_A = "org-aaaa-1111"
ORG_B = "org-bbbb-2222"


@pytest.fixture(autouse=True)
def clean_tool():
    protected_crm.reset()
    yield
    protected_crm.reset()


# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------


def test_each_tenant_gets_a_distinct_credential():
    a = broker.issue("crm", organization_id=ORG_A)
    b = broker.issue("crm", organization_id=ORG_B)
    assert a.secret != b.secret
    assert a.organization_id == ORG_A
    assert b.organization_id == ORG_B


def test_derivation_is_deterministic():
    """The tool must be able to verify without shared storage."""
    assert derive_tool_credential("crm", ORG_A) == derive_tool_credential("crm", ORG_A)


def test_derived_credential_is_not_the_master():
    issued = broker.issue("crm", organization_id=ORG_A)
    assert issued.secret != config.CRM_SECRET
    assert config.CRM_SECRET not in issued.secret


def test_issue_requires_an_organization():
    with pytest.raises(CredentialAccessDenied):
        broker.issue("crm", organization_id="")


def test_issue_refuses_unknown_tools():
    with pytest.raises(CredentialAccessDenied):
        broker.issue("payments", organization_id=ORG_A)


# ---------------------------------------------------------------------------
# The tool enforces the binding
# ---------------------------------------------------------------------------


def test_tenant_credential_works_for_its_own_tenant():
    cred = broker.issue("crm", organization_id=ORG_A)
    result = protected_crm.execute(
        "read", cred.secret, scope="customers", organization_id=ORG_A
    )
    assert result["ok"] is True
    assert result["organization_id"] == ORG_A


def test_tenant_a_credential_is_refused_for_tenant_b():
    """The attack this whole change exists to stop."""
    cred_a = broker.issue("crm", organization_id=ORG_A)
    with pytest.raises(InvalidToolCredential):
        protected_crm.execute(
            "read", cred_a.secret, scope="customers", organization_id=ORG_B
        )


def test_master_credential_cannot_be_used_to_call_as_a_tenant():
    """The master derives credentials; it is not itself a calling credential."""
    with pytest.raises(InvalidToolCredential):
        protected_crm.execute(
            "read", config.CRM_SECRET, scope="customers", organization_id=ORG_A
        )


def test_guessed_credential_is_refused():
    with pytest.raises(InvalidToolCredential):
        protected_crm.execute(
            "read", "guess", scope="customers", organization_id=ORG_A
        )


def test_tenants_see_separate_records():
    cred_a = broker.issue("crm", organization_id=ORG_A)
    cred_b = broker.issue("crm", organization_id=ORG_B)
    a = protected_crm.execute(
        "read", cred_a.secret, scope="customers", organization_id=ORG_A
    )
    b = protected_crm.execute(
        "read", cred_b.secret, scope="customers", organization_id=ORG_B
    )
    assert all(row["organization_id"] == ORG_A for row in a["records"])
    assert all(row["organization_id"] == ORG_B for row in b["records"])
    assert a["records"] != b["records"]


# ---------------------------------------------------------------------------
# Neither credential may leak outward
# ---------------------------------------------------------------------------


def test_leak_detector_catches_the_derived_credential():
    derived = derive_tool_credential("crm", ORG_A)
    assert contains_any_tool_secret({"echo": derived}, ORG_A) is True
    assert contains_any_tool_secret({"echo": derived}, ORG_B) is False
    assert contains_any_tool_secret({"echo": "harmless"}, ORG_A) is False


def test_leak_detector_still_catches_the_master():
    assert contains_any_tool_secret({"echo": config.CRM_SECRET}, ORG_A) is True


def test_tool_role_rejects_a_response_echoing_the_derived_credential(monkeypatch):
    """A compromised tool cannot smuggle a tenant's credential back out."""
    monkeypatch.setattr(config, "INTERNAL_TOOL_TOKEN", "tool-token")
    derived = derive_tool_credential("crm", ORG_A)

    def _leak(operation, secret, *, scope, payload=None, organization_id=None):
        return {"ok": True, "echo": derived}

    monkeypatch.setattr(protected_crm, "execute", _leak)
    with TestClient(create_app("protected-tool")) as client:
        response = client.post(
            "/api/internal/tools/crm/read",
            headers={"X-Internal-Token": "tool-token"},
            json={
                "secret": derived,
                "scope": "customers",
                "organization_id": ORG_A,
            },
        )
        assert response.status_code == 502
        assert derived not in response.text


def test_broker_rejects_a_response_echoing_the_derived_credential(monkeypatch):
    from app.eat import sign_eat

    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "TOOL_URL", "")
    derived = derive_tool_credential("crm", ORG_A)

    def _leak(operation, secret, *, scope, payload=None, organization_id=None):
        return {"ok": True, "echo": derived}

    monkeypatch.setattr(protected_crm, "execute", _leak)
    eat = sign_eat(
        org_id=ORG_A,
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-tenant-leak",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={},
        contract_id=None,
        contract_version=None,
    )
    with TestClient(create_app("credential-broker")) as client:
        response = client.post(
            "/api/internal/broker/execute",
            headers={"X-Internal-Token": "gw-token"},
            json={
                "eat": eat,
                "tool": "crm",
                "operation": "read",
                "scope": "customers",
                "destination": None,
                "payload": {},
                "org_id": ORG_A,
                "agent_id": "agent-1",
                "execution_id": "exec-1",
                "request_id": "req-tenant-leak",
            },
        )
        assert response.status_code == 502
        assert derived not in response.text
        assert response.json()["detail"] == "Protected tool returned unsafe payload"


def test_broker_derives_for_the_org_in_the_eat_not_the_body(monkeypatch):
    """The broker must not be steerable into using another tenant's credential.

    The EAT binds org_id and the broker rejects a body whose org_id differs, so
    there is no path where tenant B's request is served with tenant A's
    credential.
    """
    from app.eat import sign_eat

    monkeypatch.setattr(config, "INTERNAL_GATEWAY_TOKEN", "gw-token")
    monkeypatch.setattr(config, "TOOL_URL", "")
    eat = sign_eat(
        org_id=ORG_A,
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-cross",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={},
        contract_id=None,
        contract_version=None,
    )
    with TestClient(create_app("credential-broker")) as client:
        response = client.post(
            "/api/internal/broker/execute",
            headers={"X-Internal-Token": "gw-token"},
            json={
                "eat": eat,
                "tool": "crm",
                "operation": "read",
                "scope": "customers",
                "destination": None,
                "payload": {},
                "org_id": ORG_B,  # claiming a different tenant
                "agent_id": "agent-1",
                "execution_id": "exec-1",
                "request_id": "req-cross",
            },
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "eat_rejected"
