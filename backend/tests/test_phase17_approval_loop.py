"""Phase 17 — the human approval loop, closed.

Before Phase 17 `decide()` set `status='approved'` and nothing read it. The
dashboard offered an Allow button that could not cause the action to run, and no
test caught it because the tests only ever asserted that APPROVAL does *not*
execute — which was true, permanently.

These tests assert the other half: that an approved request executes, exactly
once, and only in the precise shape the human approved.

Execution is observed through `protected_crm.call_count`, so "executed" here
means the protected tool was actually invoked, not that an API returned 200.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app import models
from app.database import SessionLocal
from app.main import create_app
from app.protected.crm import protected_crm
from app.seed import DEMO_EMAIL, DEMO_PASSWORD
from app.security import utcnow


@pytest.fixture(scope="module")
def client():
    with TestClient(create_app("all")) as instance:
        yield instance


def _headers(client: TestClient) -> dict:
    token = client.post(
        "/api/auth/login", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _approving_agent(client: TestClient, name: str) -> tuple[str, str]:
    """An agent whose crm.UPDATE needs a human, and whose contract allows it."""
    headers = _headers(client)
    created = client.post(
        "/api/agents",
        headers=headers,
        json={"name": name, "provider": "demo", "model": "m", "description": ""},
    ).json()
    agent_id, token = created["agent"]["id"], created["token"]

    for kind, action, scope in (
        ("crm", "READ", "customers"),
        ("crm", "UPDATE", "customers"),
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
        json={
            "organization_id": "x",
            "agent_id": "x",
            "contract_id": f"contract-{name.lower().replace(' ', '-')}",
            "version": 1,
            "status": "ACTIVE",
            "purpose": "crm read and update",
            "capabilities": [
                {"name": "crm", "resource_kind": "crm", "actions": ["READ", "UPDATE"]}
            ],
            "resources": [{"kind": "crm", "scope": "customers"}],
            "constraints": {},
            "data_constraints": {},
            "approval_rules": [],
        },
    )
    return agent_id, token


@pytest.fixture(scope="module", autouse=True)
def approval_policy(client):
    """One org-wide policy: crm.UPDATE always needs a human."""
    client.post(
        "/api/policies",
        headers=_headers(client),
        json={
            "name": "Approve CRM updates",
            "description": "CRM writes need a human.",
            "resource_kind": "crm",
            "action": "UPDATE",
            "scope_pattern": "*",
            "decision": "APPROVAL",
            "priority": 1,
        },
    )


def _invoke(client, token, **body):
    payload = {"scope": "customers", "payload": {"id": "c-1", "name": "Ada"}}
    payload.update(body)
    return client.post(
        "/api/gateway/tools/crm/update",
        headers={"X-Agent-Token": token},
        json=payload,
    )


def _pending_approval_id(client, agent_id: str) -> str:
    rows = client.get("/api/approvals", headers=_headers(client)).json()
    mine = [r for r in rows if r["agent_id"] == agent_id and r["status"] == "pending"]
    assert mine, "expected a pending approval"
    return mine[0]["id"]


def _decide(client, approval_id: str, decision: str):
    return client.post(
        f"/api/approvals/{approval_id}/decide",
        headers=_headers(client),
        json={"decision": decision},
    )


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


def test_approval_required_does_not_execute(client):
    _, token = _approving_agent(client, "Approval Pending")
    before = protected_crm.call_count
    response = _invoke(client, token, execution_id=str(uuid4()), request_id=str(uuid4()))
    body = response.json()
    assert body["decision"] == "APPROVAL"
    assert body["executed"] is False
    assert body["approval_id"]
    assert protected_crm.call_count == before, "tool ran before a human approved"


def test_pending_approval_replay_still_does_not_execute(client):
    _, token = _approving_agent(client, "Still Pending")
    request_id = str(uuid4())
    execution_id = str(uuid4())
    _invoke(client, token, execution_id=execution_id, request_id=request_id)
    before = protected_crm.call_count
    again = _invoke(client, token, execution_id=execution_id, request_id=request_id)
    assert again.json()["decision"] == "APPROVAL"
    assert again.json()["executed"] is False
    assert protected_crm.call_count == before


def test_approved_request_executes_exactly_once(client):
    """The headline behaviour that did not exist before Phase 17."""
    agent_id, token = _approving_agent(client, "Approved Once")
    request_id = str(uuid4())
    execution_id = str(uuid4())

    first = _invoke(client, token, execution_id=execution_id, request_id=request_id)
    assert first.json()["decision"] == "APPROVAL"
    assert first.json()["executed"] is False

    approval_id = _pending_approval_id(client, agent_id)
    assert _decide(client, approval_id, "ALLOW").status_code == 200

    before = protected_crm.call_count
    executed = _invoke(client, token, execution_id=execution_id, request_id=request_id)
    body = executed.json()
    assert body["decision"] == "ALLOW"
    assert body["executed"] is True, body
    assert body["result"]["operation"] == "update"
    assert protected_crm.call_count == before + 1

    # ...and not twice.
    second = _invoke(client, token, execution_id=execution_id, request_id=request_id)
    assert second.json()["executed"] is False
    assert second.json()["decision"] == "APPROVAL"
    assert protected_crm.call_count == before + 1, "approval was reusable"


def test_denied_approval_never_executes(client):
    agent_id, token = _approving_agent(client, "Denied")
    request_id = str(uuid4())
    execution_id = str(uuid4())
    _invoke(client, token, execution_id=execution_id, request_id=request_id)
    approval_id = _pending_approval_id(client, agent_id)
    assert _decide(client, approval_id, "BLOCK").status_code == 200

    before = protected_crm.call_count
    again = _invoke(client, token, execution_id=execution_id, request_id=request_id)
    assert again.json()["executed"] is False
    assert protected_crm.call_count == before


# ---------------------------------------------------------------------------
# What the grant is bound to
# ---------------------------------------------------------------------------


def test_modified_payload_under_same_request_id_is_rejected(client):
    agent_id, token = _approving_agent(client, "Mutated Payload")
    request_id = str(uuid4())
    execution_id = str(uuid4())
    _invoke(client, token, execution_id=execution_id, request_id=request_id)
    approval_id = _pending_approval_id(client, agent_id)
    _decide(client, approval_id, "ALLOW")

    before = protected_crm.call_count
    mutated = _invoke(
        client,
        token,
        execution_id=execution_id,
        request_id=request_id,
        payload={"id": "c-1", "name": "Mallory"},
    )
    assert mutated.status_code == 409, mutated.json()
    assert protected_crm.call_count == before


def test_modified_scope_is_not_covered_by_the_grant(client):
    agent_id, token = _approving_agent(client, "Mutated Scope")
    headers = _headers(client)
    client.post(
        f"/api/agents/{agent_id}/permissions",
        headers=headers,
        json={
            "resource_kind": "crm",
            "action": "UPDATE",
            "scope": "*",
            "effect": "allow",
        },
    )
    request_id = str(uuid4())
    execution_id = str(uuid4())
    _invoke(client, token, execution_id=execution_id, request_id=request_id)
    approval_id = _pending_approval_id(client, agent_id)
    _decide(client, approval_id, "ALLOW")

    before = protected_crm.call_count
    mutated = _invoke(
        client,
        token,
        execution_id=execution_id,
        request_id=request_id,
        scope="everything",
    )
    # A different scope is a different request: idempotency rejects the reuse of
    # the key, and nothing runs.
    assert mutated.status_code == 409
    assert protected_crm.call_count == before


def test_grant_does_not_transfer_to_another_execution(client):
    agent_id, token = _approving_agent(client, "Other Execution")
    request_id = str(uuid4())
    _invoke(client, token, execution_id=str(uuid4()), request_id=request_id)
    approval_id = _pending_approval_id(client, agent_id)
    _decide(client, approval_id, "ALLOW")

    before = protected_crm.call_count
    # Same request_id, different execution: the idempotency check refuses it.
    other = _invoke(client, token, execution_id=str(uuid4()), request_id=request_id)
    assert other.status_code == 409
    assert protected_crm.call_count == before


def test_grant_does_not_transfer_to_another_agent(client):
    agent_a, token_a = _approving_agent(client, "Grant Owner")
    _, token_b = _approving_agent(client, "Grant Thief")
    request_id = str(uuid4())
    execution_id = str(uuid4())
    _invoke(client, token_a, execution_id=execution_id, request_id=request_id)
    approval_id = _pending_approval_id(client, agent_a)
    _decide(client, approval_id, "ALLOW")

    before = protected_crm.call_count
    stolen = _invoke(client, token_b, execution_id=execution_id, request_id=request_id)
    # Agent B cannot even adopt A's execution.
    assert stolen.status_code == 403
    assert protected_crm.call_count == before


def test_expired_grant_cannot_execute(client):
    agent_id, token = _approving_agent(client, "Expired Grant")
    request_id = str(uuid4())
    execution_id = str(uuid4())
    _invoke(client, token, execution_id=execution_id, request_id=request_id)
    approval_id = _pending_approval_id(client, agent_id)
    _decide(client, approval_id, "ALLOW")

    session = SessionLocal()
    try:
        row = session.query(models.Approval).filter_by(id=approval_id).one()
        row.expires_at = utcnow() - timedelta(seconds=1)
        session.commit()
    finally:
        session.close()

    before = protected_crm.call_count
    late = _invoke(client, token, execution_id=execution_id, request_id=request_id)
    assert late.json()["executed"] is False
    assert late.json()["decision"] == "APPROVAL"
    assert protected_crm.call_count == before


def test_expired_request_cannot_be_approved(client):
    agent_id, token = _approving_agent(client, "Expired Before Review")
    _invoke(client, token, execution_id=str(uuid4()), request_id=str(uuid4()))
    approval_id = _pending_approval_id(client, agent_id)

    session = SessionLocal()
    try:
        row = session.query(models.Approval).filter_by(id=approval_id).one()
        row.expires_at = utcnow() - timedelta(seconds=1)
        session.commit()
    finally:
        session.close()

    refused = _decide(client, approval_id, "ALLOW")
    assert refused.status_code == 409
    # Denying an expired request needs no authority and stays available.
    assert _decide(client, approval_id, "BLOCK").status_code == 200


def test_revoked_contract_blocks_an_approved_action(client):
    """The human approved an action under a contract, not in the abstract."""
    agent_id, token = _approving_agent(client, "Contract Revoked")
    headers = _headers(client)
    request_id = str(uuid4())
    execution_id = str(uuid4())
    _invoke(client, token, execution_id=execution_id, request_id=request_id)
    approval_id = _pending_approval_id(client, agent_id)
    _decide(client, approval_id, "ALLOW")

    contracts = client.get(f"/api/agents/{agent_id}/contracts", headers=headers).json()
    target = contracts[0]
    client.post(
        f"/api/agents/{agent_id}/contracts/{target['contract_id']}/{target['version']}/status",
        headers=headers,
        json={"status": "REVOKED"},
    )

    before = protected_crm.call_count
    after_revocation = _invoke(
        client, token, execution_id=execution_id, request_id=request_id
    )
    assert after_revocation.json()["executed"] is False
    assert protected_crm.call_count == before


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def test_approved_execution_is_recorded_as_its_own_event(client):
    """The trail should read: agent asked, human approved, action ran."""
    agent_id, token = _approving_agent(client, "Evidence Trail")
    request_id = str(uuid4())
    execution_id = str(uuid4())
    _invoke(client, token, execution_id=execution_id, request_id=request_id)
    approval_id = _pending_approval_id(client, agent_id)
    _decide(client, approval_id, "ALLOW")
    _invoke(client, token, execution_id=execution_id, request_id=request_id)

    session = SessionLocal()
    try:
        events = (
            session.query(models.Event)
            .filter(models.Event.execution_id == execution_id)
            .order_by(models.Event.seq.asc())
            .all()
        )
        assert [e.decision for e in events] == ["APPROVAL", "ALLOW"]
        assert events[1].request_id == f"{request_id}:approved"
        assert approval_id in events[1].reason
        # The chain covers both, and links.
        assert events[1].previous_evidence_hash == events[0].evidence_hash

        approval = session.query(models.Approval).filter_by(id=approval_id).one()
        assert approval.consumed_at is not None
        assert approval.consumed_event_id == events[1].id
        assert approval.param_hash == events[0].payload_hash
    finally:
        session.close()


def test_approval_records_its_full_binding(client):
    agent_id, token = _approving_agent(client, "Binding Recorded")
    request_id = str(uuid4())
    execution_id = str(uuid4())
    _invoke(client, token, execution_id=execution_id, request_id=request_id)
    approval_id = _pending_approval_id(client, agent_id)

    row = next(
        item
        for item in client.get("/api/approvals", headers=_headers(client)).json()
        if item["id"] == approval_id
    )
    assert row["execution_id"] == execution_id
    assert row["request_id"] == request_id
    assert row["contract_id"]
    assert row["contract_version"] == 1
    assert row["param_hash"]
    assert row["expires_at"]
    assert row["consumed_at"] is None
