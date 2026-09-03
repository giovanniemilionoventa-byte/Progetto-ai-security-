import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.seed import DEMO_EMAIL, DEMO_PASSWORD


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _login(client: TestClient) -> str:
    res = client.post(
        "/api/auth/login",
        json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
    )
    assert res.status_code == 200
    return res.json()["access_token"]


def _sales_token(client: TestClient) -> str:
    token = _login(client)
    agents = client.get(
        "/api/agents", headers={"Authorization": f"Bearer {token}"}
    ).json()
    sales = next(a for a in agents if a["name"] == "Sales Copilot")
    rotated = client.post(
        f"/api/agents/{sales['id']}/rotate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert rotated.status_code == 200
    return rotated.json()["token"]


def test_health(client: TestClient):
    assert client.get("/api/health").json()["status"] == "ok"


def test_crm_read_allow(client: TestClient):
    token = _sales_token(client)
    res = client.post(
        "/api/authorize",
        headers={"X-Agent-Token": token},
        json={"resource_kind": "crm", "action": "READ", "scope": "customers"},
    )
    assert res.status_code == 200
    assert res.json()["decision"] == "ALLOW"


def test_crm_delete_block(client: TestClient):
    token = _sales_token(client)
    res = client.post(
        "/api/authorize",
        headers={"X-Agent-Token": token},
        json={"resource_kind": "crm", "action": "DELETE", "scope": "all"},
    )
    assert res.json()["decision"] == "BLOCK"


def test_external_email_approval(client: TestClient):
    token = _sales_token(client)
    res = client.post(
        "/api/authorize",
        headers={"X-Agent-Token": token},
        json={
            "resource_kind": "email",
            "action": "SEND",
            "scope": "external",
            "destination": "external",
        },
    )
    body = res.json()
    assert body["decision"] == "APPROVAL"
    assert body["approval_id"]


def test_finance_export_block(client: TestClient):
    token = _sales_token(client)
    res = client.post(
        "/api/authorize",
        headers={"X-Agent-Token": token},
        json={
            "resource_kind": "files",
            "action": "EXPORT",
            "scope": "/Finance",
            "destination": "external",
        },
    )
    assert res.json()["decision"] == "BLOCK"


def test_payments_hard_block(client: TestClient):
    token = _sales_token(client)
    res = client.post(
        "/api/authorize",
        headers={"X-Agent-Token": token},
        json={"resource_kind": "payments", "action": "TRANSFER", "scope": "any"},
    )
    assert res.json()["decision"] == "BLOCK"
