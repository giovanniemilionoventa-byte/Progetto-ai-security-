import uuid

import pytest
from fastapi.testclient import TestClient

from app import models
from app.database import SessionLocal
from app.main import app
from app.seed import DEMO_EMAIL, DEMO_PASSWORD

SEQUENCE_DEF = {
    "steps": [
        {"resource_kind": "crm", "action": "READ"},
        {"resource_kind": "files", "action": "READ"},
    ]
}
THRESHOLD_DEF = {
    "resource_kind": "crm",
    "action": "READ",
    "count": 2,
}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _token(client: TestClient, email: str, password: str, org: str, name: str) -> str:
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    if res.status_code == 200:
        return res.json()["access_token"]
    res = client.post(
        "/api/auth/register",
        json={
            "organization_name": org,
            "full_name": name,
            "email": email,
            "password": password,
        },
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _headers(client: TestClient, email=DEMO_EMAIL, password=DEMO_PASSWORD, org="Acme Corp", name="Ada Admin"):
    token = _token(client, email, password, org, name)
    return {"Authorization": f"Bearer {token}"}


def _beta_headers(client: TestClient):
    return _headers(
        client,
        email="admin@beta.test",
        password="beta-demo-pass",
        org="Beta Inc",
        name="Bea Admin",
    )


def _sales_token(client: TestClient) -> str:
    headers = _headers(client)
    agents = client.get("/api/agents", headers=headers).json()
    sales = next(a for a in agents if a["name"] == "Sales Copilot")
    rotated = client.post(f"/api/agents/{sales['id']}/rotate", headers=headers)
    assert rotated.status_code == 200
    return rotated.json()["token"]


def _create(client: TestClient, headers: dict, **overrides) -> dict:
    payload = {
        "name": f"custom-{uuid.uuid4()}",
        "description": "org custom pattern",
        "type": "SEQUENCE",
        "severity": "medium",
        "definition": SEQUENCE_DEF,
        "enabled": True,
    }
    payload.update(overrides)
    res = client.post("/api/behavior-patterns", headers=headers, json=payload)
    return res


def _globals(patterns: list[dict]) -> list[dict]:
    return [p for p in patterns if p.get("organization_id") is None]


def _signals_for(pattern_id: str) -> list:
    db = SessionLocal()
    try:
        return (
            db.query(models.BehaviorSignal)
            .filter(models.BehaviorSignal.pattern_id == pattern_id)
            .all()
        )
    finally:
        db.close()


def test_unauthenticated_rejected(client: TestClient):
    res = client.get("/api/behavior-patterns")
    assert res.status_code == 401


def test_organization_sees_global_patterns(client: TestClient):
    res = client.get("/api/behavior-patterns", headers=_headers(client))
    assert res.status_code == 200
    globs = _globals(res.json())
    assert globs
    names = {p["name"] for p in globs}
    assert any("CRM read" in n for n in names)
    assert any("external email" in n.lower() for n in names)


def test_organization_sees_own_patterns(client: TestClient):
    headers = _headers(client)
    created = _create(client, headers)
    assert created.status_code in {200, 201}
    body = created.json()
    listed = client.get("/api/behavior-patterns", headers=headers).json()
    ids = {p["id"] for p in listed}
    assert body["id"] in ids
    fetched = client.get(f"/api/behavior-patterns/{body['id']}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["organization_id"] is not None


def test_organization_cannot_access_other_org_pattern(client: TestClient):
    acme = _headers(client)
    beta = _beta_headers(client)
    created = _create(client, acme, name=f"acme-only-{uuid.uuid4()}")
    assert created.status_code in {200, 201}
    pattern_id = created.json()["id"]

    listed = client.get("/api/behavior-patterns", headers=beta).json()
    assert pattern_id not in {p["id"] for p in listed}

    assert client.get(f"/api/behavior-patterns/{pattern_id}", headers=beta).status_code == 404
    assert (
        client.patch(
            f"/api/behavior-patterns/{pattern_id}",
            headers=beta,
            json={"enabled": False},
        ).status_code
        == 404
    )
    assert client.delete(f"/api/behavior-patterns/{pattern_id}", headers=beta).status_code == 404


def test_global_patterns_not_modifiable_or_deletable(client: TestClient):
    headers = _headers(client)
    globs = _globals(client.get("/api/behavior-patterns", headers=headers).json())
    pattern_id = globs[0]["id"]

    patch = client.patch(
        f"/api/behavior-patterns/{pattern_id}",
        headers=headers,
        json={"enabled": False, "name": "hacked-global"},
    )
    assert patch.status_code == 403

    delete = client.delete(f"/api/behavior-patterns/{pattern_id}", headers=headers)
    assert delete.status_code == 403

    still = client.get(f"/api/behavior-patterns/{pattern_id}", headers=headers)
    assert still.status_code == 200
    assert still.json()["name"] == globs[0]["name"]
    assert still.json()["enabled"] is True


def test_create_sequence_valid(client: TestClient):
    res = _create(client, _headers(client), type="SEQUENCE", definition=SEQUENCE_DEF)
    assert res.status_code in {200, 201}
    body = res.json()
    assert body["type"] == "SEQUENCE"
    assert body["enabled"] is True
    assert len(body["definition"]["steps"]) == 2


def test_create_threshold_valid(client: TestClient):
    res = _create(
        client,
        _headers(client),
        type="THRESHOLD",
        definition=THRESHOLD_DEF,
        severity="high",
    )
    assert res.status_code in {200, 201}
    body = res.json()
    assert body["type"] == "THRESHOLD"
    assert body["severity"] == "high"
    assert body["definition"]["count"] == 2


def test_invalid_type_rejected(client: TestClient):
    res = _create(client, _headers(client), type="ANOMALY")
    assert res.status_code == 400


def test_invalid_severity_rejected(client: TestClient):
    res = _create(client, _headers(client), severity="apocalyptic")
    assert res.status_code == 400


def test_invalid_definition_rejected(client: TestClient):
    headers = _headers(client)
    res = _create(
        client,
        headers,
        type="SEQUENCE",
        definition={"steps": [{"resource_kind": "crm"}]},
    )
    assert res.status_code == 400
    res = _create(
        client,
        headers,
        type="THRESHOLD",
        definition={"resource_kind": "email", "count": 0},
    )
    assert res.status_code == 400
    res = _create(
        client,
        headers,
        type="SEQUENCE",
        definition={"steps": [], "eval": "os.system('x')"},
    )
    assert res.status_code == 400


def test_update_own_pattern(client: TestClient):
    headers = _headers(client)
    created = _create(client, headers)
    pattern_id = created.json()["id"]
    res = client.patch(
        f"/api/behavior-patterns/{pattern_id}",
        headers=headers,
        json={"description": "updated description", "severity": "high"},
    )
    assert res.status_code == 200
    assert res.json()["description"] == "updated description"
    assert res.json()["severity"] == "high"


def test_disable_own_pattern(client: TestClient):
    headers = _headers(client)
    created = _create(client, headers)
    pattern_id = created.json()["id"]
    res = client.patch(
        f"/api/behavior-patterns/{pattern_id}",
        headers=headers,
        json={"enabled": False},
    )
    assert res.status_code == 200
    assert res.json()["enabled"] is False


def test_disabled_pattern_ignored_by_engine(client: TestClient):
    headers = _headers(client)
    created = _create(
        client,
        headers,
        type="SEQUENCE",
        definition=SEQUENCE_DEF,
        enabled=True,
        name=f"detect-then-disable-{uuid.uuid4()}",
    )
    assert created.status_code in {200, 201}
    pattern_id = created.json()["id"]
    agent_token = _sales_token(client)
    execution_id = str(uuid.uuid4())

    first = client.post(
        "/api/authorize",
        headers={"X-Agent-Token": agent_token},
        json={
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": execution_id,
        },
    )
    assert first.status_code == 200
    second = client.post(
        "/api/authorize",
        headers={"X-Agent-Token": agent_token},
        json={
            "resource_kind": "files",
            "action": "READ",
            "scope": "/Sales",
            "execution_id": execution_id,
        },
    )
    assert second.status_code == 200
    assert _signals_for(pattern_id)

    disable = client.patch(
        f"/api/behavior-patterns/{pattern_id}",
        headers=headers,
        json={"enabled": False},
    )
    assert disable.status_code == 200

    before = len(_signals_for(pattern_id))
    new_execution = str(uuid.uuid4())
    client.post(
        "/api/authorize",
        headers={"X-Agent-Token": agent_token},
        json={
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "execution_id": new_execution,
        },
    )
    client.post(
        "/api/authorize",
        headers={"X-Agent-Token": agent_token},
        json={
            "resource_kind": "files",
            "action": "READ",
            "scope": "/Sales",
            "execution_id": new_execution,
        },
    )
    assert len(_signals_for(pattern_id)) == before


def test_delete_own_pattern(client: TestClient):
    headers = _headers(client)
    created = _create(client, headers)
    pattern_id = created.json()["id"]
    res = client.delete(f"/api/behavior-patterns/{pattern_id}", headers=headers)
    assert res.status_code in {200, 204}
    assert client.get(f"/api/behavior-patterns/{pattern_id}", headers=headers).status_code == 404


def test_manipulate_global_by_id_rejected(client: TestClient):
    headers = _headers(client)
    globs = _globals(client.get("/api/behavior-patterns", headers=headers).json())
    assert globs
    pattern_id = globs[0]["id"]
    assert (
        client.patch(
            f"/api/behavior-patterns/{pattern_id}",
            headers=headers,
            json={"severity": "low"},
        ).status_code
        == 403
    )
    assert client.delete(f"/api/behavior-patterns/{pattern_id}", headers=headers).status_code == 403


def test_phase5_sequence_still_detected(client: TestClient):
    headers = _headers(client)
    patterns = client.get("/api/behavior-patterns", headers=headers).json()
    seq = next(
        p
        for p in patterns
        if p["organization_id"] is None and p["type"] == "SEQUENCE"
    )
    agent_token = _sales_token(client)
    execution_id = str(uuid.uuid4())
    steps = [
        {"resource_kind": "crm", "action": "READ", "scope": "customers"},
        {
            "resource_kind": "files",
            "action": "EXPORT",
            "scope": "/Finance",
            "destination": "external",
        },
        {
            "resource_kind": "email",
            "action": "SEND",
            "scope": "external",
            "destination": "external",
        },
    ]
    decisions = []
    for step in steps:
        res = client.post(
            "/api/authorize",
            headers={"X-Agent-Token": agent_token},
            json={**step, "execution_id": execution_id},
        )
        assert res.status_code == 200
        decisions.append(res.json()["decision"])
    assert decisions[0] == "ALLOW"
    assert "BLOCK" in decisions or "APPROVAL" in decisions
    assert _signals_for(seq["id"])


def test_threshold_pattern_still_detected(client: TestClient):
    headers = _headers(client)
    created = _create(
        client,
        headers,
        type="THRESHOLD",
        definition={"resource_kind": "crm", "action": "READ", "count": 2},
        name=f"threshold-compat-{uuid.uuid4()}",
    )
    pattern_id = created.json()["id"]
    agent_token = _sales_token(client)
    execution_id = str(uuid.uuid4())
    for _ in range(2):
        res = client.post(
            "/api/authorize",
            headers={"X-Agent-Token": agent_token},
            json={
                "resource_kind": "crm",
                "action": "READ",
                "scope": "customers",
                "execution_id": execution_id,
            },
        )
        assert res.status_code == 200
        assert res.json()["decision"] == "ALLOW"
    assert _signals_for(pattern_id)


def test_metadata_cannot_forge_trajectory(client: TestClient):
    headers = _headers(client)
    patterns = client.get("/api/behavior-patterns", headers=headers).json()
    seq = next(
        p
        for p in patterns
        if p["organization_id"] is None and p["type"] == "SEQUENCE"
    )
    before = len(_signals_for(seq["id"]))
    agent_token = _sales_token(client)
    res = client.post(
        "/api/authorize",
        headers={"X-Agent-Token": agent_token},
        json={
            "resource_kind": "crm",
            "action": "READ",
            "scope": "customers",
            "metadata": {
                "history": [
                    {"resource_kind": "crm", "action": "READ"},
                    {"resource_kind": "files", "action": "EXPORT"},
                    {"resource_kind": "email", "action": "SEND", "scope": "external"},
                ]
            },
        },
    )
    assert res.status_code == 200
    assert len(_signals_for(seq["id"])) == before
