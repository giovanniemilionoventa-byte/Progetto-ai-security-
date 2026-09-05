from datetime import datetime, timezone

from app.models import RuntimeContract
from app.runtime_contract import (
    CONTRACT_STATUSES,
    ContractValidationError,
    validate_runtime_contract,
)


def _ids(**overrides):
    payload = {
        "organization_id": "org-1",
        "agent_id": "agent-1",
        "contract_id": "contract-1",
        "version": 1,
    }
    payload.update(overrides)
    return payload


def _validate(payload):
    return validate_runtime_contract(payload)


def test_minimal_valid_contract():
    result = _validate(_ids())
    assert result["organization_id"] == "org-1"
    assert result["agent_id"] == "agent-1"
    assert result["contract_id"] == "contract-1"
    assert result["version"] == 1
    assert result["status"] == "DRAFT"
    assert result["purpose"] == ""
    assert result["capabilities"] == []
    assert result["resources"] == []
    assert result["constraints"] == {}
    assert result["data_constraints"] == {}
    assert result["workflow"] is None
    assert result["approval_rules"] == []
    assert result["valid_from"] is None
    assert result["expires_at"] is None
    assert result["integrity"] is None


def test_complete_valid_contract():
    payload = _ids(
        status="ACTIVE",
        purpose="Sales copilot bounded access",
        capabilities=[{"name": "crm.read", "actions": ["read"], "description": "Read CRM"}],
        resources=[{"kind": "CRM", "name": "Customers", "scope": "customers", "sensitivity": "internal"}],
        constraints={
            "destination_restrictions": {"allow": ["internal"], "deny": ["external"]},
            "operation_limits": {"max_calls": 10, "window_seconds": 60},
            "payload_size": {"max_bytes": 4096},
            "custom_limit": "future-extension",
        },
        data_constraints={
            "allowed_fields": ["id", "name"],
            "denied_fields": ["ssn"],
        },
        workflow={
            "initial_steps": ["start"],
            "steps": [{"id": "start", "name": "Begin"}, {"id": "end", "name": "Done"}],
            "transitions": [{"from": "start", "to": "end"}],
            "terminal_steps": ["end"],
        },
        approval_rules=[
            {
                "resource_kind": "email",
                "action": "send",
                "require": "human",
                "decision": "approval",
            }
        ],
        valid_from="2026-01-01T00:00:00Z",
        expires_at="2026-12-31T23:59:59Z",
        integrity={
            "algorithm": "sha256",
            "digest": "abc123",
            "signature": "sig-1",
            "key_id": "owner-key",
            "signed_at": "2026-01-01T00:00:00Z",
        },
    )
    result = _validate(payload)
    assert result["status"] == "ACTIVE"
    assert result["purpose"] == "Sales copilot bounded access"
    assert result["capabilities"][0]["name"] == "crm.read"
    assert result["capabilities"][0]["actions"] == ["READ"]
    assert result["resources"][0]["kind"] == "crm"
    assert result["constraints"]["destination_restrictions"]["deny"] == ["external"]
    assert result["constraints"]["operation_limits"]["max_calls"] == 10
    assert result["constraints"]["payload_size"]["max_bytes"] == 4096
    assert result["constraints"]["custom_limit"] == "future-extension"
    assert result["data_constraints"]["allowed_fields"] == ["id", "name"]
    assert result["workflow"]["initial_steps"] == ["start"]
    assert result["workflow"]["terminal_steps"] == ["end"]
    assert result["approval_rules"][0]["action"] == "SEND"
    assert result["approval_rules"][0]["decision"] == "APPROVAL"
    assert result["valid_from"] == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert result["expires_at"] == datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert result["integrity"]["algorithm"] == "sha256"
    assert result["integrity"]["digest"] == "abc123"


def test_capabilities_resources_constraints():
    result = _validate(
        _ids(
            capabilities=[
                {"name": "email.send", "actions": ["SEND"]},
                {"name": "files.read"},
            ],
            resources=[
                {"kind": "email", "identifier": "mailbox-1", "scope": "internal"},
                {"kind": "files", "scope": "/Sales"},
            ],
            constraints={
                "destination_restrictions": {"allow": ["internal"]},
                "payload_size": 1024,
            },
            data_constraints={"denied_fields": ["secret"]},
        )
    )
    assert [item["name"] for item in result["capabilities"]] == ["email.send", "files.read"]
    assert result["resources"][0]["kind"] == "email"
    assert result["resources"][1]["scope"] == "/Sales"
    assert result["constraints"]["payload_size"]["max_bytes"] == 1024
    assert result["data_constraints"]["denied_fields"] == ["secret"]


def test_valid_workflow():
    result = _validate(
        _ids(
            workflow={
                "initial_steps": ["a"],
                "steps": [{"id": "a"}, {"id": "b"}, {"id": "c"}],
                "transitions": [{"from": "a", "to": "b"}, {"from": "b", "to": "c"}],
                "terminal_steps": ["c"],
            }
        )
    )
    assert len(result["workflow"]["steps"]) == 3
    assert result["workflow"]["transitions"][0]["from"] == "a"
    assert result["workflow"]["terminal_steps"] == ["c"]


def test_approval_rules():
    result = _validate(
        _ids(
            approval_rules=[
                {"action": "DELETE", "require": "owner"},
                {"resource_kind": "payments", "decision": "BLOCK"},
            ]
        )
    )
    assert result["approval_rules"][0]["action"] == "DELETE"
    assert result["approval_rules"][1]["resource_kind"] == "payments"


def test_temporal_validity():
    result = _validate(
        _ids(
            valid_from="2026-03-01T12:00:00+00:00",
            expires_at="2026-03-02T12:00:00+00:00",
        )
    )
    assert result["valid_from"] < result["expires_at"]


def test_version_and_status():
    for status in CONTRACT_STATUSES:
        result = _validate(_ids(status=status.lower(), version=3))
        assert result["status"] == status
        assert result["version"] == 3


def test_missing_required_identifiers():
    for field in ("organization_id", "agent_id", "contract_id", "version"):
        payload = _ids()
        del payload[field]
        try:
            _validate(payload)
            assert False, field
        except ContractValidationError as exc:
            assert "required identifiers are missing" in exc.detail


def test_empty_identifiers_rejected():
    for field in ("organization_id", "agent_id", "contract_id"):
        try:
            _validate(_ids(**{field: "  "}))
            assert False, field
        except ContractValidationError:
            pass


def test_invalid_version():
    for version in (0, -1, 1.5, "1", True, None):
        try:
            _validate(_ids(version=version))
            assert False, version
        except ContractValidationError as exc:
            assert "version" in exc.detail.lower() or "required identifiers" in exc.detail


def test_invalid_status():
    for status in ("UNKNOWN", "PENDING", "", 1):
        try:
            _validate(_ids(status=status))
            assert False, status
        except ContractValidationError as exc:
            assert "status" in exc.detail.lower()


def test_wrong_types():
    try:
        _validate("not-an-object")
        assert False
    except ContractValidationError as exc:
        assert "object" in exc.detail
    try:
        _validate(_ids(capabilities="crm"))
        assert False
    except ContractValidationError as exc:
        assert "capabilities" in exc.detail
    try:
        _validate(_ids(resources={"kind": "crm"}))
        assert False
    except ContractValidationError as exc:
        assert "resources" in exc.detail
    try:
        _validate(_ids(constraints=[]))
        assert False
    except ContractValidationError as exc:
        assert "constraints" in exc.detail
    try:
        _validate(_ids(data_constraints=["ssn"]))
        assert False
    except ContractValidationError as exc:
        assert "data_constraints" in exc.detail
    try:
        _validate(_ids(approval_rules={"action": "SEND"}))
        assert False
    except ContractValidationError as exc:
        assert "approval_rules" in exc.detail
    try:
        _validate(_ids(capabilities=None))
        assert False
    except ContractValidationError:
        pass


def test_malformed_workflow():
    cases = [
        {"steps": [{"id": "a"}]},
        {
            "initial_steps": ["a"],
            "steps": [],
            "transitions": [],
            "terminal_steps": ["a"],
        },
        {
            "initial_steps": ["missing"],
            "steps": [{"id": "a"}],
            "transitions": [],
            "terminal_steps": ["a"],
        },
        {
            "initial_steps": ["a"],
            "steps": [{"id": "a"}, {"id": "a"}],
            "transitions": [],
            "terminal_steps": ["a"],
        },
        {
            "initial_steps": ["a"],
            "steps": [{"id": "a"}, {"id": "b"}],
            "transitions": [{"from": "a"}],
            "terminal_steps": ["b"],
        },
        {
            "initial_steps": ["a"],
            "steps": [{"id": "a"}, {"id": "b"}],
            "transitions": [{"from": "a", "to": "ghost"}],
            "terminal_steps": ["b"],
        },
        {
            "initial_steps": ["a"],
            "steps": [{"id": "a"}],
            "transitions": [],
            "terminal_steps": ["a"],
            "loops": True,
        },
        {
            "initial_steps": [],
            "steps": [{"id": "a"}],
            "transitions": [],
            "terminal_steps": ["a"],
        },
    ]
    for workflow in cases:
        try:
            _validate(_ids(workflow=workflow))
            assert False, workflow
        except ContractValidationError:
            pass


def test_incoherent_timestamps():
    try:
        _validate(
            _ids(
                valid_from="2026-05-02T00:00:00Z",
                expires_at="2026-05-01T00:00:00Z",
            )
        )
        assert False
    except ContractValidationError as exc:
        assert "valid_from" in exc.detail
    try:
        _validate(_ids(valid_from="not-a-date"))
        assert False
    except ContractValidationError as ext:
        assert "timestamp" in ext.detail
    try:
        _validate(
            _ids(
                valid_from="2026-05-01T00:00:00Z",
                expires_at="2026-05-01T00:00:00Z",
            )
        )
        assert False
    except ContractValidationError:
        pass


def test_structurally_invalid_contract():
    try:
        _validate(_ids(unknown_field=True))
        assert False
    except ContractValidationError as exc:
        assert "unsupported" in exc.detail
    try:
        _validate(_ids(integrity="hmac"))
        assert False
    except ContractValidationError:
        pass
    try:
        _validate(_ids(integrity={"algorithm": "sha256"}))
        assert False
    except ContractValidationError as exc:
        assert "integrity" in exc.detail
    try:
        _validate(_ids(capabilities=[{"actions": ["READ"]}]))
        assert False
    except ContractValidationError:
        pass
    try:
        _validate(_ids(resources=[{"name": "customers"}]))
        assert False
    except ContractValidationError:
        pass
    try:
        _validate(_ids(approval_rules=[{}]))
        assert False
    except ContractValidationError:
        pass


def test_capability_is_not_resource_or_workflow():
    result = _validate(
        _ids(
            capabilities=[{"name": "crm.read"}],
            resources=[{"kind": "crm"}],
            workflow={
                "initial_steps": ["read"],
                "steps": [{"id": "read"}],
                "transitions": [],
                "terminal_steps": ["read"],
            },
        )
    )
    assert result["capabilities"][0]["name"] != result["resources"][0]["kind"]
    assert "capabilities" not in result["workflow"]
    assert "resources" not in result["workflow"]


def test_orm_model_accepts_validated_contract():
    validated = _validate(
        _ids(
            status="ACTIVE",
            purpose="bounded sales access",
            capabilities=[{"name": "crm.read"}],
            resources=[{"kind": "crm"}],
            constraints={"payload_size": 2048},
            data_constraints={"allowed_fields": ["id"]},
            approval_rules=[{"action": "SEND", "require": "human"}],
            valid_from="2026-01-01T00:00:00Z",
            expires_at="2026-06-01T00:00:00Z",
            integrity={"algorithm": "sha256", "digest": "deadbeef"},
        )
    )
    row = RuntimeContract(
        organization_id=validated["organization_id"],
        agent_id=validated["agent_id"],
        contract_id=validated["contract_id"],
        version=validated["version"],
        status=validated["status"],
        purpose=validated["purpose"],
        capabilities=validated["capabilities"],
        resources=validated["resources"],
        constraints=validated["constraints"],
        data_constraints=validated["data_constraints"],
        workflow=validated["workflow"],
        approval_rules=validated["approval_rules"],
        valid_from=validated["valid_from"],
        expires_at=validated["expires_at"],
        integrity=validated["integrity"],
    )
    assert row.status == "ACTIVE"
    assert row.version == 1
    assert row.capabilities[0]["name"] == "crm.read"
    assert "uq_runtime_contract_identity" in RuntimeContract.__table_args__[0].name
