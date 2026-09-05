from uuid import uuid4

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import models, schemas
from app.contract_store import save_contract
from app.database import Base
from app.eat import EatError, param_hash, sign_claims, sign_eat, verify_eat
from app.engines.enforcement import authorize_request
from app.engines.behavior import TrajectoryStep
from app.engines.contract import evaluate_contract


def _engine():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _fk(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    return engine


def _db():
    session = sessionmaker(bind=_engine())()
    session.add(models.Organization(id="org-1", name="Acme", slug="acme"))
    session.add(models.Organization(id="org-2", name="Beta", slug="beta"))
    session.flush()
    session.add(
        models.User(
            id="user-1",
            organization_id="org-1",
            email="a@acme.test",
            password_hash="x",
            full_name="Ada",
        )
    )
    session.add(
        models.User(
            id="user-2",
            organization_id="org-2",
            email="b@beta.test",
            password_hash="x",
            full_name="Bea",
        )
    )
    session.flush()
    session.add(
        models.Agent(
            id="agent-1",
            organization_id="org-1",
            owner_id="user-1",
            name="Sales",
        )
    )
    session.add(
        models.Agent(
            id="agent-2",
            organization_id="org-1",
            owner_id="user-1",
            name="Support",
        )
    )
    session.add(
        models.Agent(
            id="agent-3",
            organization_id="org-2",
            owner_id="user-2",
            name="Other",
        )
    )
    session.flush()
    for kind, action, scope in [
        ("crm", "READ", "customers"),
        ("crm", "DELETE", "*"),
        ("email", "SEND", "internal"),
        ("email", "SEND", "external"),
        ("files", "READ", "/Sales"),
        ("files", "EXPORT", "/Finance"),
    ]:
        session.add(
            models.Permission(
                agent_id="agent-1",
                resource_kind=kind,
                action=action,
                scope=scope,
                effect="allow",
            )
        )
    session.commit()
    return session


def _agent(db, agent_id="agent-1"):
    return db.query(models.Agent).filter_by(id=agent_id).one()


def _contract(**overrides):
    payload = {
        "organization_id": "org-1",
        "agent_id": "agent-1",
        "contract_id": "sales-contract",
        "version": 1,
        "status": "ACTIVE",
        "purpose": "bounded sales access",
        "capabilities": [
            {"name": "crm.read", "actions": ["READ"]},
            {"name": "email.send", "actions": ["SEND"]},
        ],
        "resources": [
            {"kind": "crm", "scope": "customers"},
            {"kind": "email", "scope": "internal"},
        ],
        "constraints": {
            "destination_restrictions": {"allow": ["internal"], "deny": ["external"]},
            "payload_size": {"max_bytes": 256},
        },
        "data_constraints": {
            "allowed_fields": ["id", "name", "to"],
            "denied_fields": ["ssn", "secret"],
        },
        "workflow": {
            "initial_steps": ["read_crm"],
            "steps": [
                {"id": "read_crm", "resource_kind": "crm", "action": "READ"},
                {"id": "send_email", "resource_kind": "email", "action": "SEND"},
            ],
            "transitions": [{"from": "read_crm", "to": "send_email"}],
            "terminal_steps": ["send_email"],
        },
    }
    payload.update(overrides)
    return payload


def _authorize(db, agent, **body):
    request = {
        "resource_kind": "crm",
        "action": "READ",
        "scope": "customers",
        "request_id": str(uuid4()),
    }
    request.update(body)
    return authorize_request(db, agent, schemas.AuthorizeRequest(**request))


def test_no_contract_keeps_phase10_allow():
    db = _db()
    outcome = _authorize(db, _agent(db))
    assert outcome.event.decision == "ALLOW"
    assert outcome.contract_id is None


def test_resolve_active_contract_on_allow():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(db, _agent(db))
    assert outcome.event.decision == "ALLOW"
    assert outcome.contract_id == "sales-contract"
    assert outcome.contract_version == 1


def test_claimed_contract_id_mismatch_blocks():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(
        db,
        _agent(db),
        metadata={"contract_id": "other-contract", "purpose": "normal work email"},
    )
    assert outcome.event.decision == "BLOCK"
    assert "contract_id" in outcome.event.reason


def test_claimed_contract_without_active_blocks():
    db = _db()
    outcome = _authorize(
        db, _agent(db), metadata={"contract_id": "sales-contract"}
    )
    assert outcome.event.decision == "BLOCK"


def test_agent_mismatch_does_not_use_foreign_contract():
    db = _db()
    save_contract(db, _contract())
    db.add(
        models.Permission(
            agent_id="agent-2",
            resource_kind="crm",
            action="READ",
            scope="customers",
            effect="allow",
        )
    )
    db.commit()
    agent = _agent(db, "agent-2")
    allowed = _authorize(db, agent)
    assert allowed.event.decision == "ALLOW"
    assert allowed.contract_id is None
    blocked = _authorize(
        db, agent, metadata={"contract_id": "sales-contract"}
    )
    assert blocked.event.decision == "BLOCK"


def test_organization_mismatch_does_not_use_foreign_contract():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(db, _agent(db, "agent-3"))
    assert outcome.event.decision == "BLOCK"


def test_capability_allowed_continues():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(db, _agent(db))
    assert outcome.event.decision == "ALLOW"


def test_capability_denied_and_privilege_escalation_block():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(
        db, _agent(db), resource_kind="crm", action="DELETE", scope="all"
    )
    assert outcome.event.decision == "BLOCK"
    assert "capability" in outcome.event.reason.lower()


def test_resource_allowed_and_out_of_scope_block():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    allowed = _authorize(db, _agent(db), resource_kind="crm", action="READ", scope="customers")
    assert allowed.event.decision == "ALLOW"
    blocked = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="external",
        destination="external",
        execution_id=allowed.event.execution_id,
    )
    assert blocked.event.decision == "BLOCK"
    assert "resource" in blocked.event.reason.lower() or "destination" in blocked.event.reason.lower()


def test_constraint_respected_and_violated():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    first = _authorize(db, _agent(db))
    assert first.event.decision == "ALLOW"
    ok = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1", "to": "ada@acme.test"},
        execution_id=first.event.execution_id,
    )
    assert ok.event.decision == "ALLOW"
    denied = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="external",
        payload={"id": "1", "to": "ada@acme.test"},
    )
    assert denied.event.decision == "BLOCK"


def test_payload_size_and_denied_fields_block():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    first = _authorize(db, _agent(db))
    oversized = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1", "name": "x" * 400},
        execution_id=first.event.execution_id,
    )
    assert oversized.event.decision == "BLOCK"
    secret = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1", "ssn": "000"},
    )
    assert secret.event.decision == "BLOCK"


def test_unevaluable_constraint_fail_closed():
    db = _db()
    save_contract(
        db,
        _contract(
            constraints={
                "destination_restrictions": {"allow": ["internal"]},
                "semantic_class": "pii",
            }
        ),
    )
    db.commit()
    outcome = _authorize(db, _agent(db))
    assert outcome.event.decision == "BLOCK"
    assert "cannot be verified" in outcome.event.reason


def test_workflow_valid_then_skip_blocks():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    first = _authorize(db, _agent(db), execution_id="exec-wf")
    assert first.event.decision == "ALLOW"
    skip = _authorize(
        db,
        _agent(db),
        resource_kind="files",
        action="READ",
        scope="/Sales",
        execution_id="exec-skip",
    )
    assert skip.event.decision == "BLOCK"
    jump = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1"},
        execution_id="exec-skip-start",
    )
    assert jump.event.decision == "BLOCK"
    nxt = _authorize(
        db,
        _agent(db),
        resource_kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1"},
        execution_id="exec-wf",
    )
    assert nxt.event.decision == "ALLOW"


def test_declared_workflow_and_purpose_are_ignored():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(
        db,
        _agent(db),
        resource_kind="crm",
        action="DELETE",
        scope="all",
        metadata={
            "purpose": "send a normal work email",
            "capability": "email.send",
            "contract_id": "sales-contract",
            "workflow": {"initial_steps": ["delete"], "steps": [{"id": "delete"}]},
        },
    )
    assert outcome.event.decision == "BLOCK"


def test_false_capability_declaration_cannot_escalate():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(
        db,
        _agent(db),
        resource_kind="files",
        action="EXPORT",
        scope="/Finance",
        destination="external",
        metadata={"capability": "files.export", "purpose": "finance report"},
    )
    assert outcome.event.decision == "BLOCK"


def test_evaluate_contract_uses_server_trajectory_not_declaration():
    db = _db()
    row = save_contract(db, _contract())
    db.commit()
    current = TrajectoryStep("email", "SEND", "internal", "internal")
    verdict = evaluate_contract(
        row,
        kind="email",
        action="SEND",
        scope="internal",
        destination="internal",
        payload={"id": "1"},
        previous=[],
        current=current,
    )
    assert verdict.allowed is False


def test_allow_eat_binds_resolved_contract():
    db = _db()
    save_contract(db, _contract())
    db.commit()
    outcome = _authorize(db, _agent(db))
    assert outcome.event.decision == "ALLOW"
    token = sign_eat(
        org_id="org-1",
        agent_id="agent-1",
        execution_id=outcome.event.execution_id,
        request_id=outcome.event.request_id,
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={},
        contract_id=outcome.contract_id,
        contract_version=outcome.contract_version,
        now=1_700_000_000,
        jti="jti-allow",
    )
    claims = verify_eat(token, now=1_700_000_000)
    assert claims["contract_id"] == "sales-contract"
    assert claims["contract_version"] == 1
    assert claims["param_hash"] == param_hash("customers", None, {})
    assert claims["execution_id"] == outcome.event.execution_id


def test_block_and_approval_do_not_issue_eat_binding():
    db = _db()
    save_contract(db, _contract())
    db.add(
        models.Policy(
            organization_id="org-1",
            name="external-email",
            resource_kind="email",
            action="SEND",
            scope_pattern="external",
            destination_pattern="external",
            decision="APPROVAL",
            priority=10,
        )
    )
    db.commit()
    blocked = _authorize(
        db, _agent(db), resource_kind="crm", action="DELETE", scope="all"
    )
    assert blocked.event.decision == "BLOCK"
    assert blocked.event.decision != "ALLOW"
    db2 = _db()
    db2.add(
        models.Policy(
            organization_id="org-1",
            name="external-email",
            resource_kind="email",
            action="SEND",
            scope_pattern="external",
            destination_pattern="external",
            decision="APPROVAL",
            priority=10,
        )
    )
    db2.commit()
    approved = _authorize(
        db2,
        _agent(db2),
        resource_kind="email",
        action="SEND",
        scope="external",
        destination="external",
    )
    assert approved.event.decision == "APPROVAL"
    assert approved.contract_id is None


def test_eat_contract_tampering_rejected():
    token = sign_eat(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-1",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={},
        contract_id="sales-contract",
        contract_version=1,
        now=1_700_000_000,
        jti="jti-tamper",
    )
    body, _sig = token.split(".", 1)
    try:
        verify_eat(body + ".AAAA", now=1_700_000_000)
        assert False
    except EatError as exc:
        assert exc.reason == "bad_signature"
    claims = verify_eat(token, now=1_700_000_000)
    claims["contract_id"] = "other-contract"
    resigned = sign_claims(claims)
    verified = verify_eat(resigned, now=1_700_000_000)
    assert verified["contract_id"] != "sales-contract"
    assert verified["contract_id"] == "other-contract"
    claims = verify_eat(token, now=1_700_000_000)
    claims["contract_version"] = 9
    verified = verify_eat(sign_claims(claims), now=1_700_000_000)
    assert verified["contract_version"] != 1


def test_eat_missing_and_invalid_contract_claims():
    base = dict(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-1",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={},
        contract_id="sales-contract",
        contract_version=1,
        now=1_700_000_000,
        jti="jti-missing",
    )
    claims = verify_eat(sign_eat(**base), now=1_700_000_000)
    del claims["contract_id"]
    try:
        verify_eat(sign_claims(claims), now=1_700_000_000)
        assert False
    except EatError as exc:
        assert exc.reason == "missing_claim"
    claims = verify_eat(sign_eat(**base), now=1_700_000_000)
    claims["contract_version"] = 99
    verified = verify_eat(sign_claims(claims), now=1_700_000_000)
    assert verified["contract_version"] == 99
    claims = verify_eat(sign_eat(**base), now=1_700_000_000)
    del claims["contract_version"]
    try:
        verify_eat(sign_claims(claims), now=1_700_000_000)
        assert False
    except EatError as exc:
        assert exc.reason == "missing_claim"
    claims = verify_eat(sign_eat(**base), now=1_700_000_000)
    claims["contract_id"] = ""
    try:
        verify_eat(sign_claims(claims), now=1_700_000_000)
        assert False
    except EatError as exc:
        assert exc.reason == "missing_claim"


def test_eat_param_hash_and_execution_still_required():
    token = sign_eat(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-1",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={"id": "1"},
        contract_id="sales-contract",
        contract_version=1,
        now=1_700_000_000,
        jti="jti-hash",
    )
    claims = verify_eat(token, now=1_700_000_000)
    assert claims["param_hash"] == param_hash("customers", None, {"id": "1"})
    assert claims["execution_id"] == "exec-1"
    claims["param_hash"] = param_hash("customers", None, {"id": "2"})
    verified = verify_eat(sign_claims(claims), now=1_700_000_000)
    assert verified["param_hash"] != param_hash("customers", None, {"id": "1"})
    claims = verify_eat(token, now=1_700_000_000)
    del claims["execution_id"]
    try:
        verify_eat(sign_claims(claims), now=1_700_000_000)
        assert False
    except EatError as exc:
        assert exc.reason == "missing_claim"


def test_eat_version_is_frozen_at_issue_time():
    token = sign_eat(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-1",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={},
        contract_id="sales-contract",
        contract_version=1,
        now=1_700_000_000,
        jti="jti-frozen",
    )
    claims = verify_eat(token, now=1_700_000_000)
    assert claims["contract_version"] == 1
    later = sign_eat(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-2",
        request_id="req-2",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={},
        contract_id="sales-contract",
        contract_version=2,
        now=1_700_000_000,
        jti="jti-later",
    )
    later_claims = verify_eat(later, now=1_700_000_000)
    assert later_claims["contract_version"] == 2
    assert claims["contract_version"] == 1
