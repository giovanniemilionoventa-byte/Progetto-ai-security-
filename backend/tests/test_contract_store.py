from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import models
from app.contract_store import (
    ContractResolutionError,
    ContractStoreError,
    contract_exists,
    get_contract,
    get_contract_status,
    list_contract_versions,
    resolve_active_contract,
    resolve_active_contract_for_agent,
    save_contract,
    select_active_contract,
)
from app.database import Base
from app.engines.behavior import TrajectoryStep, reconstruct_trajectory
from app.runtime_contract import (
    ContractWorkflowError,
    correlate_trajectory_with_workflow,
    load_contract_workflow,
)


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
    session.commit()
    return session


def _doc(**overrides):
    payload = {
        "organization_id": "org-1",
        "agent_id": "agent-1",
        "contract_id": "sales-contract",
        "version": 1,
        "status": "DRAFT",
        "purpose": "bounded sales access",
        "capabilities": [{"name": "crm.read", "actions": ["READ"]}],
        "resources": [{"kind": "crm", "scope": "customers"}],
    }
    payload.update(overrides)
    return payload


WORKFLOW = {
    "initial_steps": ["start"],
    "steps": [{"id": "start"}, {"id": "end"}],
    "transitions": [{"from": "start", "to": "end"}],
    "terminal_steps": ["end"],
}


def test_create_and_read_contract():
    db = _db()
    saved = save_contract(db, _doc())
    db.commit()
    loaded = get_contract(db, "org-1", "agent-1", "sales-contract", 1)
    assert loaded.id == saved.id
    assert loaded.status == "DRAFT"
    assert loaded.capabilities[0]["name"] == "crm.read"
    assert contract_exists(db, "org-1", "agent-1", "sales-contract", 1)
    assert get_contract_status(db, "org-1", "agent-1", "sales-contract", 1) == {
        "status": "DRAFT",
        "version": 1,
    }


def test_multiple_versions():
    db = _db()
    save_contract(db, _doc(version=1, status="SUPERSEDED"))
    save_contract(db, _doc(version=2, status="ACTIVE"))
    db.commit()
    versions = list_contract_versions(db, "org-1", "agent-1", "sales-contract")
    assert [row.version for row in versions] == [1, 2]
    assert versions[0].status == "SUPERSEDED"
    assert versions[1].status == "ACTIVE"


def test_different_statuses():
    db = _db()
    save_contract(db, _doc(contract_id="c-a", version=1, status="DRAFT"))
    save_contract(db, _doc(contract_id="c-b", version=1, status="REVOKED"))
    save_contract(db, _doc(contract_id="c-c", version=1, status="EXPIRED"))
    db.commit()
    assert get_contract(db, "org-1", "agent-1", "c-a", 1).status == "DRAFT"
    assert get_contract(db, "org-1", "agent-1", "c-b", 1).status == "REVOKED"
    assert get_contract(db, "org-1", "agent-1", "c-c", 1).status == "EXPIRED"


def test_duplicate_identity_rejected():
    db = _db()
    save_contract(db, _doc(version=1, status="DRAFT"))
    db.commit()
    try:
        save_contract(db, _doc(version=1, status="DRAFT", purpose="again"))
        assert False
    except ContractStoreError as exc:
        assert exc.reason == "duplicate_identity"


def test_organization_isolation():
    db = _db()
    save_contract(db, _doc())
    save_contract(
        db,
        _doc(
            organization_id="org-2",
            agent_id="agent-3",
            contract_id="sales-contract",
            purpose="other org",
        ),
    )
    db.commit()
    try:
        get_contract(db, "org-2", "agent-1", "sales-contract", 1)
        assert False
    except ContractResolutionError as exc:
        assert exc.reason in {"organization_mismatch", "agent_mismatch"}
    try:
        get_contract(db, "org-1", "agent-3", "sales-contract", 1)
        assert False
    except ContractResolutionError as exc:
        assert exc.reason in {"organization_mismatch", "agent_mismatch"}
    acme = get_contract(db, "org-1", "agent-1", "sales-contract", 1)
    beta = get_contract(db, "org-2", "agent-3", "sales-contract", 1)
    assert acme.purpose == "bounded sales access"
    assert beta.purpose == "other org"


def test_resolve_active_contract():
    db = _db()
    save_contract(db, _doc(version=1, status="SUPERSEDED"))
    active = save_contract(db, _doc(version=2, status="ACTIVE"))
    db.commit()
    resolved = resolve_active_contract(db, "org-1", "agent-1")
    assert resolved.id == active.id
    assert resolved.version == 2
    agent = db.query(models.Agent).filter_by(id="agent-1").one()
    assert resolve_active_contract_for_agent(db, agent).id == active.id


def test_no_active_contract():
    db = _db()
    save_contract(db, _doc(status="DRAFT"))
    db.commit()
    try:
        resolve_active_contract(db, "org-1", "agent-1")
        assert False
    except ContractResolutionError as exc:
        assert exc.reason == "no_active_contract"


def test_contract_not_found():
    db = _db()
    try:
        resolve_active_contract(db, "org-1", "agent-1")
        assert False
    except ContractResolutionError as exc:
        assert exc.reason == "not_found"
    try:
        get_contract(db, "org-1", "agent-1", "missing", 1)
        assert False
    except ContractResolutionError as exc:
        assert exc.reason == "not_found"


def test_ambiguous_active_fail_closed():
    rows = [
        models.RuntimeContract(
            organization_id="org-1",
            agent_id="agent-1",
            contract_id="one",
            version=1,
            status="ACTIVE",
            purpose="",
            capabilities=[],
            resources=[],
            constraints={},
            data_constraints={},
            approval_rules=[],
        ),
        models.RuntimeContract(
            organization_id="org-1",
            agent_id="agent-1",
            contract_id="two",
            version=1,
            status="ACTIVE",
            purpose="",
            capabilities=[],
            resources=[],
            constraints={},
            data_constraints={},
            approval_rules=[],
        ),
    ]
    try:
        select_active_contract(rows, "org-1", "agent-1")
        assert False
    except ContractResolutionError as exc:
        assert exc.reason == "ambiguous_active_contract"


def test_second_active_save_rejected():
    db = _db()
    save_contract(db, _doc(contract_id="one", status="ACTIVE"))
    db.commit()
    try:
        save_contract(db, _doc(contract_id="two", status="ACTIVE"))
        assert False
    except ContractStoreError as exc:
        assert exc.reason == "active_contract_exists"


def test_organization_mismatch_resolution():
    db = _db()
    save_contract(db, _doc(status="ACTIVE"))
    db.commit()
    try:
        resolve_active_contract(db, "org-2", "agent-1")
        assert False
    except ContractResolutionError as exc:
        assert exc.reason in {"not_found", "organization_mismatch"}
    try:
        get_contract(db, "org-2", "agent-1", "sales-contract", 1)
        assert False
    except ContractResolutionError as exc:
        assert exc.reason == "organization_mismatch"


def test_agent_mismatch_resolution():
    db = _db()
    save_contract(db, _doc(status="ACTIVE"))
    db.commit()
    try:
        resolve_active_contract(db, "org-1", "agent-2")
        assert False
    except ContractResolutionError as exc:
        assert exc.reason == "not_found"
    try:
        get_contract(db, "org-1", "agent-2", "sales-contract", 1)
        assert False
    except ContractResolutionError as exc:
        assert exc.reason == "agent_mismatch"


def test_claimed_contract_id_cannot_select_another_contract():
    db = _db()
    save_contract(db, _doc(contract_id="owner-contract", status="ACTIVE"))
    save_contract(
        db,
        _doc(
            agent_id="agent-2",
            contract_id="other-agent-contract",
            status="ACTIVE",
        ),
    )
    db.commit()
    try:
        resolve_active_contract(
            db, "org-1", "agent-1", claimed_contract_id="other-agent-contract"
        )
        assert False
    except ContractResolutionError as exc:
        assert exc.reason == "untrusted_contract_id"
    trusted = resolve_active_contract(db, "org-1", "agent-1")
    assert trusted.contract_id == "owner-contract"
    matching = resolve_active_contract(
        db, "org-1", "agent-1", claimed_contract_id="owner-contract"
    )
    assert matching.contract_id == "owner-contract"


def test_workflow_valid_and_lookup():
    workflow = load_contract_workflow(WORKFLOW)
    assert workflow.is_initial("start")
    assert workflow.is_terminal("end")
    assert workflow.get_step("start")["id"] == "start"
    assert workflow.allows_transition("start", "end")
    assert workflow.allowed_targets("start") == ["end"]
    assert workflow.transitions_from("end") == []


def test_workflow_from_saved_contract():
    db = _db()
    row = save_contract(db, _doc(workflow=WORKFLOW, status="ACTIVE"))
    db.commit()
    workflow = load_contract_workflow(row)
    assert workflow.initial_steps == ["start"]
    assert workflow.terminal_steps == ["end"]
    assert workflow.get_step("end")["id"] == "end"


def test_invalid_transition_structure():
    try:
        load_contract_workflow(
            {
                "initial_steps": ["start"],
                "steps": [{"id": "start"}, {"id": "end"}],
                "transitions": [{"from": "start", "to": "ghost"}],
                "terminal_steps": ["end"],
            }
        )
        assert False
    except Exception:
        pass
    workflow = load_contract_workflow(WORKFLOW)
    assert not workflow.allows_transition("end", "start")
    try:
        workflow.get_step("ghost")
        assert False
    except ContractWorkflowError as exc:
        assert exc.detail == "unknown_step"


def test_contract_without_workflow():
    db = _db()
    row = save_contract(db, _doc())
    db.commit()
    assert load_contract_workflow(row) is None
    assert load_contract_workflow(None) is None


def test_trajectory_remains_separate_from_workflow():
    db = _db()
    save_contract(db, _doc(workflow=WORKFLOW, status="ACTIVE"))
    execution = models.Execution(id="exec-1", organization_id="org-1", agent_id="agent-1")
    db.add(execution)
    db.flush()
    db.add(
        models.Event(
            organization_id="org-1",
            agent_id="agent-1",
            execution_id="exec-1",
            seq=1,
            resource_kind="crm",
            action="READ",
            scope="customers",
            decision="ALLOW",
            request_id="req-1",
        )
    )
    db.commit()
    trajectory = reconstruct_trajectory(db, "exec-1")
    assert trajectory == [
        TrajectoryStep(resource_kind="crm", action="READ", scope="customers")
    ]
    workflow = load_contract_workflow(WORKFLOW)
    correlation = correlate_trajectory_with_workflow(workflow, trajectory)
    assert correlation["has_workflow"] is True
    assert correlation["trajectory_length"] == 1
    assert correlation["initial_steps"] == ["start"]
    contract = resolve_active_contract(db, "org-1", "agent-1")
    assert contract.workflow["initial_steps"] == ["start"]
    assert trajectory[0].resource_kind == "crm"
