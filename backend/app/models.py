import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import relationship

from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


def new_id():
    return str(uuid.uuid4())


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=new_id)
    name = Column(String, nullable=False)
    slug = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=utcnow)

    users = relationship("User", back_populates="organization")
    agents = relationship("Agent", back_populates="organization")
    devices = relationship("Device", back_populates="organization")
    resources = relationship("Resource", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")
    events = relationship("Event", back_populates="organization")
    alerts = relationship("Alert", back_populates="organization")
    approvals = relationship("Approval", back_populates="organization")
    executions = relationship("Execution", back_populates="organization")
    behavior_patterns = relationship("BehaviorPattern", back_populates="organization")
    behavior_signals = relationship("BehaviorSignal", back_populates="organization")
    runtime_contracts = relationship("RuntimeContract", back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    role = Column(String, nullable=False, default="admin")
    created_at = Column(DateTime, default=utcnow)

    organization = relationship("Organization", back_populates="users")
    owned_agents = relationship("Agent", back_populates="owner")


class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    hostname = Column(String, nullable=False)
    platform = Column(String, nullable=False, default="linux")
    status = Column(String, nullable=False, default="online")
    last_seen = Column(DateTime, default=utcnow)
    created_at = Column(DateTime, default=utcnow)

    organization = relationship("Organization", back_populates="devices")


class Agent(Base):
    __tablename__ = "agents"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    provider = Column(String, nullable=False, default="demo")
    model = Column(String, nullable=False, default="local-demo")
    status = Column(String, nullable=False, default="active")
    description = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)
    revoked_at = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="agents")
    owner = relationship("User", back_populates="owned_agents")
    credentials = relationship("Credential", back_populates="agent")
    permissions = relationship("Permission", back_populates="agent")
    runtime_contracts = relationship("RuntimeContract", back_populates="agent")


class Credential(Base):
    __tablename__ = "credentials"

    id = Column(String, primary_key=True, default=new_id)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    token_prefix = Column(String, nullable=False)
    status = Column(String, nullable=False, default="active")
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    revoked_at = Column(DateTime, nullable=True)

    agent = relationship("Agent", back_populates="credentials")


class Resource(Base):
    __tablename__ = "resources"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    kind = Column(String, nullable=False)
    name = Column(String, nullable=False)
    identifier = Column(String, nullable=False)
    sensitivity = Column(String, nullable=False, default="internal")
    created_at = Column(DateTime, default=utcnow)

    organization = relationship("Organization", back_populates="resources")


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(String, primary_key=True, default=new_id)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    resource_kind = Column(String, nullable=False)
    action = Column(String, nullable=False)
    scope = Column(String, nullable=False, default="*")
    effect = Column(String, nullable=False, default="allow")
    created_at = Column(DateTime, default=utcnow)

    agent = relationship("Agent", back_populates="permissions")

    __table_args__ = (
        UniqueConstraint(
            "agent_id", "resource_kind", "action", "scope", name="uq_agent_perm"
        ),
    )


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    resource_kind = Column(String, nullable=False)
    action = Column(String, nullable=False)
    scope_pattern = Column(String, nullable=False, default="*")
    destination_pattern = Column(String, nullable=True)
    decision = Column(String, nullable=False)
    priority = Column(Integer, nullable=False, default=100)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=utcnow)

    organization = relationship("Organization", back_populates="policies")


class Execution(Base):
    __tablename__ = "executions"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow)

    organization = relationship("Organization", back_populates="executions")
    events = relationship("Event", back_populates="execution")
    behavior_signals = relationship("BehaviorSignal", back_populates="execution")


class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=True)
    execution_id = Column(String, ForeignKey("executions.id"), nullable=True, index=True)
    seq = Column(Integer, nullable=False, default=0)
    resource_kind = Column(String, nullable=False)
    action = Column(String, nullable=False)
    scope = Column(String, nullable=False)
    destination = Column(String, nullable=True)
    decision = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String, nullable=False, default="low")
    reason = Column(Text, default="")
    request_id = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow)

    organization = relationship("Organization", back_populates="events")
    execution = relationship("Execution", back_populates="events")
    behavior_signals = relationship("BehaviorSignal", back_populates="event")


class BehaviorPattern(Base):
    __tablename__ = "behavior_patterns"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    type = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="medium")
    definition = Column(JSON, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    organization = relationship("Organization", back_populates="behavior_patterns")
    signals = relationship("BehaviorSignal", back_populates="pattern")


class BehaviorSignal(Base):
    __tablename__ = "behavior_signals"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    execution_id = Column(String, ForeignKey("executions.id"), nullable=True)
    event_id = Column(String, ForeignKey("events.id"), nullable=True)
    pattern_id = Column(String, ForeignKey("behavior_patterns.id"), nullable=False)
    severity = Column(String, nullable=False, default="medium")
    title = Column(String, nullable=False)
    message = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)

    organization = relationship("Organization", back_populates="behavior_signals")
    execution = relationship("Execution", back_populates="behavior_signals")
    event = relationship("Event", back_populates="behavior_signals")
    pattern = relationship("BehaviorPattern", back_populates="signals")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    event_id = Column(String, ForeignKey("events.id"), nullable=True)
    severity = Column(String, nullable=False, default="medium")
    title = Column(String, nullable=False)
    message = Column(Text, default="")
    status = Column(String, nullable=False, default="open")
    created_at = Column(DateTime, default=utcnow)

    organization = relationship("Organization", back_populates="alerts")


class Approval(Base):
    __tablename__ = "approvals"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    event_id = Column(String, ForeignKey("events.id"), nullable=True)
    resource_kind = Column(String, nullable=False)
    action = Column(String, nullable=False)
    scope = Column(String, nullable=False)
    destination = Column(String, nullable=True)
    status = Column(String, nullable=False, default="pending")
    reason = Column(Text, default="")
    reviewed_by = Column(String, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow)
    reviewed_at = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="approvals")


class RuntimeContract(Base):
    __tablename__ = "runtime_contracts"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)
    contract_id = Column(String, nullable=False, index=True)
    version = Column(Integer, nullable=False)
    status = Column(String, nullable=False, default="DRAFT")
    purpose = Column(Text, default="")
    capabilities = Column(JSON, nullable=False)
    resources = Column(JSON, nullable=False)
    constraints = Column(JSON, nullable=False)
    data_constraints = Column(JSON, nullable=False)
    workflow = Column(JSON, nullable=True)
    approval_rules = Column(JSON, nullable=False)
    valid_from = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    integrity = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    organization = relationship("Organization", back_populates="runtime_contracts")
    agent = relationship("Agent", back_populates="runtime_contracts")

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "agent_id",
            "contract_id",
            "version",
            name="uq_runtime_contract_identity",
        ),
        Index(
            "uq_runtime_contract_one_active_per_agent",
            "organization_id",
            "agent_id",
            unique=True,
            sqlite_where=text("status = 'ACTIVE'"),
            postgresql_where=text("status = 'ACTIVE'"),
        ),
    )
