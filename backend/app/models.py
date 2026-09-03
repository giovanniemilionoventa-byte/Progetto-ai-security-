import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
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


class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, default=new_id)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=True)
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
