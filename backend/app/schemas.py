from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    organization_name: str
    full_name: str
    email: str
    password: str


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    organization_id: str

    class Config:
        from_attributes = True


class OrganizationOut(BaseModel):
    id: str
    name: str
    slug: str
    created_at: datetime

    class Config:
        from_attributes = True


class MeResponse(BaseModel):
    user: UserOut
    organization: OrganizationOut


class AgentCreate(BaseModel):
    name: str
    provider: str = "demo"
    model: str = "local-demo"
    description: str = ""


class AgentOut(BaseModel):
    id: str
    name: str
    provider: str
    model: str
    status: str
    description: str
    owner_id: str
    organization_id: str
    created_at: datetime
    revoked_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AgentCredentialOut(BaseModel):
    agent: AgentOut
    token: str
    token_prefix: str
    expires_at: Optional[datetime] = None


class PermissionCreate(BaseModel):
    resource_kind: str
    action: str
    scope: str = "*"
    effect: str = "allow"


class PermissionOut(BaseModel):
    id: str
    agent_id: str
    resource_kind: str
    action: str
    scope: str
    effect: str

    class Config:
        from_attributes = True


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    resource_kind: str
    action: str
    scope_pattern: str = "*"
    destination_pattern: Optional[str] = None
    decision: str
    priority: int = 100
    enabled: bool = True


class PolicyOut(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str
    resource_kind: str
    action: str
    scope_pattern: str
    destination_pattern: Optional[str] = None
    decision: str
    priority: int
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ResourceCreate(BaseModel):
    kind: str
    name: str
    identifier: str
    sensitivity: str = "internal"


class ResourceOut(BaseModel):
    id: str
    organization_id: str
    kind: str
    name: str
    identifier: str
    sensitivity: str

    class Config:
        from_attributes = True


class DeviceOut(BaseModel):
    id: str
    hostname: str
    platform: str
    status: str
    last_seen: datetime

    class Config:
        from_attributes = True


class AuthorizeRequest(BaseModel):
    resource_kind: str = Field(..., examples=["email", "files", "crm", "payments"])
    action: str = Field(..., examples=["READ", "SEND", "EXPORT", "DELETE", "TRANSFER"])
    scope: str = Field(..., examples=["customers", "/Sales", "external"])
    destination: Optional[str] = None
    metadata: Optional[dict] = None


class AuthorizeResponse(BaseModel):
    request_id: str
    decision: str
    risk_score: float
    risk_level: str
    reason: str
    approval_id: Optional[str] = None
    agent_id: str
    organization_id: str


class EventOut(BaseModel):
    id: str
    organization_id: str
    agent_id: Optional[str]
    resource_kind: str
    action: str
    scope: str
    destination: Optional[str]
    decision: str
    risk_score: float
    risk_level: str
    reason: str
    request_id: str
    created_at: datetime

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    id: str
    severity: str
    title: str
    message: str
    status: str
    event_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ApprovalOut(BaseModel):
    id: str
    agent_id: str
    resource_kind: str
    action: str
    scope: str
    destination: Optional[str]
    status: str
    reason: str
    reviewed_by: Optional[str]
    created_at: datetime
    reviewed_at: Optional[datetime]

    class Config:
        from_attributes = True


class ApprovalDecision(BaseModel):
    decision: str


class DashboardStats(BaseModel):
    agents: int
    events: int
    blocked: int
    pending_approvals: int
    open_alerts: int
    allow_rate: float
