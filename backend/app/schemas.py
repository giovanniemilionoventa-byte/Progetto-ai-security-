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
    payload: Optional[dict] = None
    metadata: Optional[dict] = None
    execution_id: Optional[str] = None
    request_id: Optional[str] = None
    client_request_id: Optional[str] = None


class AuthorizeResponse(BaseModel):
    request_id: str
    decision: str
    risk_score: float
    risk_level: str
    reason: str
    approval_id: Optional[str] = None
    agent_id: str
    organization_id: str


class GatewayRequest(BaseModel):
    scope: str = "customers"
    destination: Optional[str] = None
    payload: Optional[dict] = None
    metadata: Optional[dict] = None
    execution_id: Optional[str] = None
    request_id: Optional[str] = None
    client_request_id: Optional[str] = None


class GatewayResponse(BaseModel):
    request_id: str
    decision: str
    risk_score: float
    risk_level: str
    reason: str
    approval_id: Optional[str] = None
    agent_id: str
    organization_id: str
    execution_id: Optional[str] = None
    tool: str
    operation: str
    executed: bool
    result: Optional[dict] = None


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
    execution_id: Optional[str] = None
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


class BehaviorPatternCreate(BaseModel):
    name: str
    description: str = ""
    type: str
    severity: str = "medium"
    definition: dict
    enabled: bool = True


class BehaviorPatternUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    type: Optional[str] = None
    severity: Optional[str] = None
    definition: Optional[dict] = None
    enabled: Optional[bool] = None


class BehaviorPatternOut(BaseModel):
    id: str
    organization_id: Optional[str] = None
    name: str
    description: str
    type: str
    severity: str
    definition: dict
    enabled: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RuntimeContractIntegrity(BaseModel):
    algorithm: Optional[str] = None
    digest: Optional[str] = None
    signature: Optional[str] = None
    key_id: Optional[str] = None
    signed_at: Optional[datetime] = None

    class Config:
        extra = "allow"


class RuntimeContractCapability(BaseModel):
    name: str
    actions: Optional[list[str]] = None
    description: Optional[str] = None

    class Config:
        extra = "allow"


class RuntimeContractResource(BaseModel):
    kind: str
    name: Optional[str] = None
    identifier: Optional[str] = None
    scope: Optional[str] = None
    sensitivity: Optional[str] = None

    class Config:
        extra = "allow"


class RuntimeContractDocument(BaseModel):
    organization_id: str
    agent_id: str
    contract_id: str
    version: int
    status: str = "DRAFT"
    purpose: str = ""
    capabilities: list[dict] = Field(default_factory=list)
    resources: list[dict] = Field(default_factory=list)
    constraints: dict = Field(default_factory=dict)
    data_constraints: dict = Field(default_factory=dict)
    workflow: Optional[dict] = None
    approval_rules: list[dict] = Field(default_factory=list)
    valid_from: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    integrity: Optional[RuntimeContractIntegrity] = None


class RuntimeContractOut(BaseModel):
    id: str
    organization_id: str
    agent_id: str
    contract_id: str
    version: int
    status: str
    purpose: str
    capabilities: list
    resources: list
    constraints: dict
    data_constraints: dict
    workflow: Optional[dict] = None
    approval_rules: list
    valid_from: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    integrity: Optional[dict] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
