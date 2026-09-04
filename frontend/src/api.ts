const TOKEN_KEY = "aegis_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    clearToken();
    if (!path.includes("/auth/login")) {
      window.location.href = "/login";
    }
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  login: (email: string, password: string) =>
    request<{ access_token: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  register: (payload: {
    organization_name: string;
    full_name: string;
    email: string;
    password: string;
  }) =>
    request<{ access_token: string }>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  me: () => request<{ user: User; organization: Org }>("/api/auth/me"),
  stats: () => request<Stats>("/api/stats"),
  agents: () => request<Agent[]>("/api/agents"),
  createAgent: (body: { name: string; provider: string; model: string; description: string }) =>
    request<{ agent: Agent; token: string }>("/api/agents", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  revokeAgent: (id: string) =>
    request<Agent>(`/api/agents/${id}/revoke`, { method: "POST" }),
  rotateAgent: (id: string) =>
    request<{ agent: Agent; token: string }>(`/api/agents/${id}/rotate`, {
      method: "POST",
    }),
  permissions: (id: string) => request<Permission[]>(`/api/agents/${id}/permissions`),
  addPermission: (id: string, body: PermissionCreate) =>
    request<Permission>(`/api/agents/${id}/permissions`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  policies: () => request<Policy[]>("/api/policies"),
  createPolicy: (body: PolicyCreate) =>
    request<Policy>("/api/policies", { method: "POST", body: JSON.stringify(body) }),
  togglePolicy: (id: string) =>
    request<Policy>(`/api/policies/${id}/toggle`, { method: "POST" }),
  events: () => request<EventRow[]>("/api/events"),
  alerts: () => request<AlertRow[]>("/api/alerts"),
  approvals: () => request<ApprovalRow[]>("/api/approvals"),
  decide: (id: string, decision: string) =>
    request<ApprovalRow>(`/api/approvals/${id}/decide`, {
      method: "POST",
      body: JSON.stringify({ decision }),
    }),
  resources: () => request<ResourceRow[]>("/api/resources"),
  devices: () => request<DeviceRow[]>("/api/devices"),
};

export type User = {
  id: string;
  email: string;
  full_name: string;
  role: string;
  organization_id: string;
};
export type Org = { id: string; name: string; slug: string; created_at: string };
export type Stats = {
  agents: number;
  events: number;
  blocked: number;
  pending_approvals: number;
  open_alerts: number;
  allow_rate: number;
};
export type Agent = {
  id: string;
  name: string;
  provider: string;
  model: string;
  status: string;
  description: string;
  owner_id: string;
  organization_id: string;
  created_at: string;
  revoked_at: string | null;
};
export type Permission = {
  id: string;
  agent_id: string;
  resource_kind: string;
  action: string;
  scope: string;
  effect: string;
};
export type PermissionCreate = {
  resource_kind: string;
  action: string;
  scope: string;
  effect: string;
};
export type Policy = {
  id: string;
  name: string;
  description: string;
  resource_kind: string;
  action: string;
  scope_pattern: string;
  destination_pattern: string | null;
  decision: string;
  priority: number;
  enabled: boolean;
  created_at: string;
};
export type PolicyCreate = {
  name: string;
  description: string;
  resource_kind: string;
  action: string;
  scope_pattern: string;
  destination_pattern?: string;
  decision: string;
  priority: number;
};
export type EventRow = {
  id: string;
  agent_id: string | null;
  resource_kind: string;
  action: string;
  scope: string;
  destination: string | null;
  decision: string;
  risk_score: number;
  risk_level: string;
  reason: string;
  request_id: string;
  execution_id?: string | null;
  created_at: string;
};
export type AlertRow = {
  id: string;
  severity: string;
  title: string;
  message: string;
  status: string;
  created_at: string;
};
export type ApprovalRow = {
  id: string;
  agent_id: string;
  resource_kind: string;
  action: string;
  scope: string;
  destination: string | null;
  status: string;
  reason: string;
  created_at: string;
};
export type ResourceRow = {
  id: string;
  kind: string;
  name: string;
  identifier: string;
  sensitivity: string;
};
export type DeviceRow = {
  id: string;
  hostname: string;
  platform: string;
  status: string;
  last_seen: string;
};
