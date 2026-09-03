export type Decision = "ALLOW" | "BLOCK" | "APPROVAL";

export interface AuthorizeRequest {
  resource_kind: string;
  action: string;
  scope: string;
  destination?: string;
  metadata?: Record<string, unknown>;
}

export interface AuthorizeResponse {
  request_id: string;
  decision: Decision;
  risk_score: number;
  risk_level: string;
  reason: string;
  approval_id: string | null;
  agent_id: string;
  organization_id: string;
}

export class AegisClient {
  constructor(
    private token: string,
    private baseUrl: string = "/api"
  ) {}

  async authorize(req: AuthorizeRequest): Promise<AuthorizeResponse> {
    const res = await fetch(`${this.baseUrl}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Agent-Token": this.token,
      },
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      throw new Error(`Aegis authorize failed: ${res.status}`);
    }
    return (await res.json()) as AuthorizeResponse;
  }
}
