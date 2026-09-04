import { FormEvent, useState } from "react";

type Result = {
  request_id: string;
  decision: string;
  risk_score: number;
  risk_level: string;
  reason: string;
  approval_id: string | null;
  executed?: boolean;
  tool?: string;
  operation?: string;
  execution_id?: string | null;
  result?: Record<string, unknown> | null;
};

export default function Playground() {
  const [token, setToken] = useState("");
  const [resource, setResource] = useState("email");
  const [action, setAction] = useState("SEND");
  const [scope, setScope] = useState("external");
  const [destination, setDestination] = useState("external");
  const [viaGateway, setViaGateway] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setResult(null);
    try {
      const url = viaGateway
        ? `/api/gateway/tools/${resource}/${action.toLowerCase()}`
        : "/api/authorize";
      const payload = viaGateway
        ? { scope, destination: destination || null }
        : {
            resource_kind: resource,
            action,
            scope,
            destination: destination || null,
          };
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Agent-Token": token,
        },
        body: JSON.stringify(payload),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.detail || res.statusText);
      setResult(body);
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed");
    }
  }

  return (
    <>
      <h2 className="page-title">Authorize</h2>
      <p className="page-sub">Agent uses an Aegis token. Gateway forwards to the protected tool only on ALLOW.</p>
      <div className="card">
        <form onSubmit={submit} className="grid" style={{ gap: 10, maxWidth: 560 }}>
          <label className="field">
            Agent token
            <input value={token} onChange={(e) => setToken(e.target.value)} placeholder="aegis_..." required />
          </label>
          <div className="row">
            <input value={resource} onChange={(e) => setResource(e.target.value)} />
            <input value={action} onChange={(e) => setAction(e.target.value)} />
            <input value={scope} onChange={(e) => setScope(e.target.value)} />
            <input value={destination} onChange={(e) => setDestination(e.target.value)} />
          </div>
          <label className="field">
            <input type="checkbox" checked={viaGateway} onChange={(e) => setViaGateway(e.target.checked)} />
            Send through enforcement gateway
          </label>
          <button className="btn" type="submit">{viaGateway ? "Invoke tool" : "Evaluate"}</button>
        </form>
        {error && <p className="flash">{error}</p>}
        {result && (
          <div style={{ marginTop: 16 }}>
            <span className={"badge badge-" + result.decision}>{result.decision}</span>{" "}
            <span className={"badge badge-" + result.risk_level}>{result.risk_level} {result.risk_score}</span>
            <p>{result.reason}</p>
            <div className="mono">request {result.request_id}</div>
            {result.approval_id && <div className="mono">approval {result.approval_id}</div>}
            {result.execution_id && <div className="mono">execution {result.execution_id}</div>}
            {viaGateway && (
              <div className="mono">
                tool {result.tool}.{result.operation} executed={String(result.executed)}
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}
