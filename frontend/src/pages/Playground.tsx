import { FormEvent, useState } from "react";

type Result = {
  request_id: string;
  decision: string;
  risk_score: number;
  risk_level: string;
  reason: string;
  approval_id: string | null;
};

export default function Playground() {
  const [token, setToken] = useState("");
  const [resource, setResource] = useState("email");
  const [action, setAction] = useState("SEND");
  const [scope, setScope] = useState("external");
  const [destination, setDestination] = useState("external");
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setResult(null);
    try {
      const res = await fetch("/api/authorize", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Agent-Token": token,
        },
        body: JSON.stringify({
          resource_kind: resource,
          action,
          scope,
          destination: destination || null,
        }),
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
      <p className="page-sub">Simulate a tool call. Contract: Agent → Tool Request → Runtime Engine → ALLOW / APPROVAL / BLOCK → Evidence.</p>
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
          <button className="btn" type="submit">Evaluate</button>
        </form>
        {error && <p className="flash">{error}</p>}
        {result && (
          <div style={{ marginTop: 16 }}>
            <span className={"badge badge-" + result.decision}>{result.decision}</span>{" "}
            <span className={"badge badge-" + result.risk_level}>{result.risk_level} {result.risk_score}</span>
            <p>{result.reason}</p>
            <div className="mono">request {result.request_id}</div>
            {result.approval_id && <div className="mono">approval {result.approval_id}</div>}
          </div>
        )}
      </div>
    </>
  );
}
