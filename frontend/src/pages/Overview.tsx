import { useEffect, useState } from "react";
import { api, type AlertRow, type EventRow, type Stats } from "../api";

export default function Overview() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);

  useEffect(() => {
    api.stats().then(setStats);
    api.events().then((e) => setEvents(e.slice(0, 8)));
    api.alerts().then((a) => setAlerts(a.slice(0, 6)));
  }, []);

  return (
    <>
      <h2 className="page-title">Control plane</h2>
      <p className="page-sub">Identity, policy, risk, audit. The model is a provider, not the center.</p>
      <div className="flow">
        <b>Agent</b> → tool call → <b>Aegis</b> → ALLOW / APPROVAL / BLOCK → resource
      </div>
      <div className="grid grid-4" style={{ marginBottom: 20 }}>
        {[
          ["Agents", stats?.agents ?? "—"],
          ["Events", stats?.events ?? "—"],
          ["Blocked", stats?.blocked ?? "—"],
          ["Pending approvals", stats?.pending_approvals ?? "—"],
        ].map(([label, value]) => (
          <div className="card" key={label}>
            <div className="stat-label">{label}</div>
            <div className="stat-value">{value}</div>
          </div>
        ))}
      </div>
      <div className="grid grid-2">
        <div className="card">
          <h3>Recent decisions</h3>
          {events.length === 0 && <div className="empty">No events yet. Run the demo agent.</div>}
          <table>
            <thead>
              <tr>
                <th>Decision</th>
                <th>Action</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td><span className={"badge badge-" + e.decision}>{e.decision}</span></td>
                  <td className="mono">{e.resource_kind}.{e.action} {e.scope}</td>
                  <td><span className={"badge badge-" + e.risk_level}>{e.risk_level}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h3>Alerts</h3>
          {alerts.length === 0 && <div className="empty">No open alerts.</div>}
          {alerts.map((a) => (
            <div key={a.id} style={{ marginBottom: 12 }}>
              <span className={"badge badge-" + a.severity}>{a.severity}</span>{" "}
              <strong>{a.title}</strong>
              <div className="page-sub">{a.message}</div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
