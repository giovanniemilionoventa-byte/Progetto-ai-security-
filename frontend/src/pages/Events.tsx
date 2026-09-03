import { useEffect, useState } from "react";
import { api, type EventRow } from "../api";

export default function Events() {
  const [events, setEvents] = useState<EventRow[]>([]);
  useEffect(() => { api.events().then(setEvents); }, []);

  return (
    <>
      <h2 className="page-title">Audit log</h2>
      <p className="page-sub">Metadata only. Conversations are not stored.</p>
      <div className="card">
        {events.length === 0 && <div className="empty">No decisions recorded.</div>}
        <table>
          <thead>
            <tr>
              <th>Time</th><th>Decision</th><th>Call</th><th>Risk</th><th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td className="mono">{new Date(e.created_at).toLocaleString()}</td>
                <td><span className={"badge badge-" + e.decision}>{e.decision}</span></td>
                <td className="mono">{e.resource_kind}.{e.action}<br />{e.scope}</td>
                <td><span className={"badge badge-" + e.risk_level}>{e.risk_level} {e.risk_score}</span></td>
                <td>{e.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
