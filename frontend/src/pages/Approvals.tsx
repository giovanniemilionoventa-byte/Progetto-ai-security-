import { useEffect, useState } from "react";
import { api, type ApprovalRow } from "../api";

export default function Approvals() {
  const [rows, setRows] = useState<ApprovalRow[]>([]);
  const refresh = () => api.approvals().then(setRows);
  useEffect(() => { refresh(); }, []);

  return (
    <>
      <h2 className="page-title">Human approval</h2>
      <p className="page-sub">Irreversible or external actions wait here. Least privilege still applies.</p>
      <div className="card">
        {rows.length === 0 && <div className="empty">No approval requests.</div>}
        <table>
          <thead>
            <tr><th>Status</th><th>Action</th><th>Reason</th><th></th></tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td><span className={"badge badge-" + r.status}>{r.status}</span></td>
                <td className="mono">{r.resource_kind}.{r.action} {r.scope}</td>
                <td>{r.reason}</td>
                <td>
                  {r.status === "pending" && (
                    <div className="row">
                      <button className="btn small" onClick={() => api.decide(r.id, "ALLOW").then(refresh)}>Allow</button>
                      <button className="btn danger small" onClick={() => api.decide(r.id, "BLOCK").then(refresh)}>Block</button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
