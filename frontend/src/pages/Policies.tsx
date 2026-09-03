import { FormEvent, useEffect, useState } from "react";
import { api, type Policy } from "../api";

export default function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [form, setForm] = useState({
    name: "",
    description: "",
    resource_kind: "email",
    action: "SEND",
    scope_pattern: "external",
    destination_pattern: "external",
    decision: "APPROVAL",
    priority: 25,
  });

  const refresh = () => api.policies().then(setPolicies);
  useEffect(() => { refresh(); }, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    await api.createPolicy(form);
    setForm({ ...form, name: "", description: "" });
    refresh();
  }

  return (
    <>
      <h2 className="page-title">Policy engine</h2>
      <p className="page-sub">Deterministic evaluation. Most specific restrictive decision wins.</p>
      <div className="card" style={{ marginBottom: 16 }}>
        <table>
          <thead>
            <tr>
              <th>Prio</th><th>Name</th><th>Match</th><th>Decision</th><th>On</th>
            </tr>
          </thead>
          <tbody>
            {policies.map((p) => (
              <tr key={p.id}>
                <td className="mono">{p.priority}</td>
                <td>
                  <strong>{p.name}</strong>
                  <div className="page-sub">{p.description}</div>
                </td>
                <td className="mono">{p.resource_kind}.{p.action} {p.scope_pattern}</td>
                <td><span className={"badge badge-" + p.decision}>{p.decision}</span></td>
                <td>
                  <button className="btn secondary small" onClick={() => api.togglePolicy(p.id).then(refresh)}>
                    {p.enabled ? "enabled" : "disabled"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card">
        <h3>New rule</h3>
        <form onSubmit={create} className="grid grid-2">
          <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          <input placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <input placeholder="Resource" value={form.resource_kind} onChange={(e) => setForm({ ...form, resource_kind: e.target.value })} />
          <input placeholder="Action" value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })} />
          <input placeholder="Scope pattern" value={form.scope_pattern} onChange={(e) => setForm({ ...form, scope_pattern: e.target.value })} />
          <input placeholder="Destination" value={form.destination_pattern} onChange={(e) => setForm({ ...form, destination_pattern: e.target.value })} />
          <select value={form.decision} onChange={(e) => setForm({ ...form, decision: e.target.value })}>
            <option>ALLOW</option>
            <option>BLOCK</option>
            <option>APPROVAL</option>
          </select>
          <input type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} />
          <button className="btn" type="submit">Add policy</button>
        </form>
      </div>
    </>
  );
}
