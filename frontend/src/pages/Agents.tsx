import { FormEvent, useEffect, useState } from "react";
import { api, type Agent, type Permission } from "../api";

export default function Agents() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selected, setSelected] = useState<Agent | null>(null);
  const [perms, setPerms] = useState<Permission[]>([]);
  const [token, setToken] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", provider: "demo", model: "local-demo", description: "" });
  const [perm, setPerm] = useState({ resource_kind: "files", action: "READ", scope: "/Sales", effect: "allow" });

  const refresh = () => api.agents().then(setAgents);

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    if (selected) api.permissions(selected.id).then(setPerms);
  }, [selected]);

  async function create(e: FormEvent) {
    e.preventDefault();
    const res = await api.createAgent(form);
    setToken(res.token);
    setForm({ name: "", provider: "demo", model: "local-demo", description: "" });
    await refresh();
  }

  return (
    <>
      <h2 className="page-title">Agent registry</h2>
      <p className="page-sub">Identity is distinct from the human owner and from the model provider.</p>
      <div className="grid grid-2">
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Provider</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a.id} onClick={() => setSelected(a)} style={{ cursor: "pointer" }}>
                  <td>
                    <strong>{a.name}</strong>
                    <div className="mono">{a.id.slice(0, 8)}</div>
                  </td>
                  <td className="mono">{a.provider}/{a.model}</td>
                  <td><span className={"badge badge-" + a.status}>{a.status}</span></td>
                  <td>
                    {a.status === "active" && (
                      <button
                        className="btn danger small"
                        onClick={(e) => {
                          e.stopPropagation();
                          api.revokeAgent(a.id).then(refresh);
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h3>Register agent</h3>
          <form onSubmit={create} className="grid" style={{ gap: 10 }}>
            <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            <input placeholder="Provider" value={form.provider} onChange={(e) => setForm({ ...form, provider: e.target.value })} />
            <input placeholder="Model" value={form.model} onChange={(e) => setForm({ ...form, model: e.target.value })} />
            <textarea placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            <button className="btn" type="submit">Issue signed token</button>
          </form>
          {token && (
            <div>
              <p className="page-sub">Show once. Store as AEGIS_AGENT_TOKEN.</p>
              <div className="token-box">{token}</div>
            </div>
          )}
        </div>
      </div>
      {selected && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Scopes — {selected.name}</h3>
          <table>
            <thead>
              <tr><th>Resource</th><th>Action</th><th>Scope</th><th>Effect</th></tr>
            </thead>
            <tbody>
              {perms.map((p) => (
                <tr key={p.id}>
                  <td className="mono">{p.resource_kind}</td>
                  <td className="mono">{p.action}</td>
                  <td className="mono">{p.scope}</td>
                  <td><span className={"badge badge-" + p.effect}>{p.effect}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          <form
            className="row"
            style={{ marginTop: 12 }}
            onSubmit={async (e) => {
              e.preventDefault();
              await api.addPermission(selected.id, perm);
              setPerms(await api.permissions(selected.id));
            }}
          >
            <input value={perm.resource_kind} onChange={(e) => setPerm({ ...perm, resource_kind: e.target.value })} />
            <input value={perm.action} onChange={(e) => setPerm({ ...perm, action: e.target.value })} />
            <input value={perm.scope} onChange={(e) => setPerm({ ...perm, scope: e.target.value })} />
            <select value={perm.effect} onChange={(e) => setPerm({ ...perm, effect: e.target.value })}>
              <option value="allow">allow</option>
              <option value="deny">deny</option>
            </select>
            <button className="btn small" type="submit">Grant</button>
          </form>
        </div>
      )}
    </>
  );
}
