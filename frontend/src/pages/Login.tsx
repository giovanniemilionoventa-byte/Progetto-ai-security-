import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, setToken } from "../api";

export default function Login() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("admin@acme.test");
  const [password, setPassword] = useState("aegis-demo");
  const [fullName, setFullName] = useState("Ada Admin");
  const [org, setOrg] = useState("Acme Corp");
  const [error, setError] = useState("");
  const nav = useNavigate();

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const res =
        mode === "login"
          ? await api.login(email, password)
          : await api.register({
              organization_name: org,
              full_name: fullName,
              email,
              password,
            });
      setToken(res.access_token);
      nav("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Auth failed");
    }
  }

  return (
    <div className="auth-wrap">
      <div className="card auth-card">
        <div className="brand" style={{ marginBottom: 12 }}>
          <div className="brand-mark" />
          <div>
            <h1>AEGIS</h1>
            <span>control plane</span>
          </div>
        </div>
        <p className="page-sub">
          Independent security layer between AI agents and real systems.
        </p>
        <form onSubmit={onSubmit} className="grid" style={{ gap: 12 }}>
          {mode === "register" && (
            <>
              <label className="field">
                Organization
                <input value={org} onChange={(e) => setOrg(e.target.value)} />
              </label>
              <label className="field">
                Full name
                <input value={fullName} onChange={(e) => setFullName(e.target.value)} />
              </label>
            </>
          )}
          <label className="field">
            Email
            <input value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label className="field">
            Password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          {error && <p className="flash">{error}</p>}
          <button className="btn" type="submit">
            {mode === "login" ? "Enter control plane" : "Create organization"}
          </button>
        </form>
        <p style={{ marginTop: 16, fontSize: 13 }}>
          {mode === "login" ? (
            <a href="#" onClick={(e) => { e.preventDefault(); setMode("register"); }}>
              Create a new organization
            </a>
          ) : (
            <a href="#" onClick={(e) => { e.preventDefault(); setMode("login"); }}>
              Back to sign in
            </a>
          )}
        </p>
        <p className="page-sub" style={{ marginTop: 8 }}>
          Demo: admin@acme.test / aegis-demo
        </p>
      </div>
    </div>
  );
}
