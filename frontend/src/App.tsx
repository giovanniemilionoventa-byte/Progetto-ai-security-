import { Navigate, NavLink, Route, Routes, useNavigate } from "react-router-dom";
import { useEffect, useState, type ReactNode } from "react";
import { api, clearToken, getToken, type Org, type User } from "./api";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Agents from "./pages/Agents";
import Policies from "./pages/Policies";
import Events from "./pages/Events";
import Approvals from "./pages/Approvals";
import Playground from "./pages/Playground";

function Shell({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<{ user: User; organization: Org } | null>(null);
  const nav = useNavigate();

  useEffect(() => {
    api.me().then(setMe).catch(() => nav("/login"));
  }, [nav]);

  const links = [
    ["/", "Overview"],
    ["/agents", "Agents"],
    ["/policies", "Policies"],
    ["/events", "Audit"],
    ["/approvals", "Approvals"],
    ["/playground", "Authorize"],
  ];

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" />
          <div>
            <h1>AEGIS</h1>
            <span>AI security layer</span>
          </div>
        </div>
        {links.map(([to, label]) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) => "nav-link" + (isActive ? " active" : "")}
          >
            {label}
          </NavLink>
        ))}
        <div className="sidebar-foot">
          <div>{me?.organization.name}</div>
          <div>{me?.user.email}</div>
          <button
            className="btn secondary small"
            style={{ marginTop: 8 }}
            onClick={() => {
              clearToken();
              nav("/login");
            }}
          >
            Sign out
          </button>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}

function Private({ children }: { children: ReactNode }) {
  if (!getToken()) return <Navigate to="/login" replace />;
  return <Shell>{children}</Shell>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Private><Overview /></Private>} />
      <Route path="/agents" element={<Private><Agents /></Private>} />
      <Route path="/policies" element={<Private><Policies /></Private>} />
      <Route path="/events" element={<Private><Events /></Private>} />
      <Route path="/approvals" element={<Private><Approvals /></Private>} />
      <Route path="/playground" element={<Private><Playground /></Private>} />
    </Routes>
  );
}
