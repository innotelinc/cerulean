import { useEffect, useState } from "react";
import { api, clearToken, getToken } from "./api";
import Dashboard from "./pages/Dashboard";
import Domains from "./pages/Domains";
import DnsProviders from "./pages/DnsProviders";
import Certificates from "./pages/Certificates";
import NpmExport from "./pages/NpmExport";
import Pki from "./pages/Pki";
import Tenants from "./pages/Tenants";
import Discovery from "./pages/Discovery";
import Settings from "./pages/Settings";
import Login from "./pages/Login";
import type { SessionUser } from "./types";

type Page = "dashboard" | "domains" | "dnsproviders" | "certificates" | "pki" | "tenants" | "npm" | "discovery" | "settings";

const NAV: { page: Page; label: string; icon: string; platformOnly?: boolean }[] = [
  { page: "dashboard", label: "Dashboard", icon: "◈" },
  { page: "domains", label: "Domains", icon: "◉" },
  { page: "dnsproviders", label: "DNS Providers", icon: "☁" },
  { page: "certificates", label: "Certificates", icon: "🔒" },
  { page: "pki", label: "PKI & Devices", icon: "🛡" },
  { page: "npm", label: "nginx Proxy Manager", icon: "⇄" },
  { page: "discovery", label: "Discovery & Audit", icon: "⌕" },
  { page: "tenants", label: "Tenants", icon: "▤", platformOnly: true },
  { page: "settings", label: "Settings", icon: "⚙" },
];

export default function App() {
  const [authed, setAuthed] = useState<boolean>(() => Boolean(getToken()));
  const [page, setPage] = useState<Page>("dashboard");
  const [user, setUser] = useState<SessionUser | null>(null);
  const [tenant, setTenant] = useState<{ id: number; slug: string; name: string } | null>(null);
  const [platform, setPlatform] = useState(false);

  useEffect(() => {
    if (authed) {
      api
        .me()
        .then((res) => {
          setUser(res.user);
          setTenant(res.tenant ?? null);
          setPlatform(Boolean(res.platform));
        })
        .catch(() => setUser(null));
    }
  }, [authed]);

  useEffect(() => {
    if (!authed) {
      const onHash = () => setPage("dashboard");
      window.addEventListener("hashchange", onHash);
      return () => window.removeEventListener("hashchange", onHash);
    }
  }, [authed]);

  if (!authed) {
    return (
      <Login
        onLogin={() => {
          setAuthed(true);
          setPage("dashboard");
        }}
      />
    );
  }

  const logout = async () => {
    try {
      await api.logout();
    } catch {
      // session may already be gone — clear locally regardless
    }
    clearToken();
    setUser(null);
    setAuthed(false);
  };

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">◆</span>
          <span>Cerulean</span>
        </div>
        <nav>
          {NAV.filter((item) => !item.platformOnly || platform).map((item) => (
            <button
              key={item.page}
              className={`nav-item ${page === item.page ? "active" : ""}`}
              onClick={() => setPage(item.page)}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          {user && (
            <div className="muted" style={{ padding: "0 14px 8px", fontSize: 12 }}>
              {user.name}
              {user.email && <div className="mono">{user.email}</div>}
              {tenant && (
                <div style={{ marginTop: 4 }}>
                  <span className="badge blue">
                    {tenant.name}
                    {platform ? " · platform" : ""}
                  </span>
                </div>
              )}
            </div>
          )}
          <button className="nav-item logout" onClick={logout}>
            <span className="nav-icon">⏻</span> Log out
          </button>
        </div>
      </aside>
      <main className="content">
        {page === "dashboard" && <Dashboard goTo={setPage} />}
        {page === "domains" && <Domains />}
        {page === "dnsproviders" && <DnsProviders />}
        {page === "certificates" && <Certificates />}
        {page === "pki" && <Pki />}
        {page === "tenants" && platform && <Tenants />}
        {page === "npm" && <NpmExport />}
        {page === "discovery" && <Discovery />}
        {page === "settings" && <Settings />}
      </main>
    </div>
  );
}
