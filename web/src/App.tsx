import { useEffect, useState } from "react";
import { clearToken, getToken } from "./api";
import Dashboard from "./pages/Dashboard";
import Domains from "./pages/Domains";
import Certificates from "./pages/Certificates";
import NpmExport from "./pages/NpmExport";
import Settings from "./pages/Settings";
import Login from "./pages/Login";

type Page = "dashboard" | "domains" | "certificates" | "npm" | "settings";

const NAV: { page: Page; label: string; icon: string }[] = [
  { page: "dashboard", label: "Dashboard", icon: "◈" },
  { page: "domains", label: "Domains", icon: "◉" },
  { page: "certificates", label: "Certificates", icon: "🔒" },
  { page: "npm", label: "nginx Proxy Manager", icon: "⇄" },
  { page: "settings", label: "Settings", icon: "⚙" },
];

export default function App() {
  const [authed, setAuthed] = useState<boolean>(() => Boolean(getToken()));
  const [page, setPage] = useState<Page>("dashboard");

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

  const logout = () => {
    clearToken();
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
          {NAV.map((item) => (
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
        <button className="nav-item logout" onClick={logout}>
          <span className="nav-icon">⏻</span> Log out
        </button>
      </aside>
      <main className="content">
        {page === "dashboard" && <Dashboard goTo={setPage} />}
        {page === "domains" && <Domains />}
        {page === "certificates" && <Certificates />}
        {page === "npm" && <NpmExport />}
        {page === "settings" && <Settings />}
      </main>
    </div>
  );
}
