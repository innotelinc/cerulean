import { useEffect, useState } from "react";
import { api } from "../api";
import type { Activity, Certificate, Domain, StatusResponse } from "../types";

export default function Dashboard({
  goTo,
}: {
  goTo: (page: "domains" | "certificates" | "npm" | "settings") => void;
}) {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [activities, setActivities] = useState<Activity[]>([]);
  const [error, setError] = useState("");

  const load = async () => {
    try {
      const [s, d, c, a] = await Promise.all([
        api.status(),
        api.listDomains(),
        api.listCertificates(),
        api.activities(),
      ]);
      setStatus(s);
      setDomains(d);
      setCerts(c);
      setActivities(a);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load");
    }
  };

  useEffect(() => {
    load();
  }, []);

  const issued = certs.filter((c) => c.status === "issued");
  const expiring = issued.filter((c) => {
    if (!c.expiresAt) return false;
    return new Date(c.expiresAt).getTime() < Date.now() + 30 * 86400000;
  });
  const issuing = certs.filter((c) => c.status === "issuing").length;

  const statusDot = (s: string) =>
    s === "ok" ? "ok" : s === "not-configured" ? "warn" : "err";

  return (
    <div>
      <h1>Dashboard</h1>
      <p className="subtitle">Cerulean — DNS &amp; certificate management for {status?.config.zone || "your zone"}</p>

      {error && <p className="error">{error}</p>}

      <div className="cards">
        <div className="card">
          <div className="num">{domains.length}</div>
          <div className="label">Domains managed</div>
        </div>
        <div className="card">
          <div className="num">{issued.length}</div>
          <div className="label">Certificates issued</div>
        </div>
        <div className="card">
          <div className="num" style={{ color: expiring.length ? "var(--amber)" : undefined }}>
            {expiring.length}
          </div>
          <div className="label">Expiring within 30 days</div>
        </div>
        <div className="card">
          <div className="num">{issuing}</div>
          <div className="label">In progress</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-title">Integration status</div>
        {!status ? (
          <p className="muted">Loading…</p>
        ) : (
          <table>
            <tbody>
              <tr>
                <td style={{ width: 220 }}>
                  <span className={`status-dot ${statusDot(status.bind.status)}`} />
                  BIND (SSH + nsupdate)
                </td>
                <td className="muted">{status.bind.status}</td>
                <td className="muted mono">{status.bind.detail}</td>
              </tr>
              <tr>
                <td>
                  <span className={`status-dot ${statusDot(status.acmedns.status)}`} />
                  acme-dns
                </td>
                <td className="muted">{status.acmedns.status}</td>
                <td className="muted mono">{status.config.acmednsApiUrl}</td>
              </tr>
              <tr>
                <td>
                  <span className={`status-dot ${statusDot(status.npm.status)}`} />
                  nginx proxy manager
                </td>
                <td className="muted">{status.npm.status}</td>
                <td className="muted mono">{status.config.npmApiUrl}</td>
              </tr>
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">Quick actions</div>
        <div className="actions">
          <button onClick={() => goTo("domains")}>Manage DNS records</button>
          <button onClick={() => goTo("certificates")}>Issue a certificate</button>
          <button onClick={() => goTo("npm")}>Export to nginx proxy manager</button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-title">Recent activity</div>
        {activities.length === 0 ? (
          <div className="empty">No activity yet</div>
        ) : (
          <table>
            <tbody>
              {activities.slice(0, 12).map((a) => (
                <tr key={a.id}>
                  <td className="muted mono" style={{ whiteSpace: "nowrap" }}>
                    {new Date(a.ts).toLocaleString()}
                  </td>
                  <td>
                    <span className="badge blue">{a.kind}</span>
                  </td>
                  <td>{a.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
