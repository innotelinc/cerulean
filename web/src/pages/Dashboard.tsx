import { useEffect, useState } from "react";
import { api } from "../api";
import type { Activity, Certificate, Domain, StatusResponse } from "../types";

export default function Dashboard({
  goTo,
}: {
  goTo: (page: "domains" | "certificates" | "pki" | "npm" | "settings" | "orchestrator") => void;
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

  // Infisical is the stack's secret store when enabled; HashiCorp Vault otherwise.
  const secretVault = status?.infisical?.enabled
    ? { status: status.infisical.status, addr: status.infisical.addr }
    : { status: status?.vault.status ?? "not-configured", addr: status?.vault.addr ?? "" };

  const issued = certs.filter((c) => c.status === "issued");
  const expiring = issued.filter((c) => {
    if (!c.expiresAt) return false;
    return new Date(c.expiresAt).getTime() < Date.now() + 30 * 86400000;
  });
  const issuing = certs.filter((c) => c.status === "issuing").length;

  const statusDot = (s: string) =>
    s === "ok" ? "ok" : s === "not-configured" || s === "off" ? "warn" : "err";

  return (
    <div>
      <h1>Dashboard</h1>
      <p className="subtitle">
        Master orchestrator {status?.server.serverId ? `${status.server.serverId} · ${status.server.apex} (+ ${status.server.wildcard})` : "— certificate & DNS"}
      </p>

      {error && <p className="error">{error}</p>}

      <div className="cards">
        <div className="card">
          <div className="num">{domains.length}</div>
          <div className="label">Zones managed</div>
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
          <div className="num">{status?.pki?.issued ?? 0}</div>
          <div className="label">Device certificates (PKI)</div>
        </div>
        <div className="card">
          <div className="num">{issuing}</div>
          <div className="label">In progress</div>
        </div>
        <div className="card">
          <div className="num">{status?.dhcp.scopes ?? 0}</div>
          <div className="label">DHCP scopes · {status?.dhcp.leases ?? 0} leases</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-title">Master orchestrator</div>
        {!status ? (
          <p className="muted">Loading…</p>
        ) : (
          <table>
            <tbody>
              <tr>
                <td style={{ width: 220 }}>
                  <span className={`status-dot ${statusDot(status.technitium.status)}`} />
                  Technitium DNS
                </td>
                <td className="muted">{status.technitium.status}</td>
                <td className="muted mono">{status.technitium.url}</td>
              </tr>
              <tr>
                <td>
                  <span className={`status-dot ${statusDot(status.dhcp.status)}`} />
                  DHCP
                </td>
                <td className="muted">{status.dhcp.enabled ? status.dhcp.status : "disabled"}</td>
                <td className="muted mono">{status.dhcp.detail} {status.dhcp.scopes ? `· ${status.dhcp.scopes} scopes` : ""}</td>
              </tr>
              <tr>
                <td>
                  <span className={`status-dot ${statusDot(status.blocking.status)}`} />
                  Ad-blocking
                </td>
                <td className="muted">{status.blocking.enabled ? status.blocking.status : "disabled"}</td>
                <td className="muted mono">{status.blocking.detail} {status.blocking.blockedZones ? `· ${status.blocking.blockedZones} blocked` : ""}</td>
              </tr>
              <tr>
                <td>
                  <span className={`status-dot ${statusDot(status.npm.status)}`} />
                  nginx proxy manager
                </td>
                <td className="muted">{status.npm.status}</td>
                <td className="muted mono">{status.config.npmApiUrl || "—"}</td>
              </tr>
              <tr>
                <td>
                  <span className={`status-dot ${status.auth.oidcEnabled ? "ok" : "warn"}`} />
                  Authentik (OIDC)
                </td>
                <td className="muted">{status.auth.oidcEnabled ? "configured" : "not-configured"}</td>
                <td className="muted mono">{status.auth.issuerUrl || "—"}</td>
              </tr>
              <tr>
                <td>
                  <span className={`status-dot ${statusDot(secretVault.status)}`} />
                  Secret vault
                </td>
                <td className="muted">{secretVault.status}</td>
                <td className="muted mono">{secretVault.addr || "—"}</td>
              </tr>
              <tr>
                <td>
                  <span className={`status-dot ${status.pki.initialized ? "ok" : "warn"}`} />
                  Internal root CA (PKI)
                </td>
                <td className="muted">{status.pki.initialized ? "ready" : "not-initialized"}</td>
                <td className="muted mono">{status.pki.commonName || "—"}</td>
              </tr>
              <tr>
                <td>
                  <span className={`status-dot ${status.server.registered ? "ok" : "warn"}`} />
                  Server {status.server.serverId}
                </td>
                <td className="muted">{status.server.registered ? "registered" : "standalone"}</td>
                <td className="muted mono">{status.server.apex} · wildcard {status.server.wildcardValidityDays}d {status.server.autoWildcard ? "(auto)" : ""}</td>
              </tr>
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">Quick actions</div>
        <div className="actions">
          <button onClick={() => goTo("orchestrator")}>Orchestrator · DHCP · Blocking</button>
          <button onClick={() => goTo("domains")}>Manage DNS zones</button>
          <button onClick={() => goTo("certificates")}>Issue a certificate</button>
          <button onClick={() => goTo("pki")}>Device certificates</button>
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
