import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { DiscoveredCertificate, DnsAudit, StatusResponse } from "../types";

const gradeClass = (grade: string) =>
  grade === "A" || grade === "B" ? "badge green" : grade === "C" ? "badge amber" : "badge red";

export default function Discovery() {
  const [certs, setCerts] = useState<DiscoveredCertificate[]>([]);
  const [audits, setAudits] = useState<DnsAudit[]>([]);
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [scanning, setScanning] = useState(false);
  const [auditing, setAuditing] = useState(false);

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 4000);
  };

  const load = useCallback(async () => {
    try {
      const [c, s] = await Promise.all([api.listDiscovered(), api.status()]);
      setCerts(c);
      setStatus(s);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load discovery");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const scan = async () => {
    setScanning(true);
    setError("");
    try {
      const res = await api.scanDiscovery();
      flash(
        `Scan complete — ${res.sources.npm} from nginx proxy manager, ${res.sources.file} from files (${res.added} new)`,
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const auditAll = async () => {
    setAuditing(true);
    setError("");
    try {
      setAudits(await api.auditDns());
      flash("DNS audit complete");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Audit failed");
    } finally {
      setAuditing(false);
    }
  };

  const remove = async (c: DiscoveredCertificate) => {
    if (!window.confirm(`Remove discovered certificate ${c.name} from the inventory?`)) return;
    try {
      await api.deleteDiscovered(c.id);
      flash("Removed");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
    }
  };

  const syncVault = async () => {
    try {
      const res = await api.vaultSync();
      flash(`Synced ${res.written.length} secret(s) to the vault`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Vault sync failed");
    }
  };

  const statusDot = (s: string) =>
    s === "ok" ? "ok" : s === "not-configured" ? "warn" : "err";

  const expiryCell = (expiresAt: string | null) => {
    if (!expiresAt) return <span className="muted">—</span>;
    const days = Math.round((new Date(expiresAt).getTime() - Date.now()) / 86400000);
    const cls = days < 30 ? "red" : days < 90 ? "" : "muted";
    return (
      <span className={cls}>
        {new Date(expiresAt).toLocaleDateString()}
        {days >= 0 ? ` (${days}d)` : " expired"}
      </span>
    );
  };

  return (
    <div>
      <h1>Discovery &amp; Audit</h1>
      <p className="subtitle">
        Certificates found on nginx proxy manager and local disk, plus DNS
        health audits for every registered domain.
      </p>

      {error && <p className="error">{error}</p>}

      <div className="panel">
        <div className="panel-title">Integration status</div>
        <table>
          <tbody>
            <tr>
              <td style={{ width: 260 }}>
                <span className={`status-dot ${statusDot(status?.auth.oidcEnabled ? "ok" : "warn")}`} />
                Authentik (OIDC)
              </td>
              <td className="muted">
                {status?.auth.oidcEnabled ? status.auth.issuerUrl : "not configured"}
              </td>
            </tr>
            <tr>
              <td>
                <span className={`status-dot ${statusDot(status?.vault.status || "warn")}`} />
                Secret vault (HashiCorp Vault)
              </td>
              <td className="muted mono">{status?.vault.status || "not-configured"}</td>
              <td style={{ textAlign: "right" }}>
                {status?.vault.enabled && (
                  <button className="secondary small" onClick={syncVault}>
                    Sync secrets
                  </button>
                )}
              </td>
            </tr>
            <tr>
              <td>
                <span className={`status-dot ${status?.discovery.dirs.length ? "ok" : "warn"}`} />
                Certificate discovery
              </td>
              <td className="muted mono">
                {status?.discovery.dirs.length
                  ? status.discovery.dirs.join(", ")
                  : "NPM only (set CERT_DISCOVERY_DIRS for local PEMs)"}
              </td>
              <td style={{ textAlign: "right" }}>
                <button className="secondary small" onClick={scan} disabled={scanning}>
                  {scanning ? "Scanning…" : "Scan now"}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="panel">
        <div className="panel-title">
          Discovered certificates ({certs.length})
          <button className="secondary small" style={{ marginLeft: 12 }} onClick={scan} disabled={scanning}>
            {scanning ? "Scanning…" : "Re-scan"}
          </button>
        </div>
        {certs.length === 0 ? (
          <div className="empty">
            Nothing discovered yet — run a scan to import certificates found on
            nginx proxy manager and in CERT_DISCOVERY_DIRS.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Source</th>
                <th>Domains</th>
                <th>Health</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {certs.map((c) => (
                <tr key={c.id}>
                  <td>
                    <strong>{c.name}</strong>
                    {c.issuer && <div className="muted" style={{ fontSize: 11 }}>{c.issuer}</div>}
                  </td>
                  <td>
                    <span className={`badge ${c.source === "npm" ? "blue" : "gray"}`}>{c.source}</span>
                  </td>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {c.domains.join(", ")}
                  </td>
                  <td>
                    <span className={gradeClass(c.health.grade)}>
                      {c.health.grade} {c.health.score}
                    </span>
                  </td>
                  <td>{expiryCell(c.expiresAt)}</td>
                  <td>
                    <button className="danger small" onClick={() => remove(c)}>
                      ✕
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">
          DNS health audit
          <button className="secondary small" style={{ marginLeft: 12 }} onClick={auditAll} disabled={auditing}>
            {auditing ? "Auditing…" : "Run audit for all domains"}
          </button>
        </div>
        {audits.length === 0 ? (
          <div className="empty">
            No audit run yet. Run one above, or use the Audit button on the
            Domains page for a single domain. Audits also run automatically
            every 6 hours.
          </div>
        ) : (
          audits.map((a) => (
            <div key={a.domain} style={{ marginBottom: 14 }}>
              <div className="form-row" style={{ marginBottom: 0 }}>
                <strong>{a.domain}</strong>
                <span className={gradeClass(a.grade)}>{a.grade} {a.score}/100</span>
                <span className="muted" style={{ fontSize: 12 }}>
                  {new Date(a.runAt).toLocaleString()}
                </span>
              </div>
              <table>
                <tbody>
                  {a.checks.map((c) => (
                    <tr key={c.name}>
                      <td style={{ width: 180 }}>
                        <span className={`status-dot ${c.status === "ok" ? "ok" : c.status === "warn" ? "warn" : "err"}`} />
                        {c.name}
                      </td>
                      <td className="muted">{c.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))
        )}
      </div>

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
