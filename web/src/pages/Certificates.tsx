import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { Certificate, Domain } from "../types";

export default function Certificates() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [busy, setBusy] = useState(false);

  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [wildcard, setWildcard] = useState(false);

  const [detail, setDetail] = useState<Certificate | null>(null);
  const [material, setMaterial] = useState<{ certificate: string; key: string } | null>(null);
  const [health, setHealth] = useState<import("../types").CertHealth | null>(null);

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 4000);
  };

  const load = useCallback(async () => {
    try {
      const [c, d] = await Promise.all([api.listCertificates(), api.listDomains()]);
      setCerts(c);
      setDomains(d);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load certificates");
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!certs.some((c) => c.status === "issuing")) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [certs, load]);

  const issue = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await api.createCertificate({
        name: name || undefined,
        domain: domain || undefined,
        wildcard,
      });
      flash(res.status === "issued" ? `Issued ${wildcard ? "wildcard " : ""}${res.domain} (${res.source ?? "pki"})` : `Issuance started for ${res.domain}`);
      setName("");
      setWildcard(false);
      if (!domain) {
        // default wildcard issued synchronously — no domain chosen
      } else {
        // keep domain for convenience
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start issuance");
    } finally {
      setBusy(false);
    }
  };

  const renew = async (c: Certificate) => {
    if (!window.confirm(`Renew certificate for ${c.domain}?`)) return;
    try {
      await api.renewCertificate(c.id);
      flash("Renewal started");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Renewal failed");
    }
  };

  const remove = async (c: Certificate) => {
    if (!window.confirm(`Delete certificate for ${c.domain}?`)) return;
    try {
      await api.deleteCertificate(c.id);
      flash("Certificate deleted");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
    }
  };

  const showDetail = async (c: Certificate) => {
    setDetail(c);
    setMaterial(null);
    setHealth(null);
    try { setHealth(await api.certHealth(c.id)); } catch { setHealth(null); }
    if (c.hasMaterial) {
      try { setMaterial(await api.certMaterial(c.id)); } catch { setMaterial(null); }
    }
  };

  const exportToNpm = async (c: Certificate) => {
    try {
      const result = await api.exportCert({ certificate_id: c.id });
      flash(`Exported to nginx proxy manager (cert #${result.npmCertificateId})`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    }
  };

  const statusBadge = (c: Certificate) => {
    if (c.status === "issued") return <span className="badge green">issued {c.source ? `· ${c.source}` : ""}</span>;
    if (c.status === "error") return <span className="badge red">error</span>;
    return <span className="badge amber">issuing…</span>;
  };

  const healthBadge = (c: Certificate) => {
    const { grade, score } = c.health || { grade: "?", score: 0 };
    const cls = grade === "A" || grade === "B" ? "badge green" : grade === "C" ? "badge amber" : "badge red";
    return <span className={cls}>{grade} {score}</span>;
  };

  const expiryCell = (c: Certificate) => {
    if (!c.expiresAt) return <span className="muted">—</span>;
    const days = Math.round((new Date(c.expiresAt).getTime() - Date.now()) / 86400000);
    const cls = days < 7 ? "red" : days < 30 ? "" : "muted";
    return <span className={cls}>{new Date(c.expiresAt).toLocaleDateString()}<span className="muted"> ({days}d)</span></span>;
  };

  return (
    <div>
      <h1>Certificates</h1>
      <p className="subtitle">
        DNS-01 via Technitium HTTP API — regular or wildcard. Leave domain empty for the server&apos;s default
        <span className="mono"> *.*.lab.innotel.us</span> (30-day, PKI offline → ACME when online).
      </p>

      {error && <p className="error">{error}</p>}

      <div className="panel">
        <div className="panel-title">Issue a certificate</div>
        <form className="form-row" onSubmit={issue}>
          <input
            placeholder="name (optional)"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <select value={domain} onChange={(e) => setDomain(e.target.value)}>
            <option value="">— default wildcard (*.&lt;serverId&gt;.lab.innotel.us) —</option>
            {domains.map((d) => (
              <option key={d.id} value={d.name}>
                {d.name}
              </option>
            ))}
          </select>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={wildcard || !domain}
              onChange={(e) => setWildcard(e.target.checked)}
              disabled={!domain}
            />
            Wildcard (*.{domain || "domain"})
          </label>
          <button type="submit" disabled={busy}>
            {busy ? "Starting…" : domain ? "Issue" : "Issue default wildcard"}
          </button>
        </form>
        {(wildcard || !domain) && (
          <p className="muted" style={{ marginTop: 0 }}>
            Wildcard covers apex + subdomains (<span className="mono">*.*.lab.innotel.us</span>). Default wildcard is 30-day PKI (offline) and auto-upgraded to ACME.
          </p>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">Certificates</div>
        {certs.length === 0 ? (
          <div className="empty">No certificates yet — issue one above.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Domains</th>
                <th>Status</th>
                <th>Health</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {certs.map((c) => (
                <tr key={c.id}>
                  <td><strong>{c.name}</strong></td>
                  <td className="mono">{c.domains.join(", ")}</td>
                  <td>{statusBadge(c)}</td>
                  <td>{c.status === "issued" ? healthBadge(c) : <span className="muted">—</span>}</td>
                  <td>{expiryCell(c)}</td>
                  <td>
                    <div className="actions">
                      <button className="secondary small" onClick={() => showDetail(c)}>View</button>
                      <button className="secondary small" onClick={() => renew(c)} disabled={c.status === "issuing"}>Renew</button>
                      <button className="secondary small" onClick={() => exportToNpm(c)} disabled={!c.hasMaterial}>→ NPM</button>
                      <button className="danger small" onClick={() => remove(c)}>✕</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {detail && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 50 }} onClick={() => setDetail(null)}>
          <div className="panel" style={{ width: 760, maxHeight: "80vh", overflow: "auto", margin: 0 }} onClick={(e) => e.stopPropagation()}>
            <div className="panel-title">{detail.name} — {detail.domains.join(", ")} {detail.source && <span className="badge blue">{detail.source}</span>}
              {detail.status === "error" && <p className="error" style={{ marginTop: 8 }}>{detail.error}</p>}
            </div>
            <p className="muted">
              Issued: {detail.issuedAt ? new Date(detail.issuedAt).toLocaleString() : "—"} · Expires: {detail.expiresAt ? new Date(detail.expiresAt).toLocaleString() : "—"} · Auto-renew: {detail.autoRenew ? "on" : "off"} · Source: {detail.source ?? "—"}
            </p>
            {health && (
              <div style={{ margin: "8px 0" }}>
                <p className="panel-title" style={{ marginBottom: 6 }}>Health: {health.grade} ({health.score}/100)</p>
                <table><tbody>{health.checks.map((c) => (
                  <tr key={c.name}><td style={{ width: 140 }}><span className={`status-dot ${c.status === "ok" ? "ok" : c.status === "warn" ? "warn" : "err"}`} />{c.name}</td><td className="muted">{c.detail}</td></tr>
                ))}</tbody></table>
              </div>
            )}
            {material ? (
              <><p className="panel-title" style={{ marginBottom: 6 }}>Fullchain (PEM)</p><textarea readOnly value={material.certificate} /><p className="panel-title" style={{ marginBottom: 6 }}>Private key (PEM)</p><textarea readOnly value={material.key} /></>
            ) : (
              <p className="muted">Certificate material not available.</p>
            )}
          </div>
        </div>
      )}

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
