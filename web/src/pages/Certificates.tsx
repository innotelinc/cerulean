import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { Certificate, Domain } from "../types";

export default function Certificates() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [busy, setBusy] = useState(false);

  // issue form
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [wildcard, setWildcard] = useState(false);
  const [strategy, setStrategy] = useState<"acme-dns" | "bind">("acme-dns");

  // detail modal
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

  useEffect(() => {
    load();
  }, [load]);

  // Poll while anything is issuing
  useEffect(() => {
    if (!certs.some((c) => c.status === "issuing")) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [certs, load]);

  const issue = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain) return;
    setBusy(true);
    setError("");
    try {
      await api.createCertificate({
        name: name || undefined,
        domain,
        wildcard,
        strategy,
      });
      setName("");
      setWildcard(false);
      flash(`Issuance started for ${wildcard ? "*." : ""}${domain}`);
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
    try {
      setHealth(await api.certHealth(c.id));
    } catch {
      setHealth(null);
    }
    if (c.hasMaterial) {
      try {
        setMaterial(await api.certMaterial(c.id));
      } catch {
        setMaterial(null);
      }
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
    if (c.status === "issued") return <span className="badge green">issued</span>;
    if (c.status === "error") return <span className="badge red">error</span>;
    return <span className="badge amber">issuing…</span>;
  };

  const healthBadge = (c: Certificate) => {
    const { grade, score } = c.health || { grade: "?", score: 0 };
    const cls =
      grade === "A" || grade === "B"
        ? "badge green"
        : grade === "C"
          ? "badge amber"
          : "badge red";
    return (
      <span className={cls}>
        {grade} {score}
      </span>
    );
  };

  const expiryCell = (c: Certificate) => {
    if (!c.expiresAt) return <span className="muted">—</span>;
    const days = Math.round(
      (new Date(c.expiresAt).getTime() - Date.now()) / 86400000,
    );
    const cls = days < 30 ? "red" : "muted";
    return (
      <span className={cls}>
        {new Date(c.expiresAt).toLocaleDateString()}
        {c.status === "issued" && (
          <span className="muted"> ({days} days)</span>
        )}
      </span>
    );
  };

  return (
    <div>
      <h1>Certificates</h1>
      <p className="subtitle">
        Let's Encrypt certificates issued via DNS-01 (acme-dns or BIND), regular
        and wildcard.
      </p>

      {error && <p className="error">{error}</p>}

      <div className="panel">
        <div className="panel-title">Issue a certificate</div>
        <form className="form-row" onSubmit={issue}>
          <input
            placeholder="certificate name (optional)"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <select value={domain} onChange={(e) => setDomain(e.target.value)}>
            <option value="">— choose domain —</option>
            {domains.map((d) => (
              <option key={d.id} value={d.name}>
                {d.name}
              </option>
            ))}
          </select>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={wildcard}
              onChange={(e) => setWildcard(e.target.checked)}
            />
            Wildcard (*.{domain || "domain"})
          </label>
          <select value={strategy} onChange={(e) => setStrategy(e.target.value as "acme-dns" | "bind")}>
            <option value="acme-dns">acme-dns</option>
            <option value="bind">BIND nsupdate</option>
          </select>
          <button type="submit" disabled={busy || !domain}>
            {busy ? "Starting…" : "Issue"}
          </button>
        </form>
        {wildcard && (
          <p className="muted" style={{ marginTop: 0 }}>
            Wildcard certificates cover {domain || "the domain"} and all
            subdomains (e.g. <span className="mono">*.{domain || "domain"}</span>).
          </p>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">Issued certificates</div>
        {certs.length === 0 ? (
          <div className="empty">No certificates yet</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Domains</th>
                <th>Strategy</th>
                <th>Status</th>
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
                  </td>
                  <td className="mono">{c.domains.join(", ")}</td>
                  <td>
                    <span className="badge gray">{c.strategy}</span>
                  </td>
                  <td>{statusBadge(c)}</td>
                  <td>{c.status === "issued" ? healthBadge(c) : <span className="muted">—</span>}</td>
                  <td>{expiryCell(c)}</td>
                  <td>
                    <div className="actions">
                      <button className="secondary small" onClick={() => showDetail(c)}>
                        View
                      </button>
                      <button className="secondary small" onClick={() => renew(c)} disabled={c.status === "issuing"}>
                        Renew
                      </button>
                      <button className="secondary small" onClick={() => exportToNpm(c)} disabled={!c.hasMaterial}>
                        → NPM
                      </button>
                      <button className="danger small" onClick={() => remove(c)}>
                        ✕
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {detail && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 50,
          }}
          onClick={() => setDetail(null)}
        >
          <div
            className="panel"
            style={{ width: 760, maxHeight: "80vh", overflow: "auto", margin: 0 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="panel-title">
              {detail.name} — {detail.domains.join(", ")}
              {detail.status === "error" && (
                <p className="error" style={{ marginTop: 8 }}>
                  {detail.error}
                </p>
              )}
            </div>
            <p className="muted">
              Issued: {detail.issuedAt ? new Date(detail.issuedAt).toLocaleString() : "—"} · Expires:{" "}
              {detail.expiresAt ? new Date(detail.expiresAt).toLocaleString() : "—"} · Auto-renew:{" "}
              {detail.autoRenew ? "on" : "off"}
            </p>
            {health && (
              <div style={{ margin: "8px 0" }}>
                <p className="panel-title" style={{ marginBottom: 6 }}>
                  Health: {health.grade} ({health.score}/100)
                </p>
                <table>
                  <tbody>
                    {health.checks.map((c) => (
                      <tr key={c.name}>
                        <td style={{ width: 140 }}>
                          <span
                            className={`status-dot ${c.status === "ok" ? "ok" : c.status === "warn" ? "warn" : "err"}`}
                          />
                          {c.name}
                        </td>
                        <td className="muted">{c.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {material ? (
              <>
                <p className="panel-title" style={{ marginBottom: 6 }}>Fullchain (PEM)</p>
                <textarea readOnly value={material.certificate} />
                <p className="panel-title" style={{ marginBottom: 6 }}>Private key (PEM)</p>
                <textarea readOnly value={material.key} />
              </>
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
