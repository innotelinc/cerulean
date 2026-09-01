import { useEffect, useState } from "react";
import { api } from "../api";
import type { Certificate, NpmCertificate, NpmProxyHost } from "../types";

export default function NpmExport() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [npmCerts, setNpmCerts] = useState<NpmCertificate[]>([]);
  const [npmHosts, setNpmHosts] = useState<NpmProxyHost[]>([]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [busy, setBusy] = useState(false);

  // proxy host form
  const [domain, setDomain] = useState("");
  const [forwardHost, setForwardHost] = useState("");
  const [forwardPort, setForwardPort] = useState(3000);
  const [forwardScheme, setForwardScheme] = useState("http");
  const [useSsl, setUseSsl] = useState(true);
  const [certSel, setCertSel] = useState("");

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 4000);
  };

  const load = async () => {
    try {
      const [c, nc, nh] = await Promise.all([
        api.listCertificates(),
        api.npmCertificates(),
        api.npmHosts(),
      ]);
      setCerts(c);
      setNpmCerts(nc);
      setNpmHosts(nh);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load NPM data");
    }
  };

  useEffect(() => {
    load();
  }, []);

  const exportCert = async (c: Certificate) => {
    setBusy(true);
    try {
      const result = await api.exportCert({ certificate_id: c.id });
      flash(`Exported "${c.domain}" → NPM certificate #${result.npmCertificateId}`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setBusy(false);
    }
  };

  const createHost = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain || !forwardHost) return;
    setBusy(true);
    setError("");
    try {
      let certId: number | undefined;
      if (useSsl && certSel) {
        if (certSel.startsWith("cerulean:")) {
          const cert = certs.find((c) => c.id === Number(certSel.slice(9)));
          if (!cert) throw new Error("Selected certificate not found");
          const result = await api.exportCert({ certificate_id: cert.id });
          certId = result.npmCertificateId;
        } else {
          certId = Number(certSel);
        }
      }
      await api.createNpmHost({
        domain,
        forward_host: forwardHost,
        forward_port: forwardPort,
        forward_scheme: forwardScheme,
        certificate_id: certId,
        ssl_forced: useSsl,
        http2_support: true,
      });
      flash(`Proxy host created for ${domain}`);
      setDomain("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create proxy host");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1>nginx proxy manager</h1>
      <p className="subtitle">
        One-click export of Cerulean certificates and proxy host creation on
        your nginx proxy manager instance.
      </p>

      {error && <p className="error">{error}</p>}

      <div className="panel">
        <div className="panel-title">Create a proxy host</div>
        <form onSubmit={createHost}>
          <div className="form-row">
            <label>Domain</label>
            <input
              placeholder="e.g. app.innotel.us"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              style={{ flex: 1 }}
            />
          </div>
          <div className="form-row">
            <label>Forward to</label>
            <input
              placeholder="192.168.1.x"
              value={forwardHost}
              onChange={(e) => setForwardHost(e.target.value)}
              style={{ flex: 1 }}
            />
            <input
              type="number"
              placeholder="port"
              value={forwardPort}
              onChange={(e) => setForwardPort(Number(e.target.value))}
              style={{ width: 90 }}
            />
            <select
              value={forwardScheme}
              onChange={(e) => setForwardScheme(e.target.value)}
            >
              <option value="http">http</option>
              <option value="https">https</option>
            </select>
          </div>
          <div className="form-row">
            <label>SSL certificate</label>
            <label className="checkbox-row" style={{ minWidth: 0 }}>
              <input
                type="checkbox"
                checked={useSsl}
                onChange={(e) => setUseSsl(e.target.checked)}
              />
              Enable SSL
            </label>
            {useSsl && (
              <select
                value={certSel}
                onChange={(e) => setCertSel(e.target.value)}
                style={{ flex: 1 }}
              >
                <option value="">— choose certificate —</option>
                <optgroup label="Cerulean (auto-export)">
                  {certs
                    .filter((c) => c.hasMaterial)
                    .map((c) => (
                      <option key={c.id} value={`cerulean:${c.id}`}>
                        {c.name} ({c.domains.join(", ")})
                      </option>
                    ))}
                </optgroup>
                <optgroup label="Already in NPM">
                  {npmCerts.map((c) => (
                    <option key={c.id} value={c.id}>
                      #{c.id} {c.nice_name}
                    </option>
                  ))}
                </optgroup>
              </select>
            )}
          </div>
          <button type="submit" disabled={busy}>
            {busy ? "Creating…" : "Create proxy host"}
          </button>
        </form>
      </div>

      <div className="panel">
        <div className="panel-title">Export Cerulean certificates</div>
        {certs.filter((c) => c.hasMaterial).length === 0 ? (
          <div className="empty">
            No issued certificates to export — issue one on the Certificates page.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Certificate</th>
                <th>Status</th>
                <th>Already in NPM</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {certs
                .filter((c) => c.hasMaterial)
                .map((c) => {
                  const inNpm = npmCerts.filter((nc) =>
                    nc.domain_names.some((dn) => c.domains.includes(dn)),
                  );
                  return (
                    <tr key={c.id}>
                      <td>
                        <strong>{c.name}</strong>
                        <div className="muted mono">{c.domains.join(", ")}</div>
                      </td>
                      <td>
                        <span className="badge green">issued</span>
                      </td>
                      <td>
                        {inNpm.length ? (
                          inNpm.map((nc) => (
                            <span key={nc.id} className="badge blue" style={{ marginRight: 4 }}>
                              #{nc.id} {nc.nice_name}
                            </span>
                          ))
                        ) : (
                          <span className="muted">not yet</span>
                        )}
                      </td>
                      <td>
                        <button className="secondary small" onClick={() => exportCert(c)} disabled={busy}>
                          Export to NPM
                        </button>
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">Existing proxy hosts ({npmHosts.length})</div>
        {npmHosts.length === 0 ? (
          <div className="empty">No proxy hosts found (or NPM is unreachable).</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Forward</th>
                <th>SSL</th>
                <th>Enabled</th>
              </tr>
            </thead>
            <tbody>
              {npmHosts.map((h) => (
                <tr key={h.id}>
                  <td className="mono">{h.domain_names.join(", ")}</td>
                  <td className="mono">
                    {h.forward_scheme}://{h.forward_host}:{h.forward_port}
                  </td>
                  <td>
                    {h.certificate_id ? (
                      <span className="badge green">cert #{h.certificate_id}</span>
                    ) : (
                      <span className="badge gray">none</span>
                    )}
                  </td>
                  <td>
                    {h.enabled ? (
                      <span className="badge green">enabled</span>
                    ) : (
                      <span className="badge gray">disabled</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
