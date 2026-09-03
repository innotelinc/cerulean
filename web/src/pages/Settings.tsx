import { useEffect, useState } from "react";
import { api } from "../api";
import type { StatusResponse } from "../types";

export default function Settings() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [sweeping, setSweeping] = useState(false);

  const load = async () => {
    try {
      setStatus(await api.status());
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load status");
    }
  };

  useEffect(() => {
    load();
  }, []);

  const runSweep = async () => {
    setSweeping(true);
    try {
      const res = await fetch("/api/renewal-sweep", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("cerulean_token") || ""}`,
        },
      });
      if (!res.ok) throw new Error(`Sweep failed (HTTP ${res.status})`);
      setToast("Renewal sweep complete");
      setTimeout(() => setToast(""), 4000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sweep failed");
    } finally {
      setSweeping(false);
    }
  };

  const dot = (s: string) =>
    s === "ok" ? <span className="status-dot ok" /> : s === "not-configured" ? <span className="status-dot warn" /> : <span className="status-dot err" />;

  return (
    <div>
      <h1>Settings</h1>
      <p className="subtitle">Integration health and configuration summary.</p>

      {error && <p className="error">{error}</p>}

      {!status ? (
        <p className="muted">Loading…</p>
      ) : (
        <>
          <div className="panel">
            <div className="panel-title">Integrations</div>
            <table>
              <tbody>
                <tr>
                  <td style={{ width: 260 }}>{dot(status.bind.status)} BIND — SSH + nsupdate</td>
                  <td className="mono">{status.bind.status}</td>
                  <td className="muted mono">{status.bind.detail}</td>
                </tr>
                <tr>
                  <td>{dot(status.npm.status)} nginx proxy manager</td>
                  <td className="mono">{status.npm.status}</td>
                  <td className="muted mono">{status.config.npmApiUrl}</td>
                </tr>
                <tr>
                  <td>{dot(status.auth.oidcEnabled ? "ok" : "warn")} Authentik (OIDC)</td>
                  <td className="mono">{status.auth.oidcEnabled ? "configured" : "not-configured"}</td>
                  <td className="muted mono">{status.auth.issuerUrl || "set AUTHENTIK_* in .env"}</td>
                </tr>
                <tr>
                  <td>{dot(status.vault.status)} Secret vault (HashiCorp Vault)</td>
                  <td className="mono">{status.vault.status}</td>
                  <td className="muted mono">{status.vault.addr || "set VAULT_ADDR/VAULT_TOKEN in .env"}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="panel">
            <div className="panel-title">Configuration</div>
            <table>
              <tbody>
                <tr>
                  <td style={{ width: 260 }}>Primary zone</td>
                  <td className="mono">{status.config.zone}</td>
                </tr>
                <tr>
                  <td>ACME directory</td>
                  <td className="mono">{status.config.acmeDirectoryUrl}</td>
                </tr>
                <tr>
                  <td>ACME email</td>
                  <td className="mono">{status.config.acmeEmail}</td>
                </tr>
                <tr>
                  <td>BIND server</td>
                  <td className="mono">{status.config.bindHost}</td>
                </tr>
                <tr>
                  <td>BIND TSIG key</td>
                  <td>
                    {status.config.tsigConfigured ? (
                      <span className="badge green">configured</span>
                    ) : (
                      <span className="badge red">missing — run <span className="mono">tsig-keygen cerulean</span> on the BIND server</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td>Certificate discovery dirs</td>
                  <td className="mono">{status.discovery.dirs.length ? status.discovery.dirs.join(", ") : "none (NPM only)"}</td>
                </tr>
              </tbody>
            </table>
            <div className="actions" style={{ marginTop: 14 }}>
              <button onClick={load} className="secondary">
                Re-test connections
              </button>
              <button onClick={runSweep} className="secondary" disabled={sweeping}>
                {sweeping ? "Running…" : "Run renewal sweep now"}
              </button>
            </div>
          </div>

          <div className="panel">
            <div className="panel-title">How DNS-01 works here</div>
            <p className="muted" style={{ lineHeight: 1.6 }}>
              Cerulean writes DNS-01 challenge TXT records directly to BIND over
              SSH using nsupdate with a TSIG key, then waits for them to be served before
              Let's Encrypt validates. Requires <span className="mono">allow-update</span> for
              the TSIG key on each zone, and the zone must be reachable from the internet.
            </p>
          </div>
        </>
      )}

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
