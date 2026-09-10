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

  useEffect(() => { load(); }, []);

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
    s === "ok" ? <span className="status-dot ok" /> : s === "not-configured" || s === "off" ? <span className="status-dot warn" /> : <span className="status-dot err" />;

  // Infisical is the stack's secret store when enabled; HashiCorp Vault otherwise.
  const secretVault = status?.infisical?.enabled
    ? { status: status.infisical.status, addr: status.infisical.addr }
    : { status: status?.vault.status ?? "not-configured", addr: status?.vault.addr ?? "" };

  return (
    <div>
      <h1>Settings</h1>
      <p className="subtitle">Orchestrator, Technitium & configuration summary.</p>

      {error && <p className="error">{error}</p>}

      {!status ? (
        <p className="muted">Loading…</p>
      ) : (
        <>
          <div className="panel">
            <div className="panel-title">Master orchestrator</div>
            <table><tbody>
              <tr><td style={{ width: 260 }}>Server ID</td><td className="mono">{status.server.serverId}</td><td className="muted mono">{status.server.apex}</td></tr>
              <tr><td>Wildcard</td><td className="mono">{status.server.wildcard}</td><td className="muted">{status.server.wildcardValidityDays} days · {status.server.autoWildcard ? "auto" : "manual"} · {status.server.registered ? "registered" : "standalone"}</td></tr>
              <tr><td>Orchestrator</td><td>{status.orchestrator.enabled ? <span className="badge green">on</span> : <span className="badge gray">off</span>}</td><td className="muted">DHCP {status.orchestrator.dhcpEnabled ? "on" : "off"} · Blocking {status.orchestrator.blockingEnabled ? "on" : "off"}</td></tr>
            </tbody></table>
          </div>

          <div className="panel">
            <div className="panel-title">Integrations</div>
            <table>
              <tbody>
                <tr>
                  <td style={{ width: 260 }}>{dot(status.technitium.status)} Technitium DNS · DHCP · Blocking</td>
                  <td className="mono">{status.technitium.status}</td>
                  <td className="muted mono">{status.technitium.detail}</td>
                </tr>
                <tr>
                  <td>{dot(status.dhcp.status)} DHCP</td>
                  <td className="mono">{status.dhcp.enabled ? status.dhcp.status : "disabled"}</td>
                  <td className="muted mono">{status.dhcp.detail} {status.dhcp.scopes ? `· ${status.dhcp.scopes} scopes · ${status.dhcp.leases} leases` : ""}</td>
                </tr>
                <tr>
                  <td>{dot(status.blocking.status)} Ad-blocking</td>
                  <td className="mono">{status.blocking.enabled ? status.blocking.status : "disabled"}</td>
                  <td className="muted mono">{status.blocking.detail} {status.blocking.blockedZones ? `· ${status.blocking.blockedZones} blocked` : ""}</td>
                </tr>
                <tr>
                  <td>{dot(status.npm.status)} nginx proxy manager</td>
                  <td className="mono">{status.npm.status}</td>
                  <td className="muted mono">{status.config.npmApiUrl || "—"}</td>
                </tr>
                <tr>
                  <td>{dot(status.auth.oidcEnabled ? "ok" : "warn")} Authentik (OIDC)</td>
                  <td className="mono">{status.auth.oidcEnabled ? "configured" : "not-configured"}</td>
                  <td className="muted mono">{status.auth.issuerUrl || "set AUTHENTIK_* in .env"}</td>
                </tr>
                <tr>
                  <td>{dot(secretVault.status)} Secret vault {status.infisical?.enabled ? "(Infisical)" : "(HashiCorp Vault)"}</td>
                  <td className="mono">{secretVault.status}</td>
                  <td className="muted mono">{secretVault.addr || (status.infisical?.enabled ? "set INFISICAL_ADDR/INFISICAL_TOKEN in .env" : "set VAULT_ADDR/VAULT_TOKEN in .env")}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="panel">
            <div className="panel-title">Configuration</div>
            <table>
              <tbody>
                <tr><td style={{ width: 260 }}>Primary zone</td><td className="mono">{status.config.zone}</td></tr>
                <tr><td>Technitium URL</td><td className="mono">{status.config.technitiumUrl}</td></tr>
                <tr><td>ACME directory</td><td className="mono">{status.config.acmeDirectoryUrl}</td></tr>
                <tr><td>ACME email</td><td className="mono">{status.config.acmeEmail}</td></tr>
                <tr><td>Certificate discovery dirs</td><td className="mono">{status.discovery.dirs.length ? status.discovery.dirs.join(", ") : "none (NPM only)"}</td></tr>
              </tbody>
            </table>
            <div className="actions" style={{ marginTop: 14 }}>
              <button onClick={load} className="secondary">Re-test connections</button>
              <button onClick={runSweep} className="secondary" disabled={sweeping}>{sweeping ? "Running…" : "Run renewal sweep now"}</button>
            </div>
          </div>

          <div className="panel">
            <div className="panel-title">How DNS-01 works now</div>
            <p className="muted" style={{ lineHeight: 1.6 }}>
              Cerulean writes DNS-01 challenge TXT records via Technitium&apos;s HTTP API
              (<span className="mono">/api/zones/records/add</span>) and polls Technitium as authoritative
              before Let&apos;s Encrypt validates. No SSH, no TSIG, no <span className="mono">nsupdate</span>.
              The 90-day wildcard is issued offline via internal PKI first, then upgraded to ACME when online.
            </p>
          </div>
        </>
      )}

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
