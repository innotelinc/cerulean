import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { BlockingStatus, DhcpLease, DhcpScope, OrchestratorStatus, ServerIdentity } from "../types";

export default function Orchestrator() {
  const [ident, setIdent] = useState<ServerIdentity | null>(null);
  const [orch, setOrch] = useState<OrchestratorStatus | null>(null);
  const [scopes, setScopes] = useState<DhcpScope[]>([]);
  const [leases, setLeases] = useState<DhcpLease[]>([]);
  const [blocking, setBlocking] = useState<BlockingStatus | null>(null);
  const [blocked, setBlocked] = useState<string[]>([]);
  const [allowed, setAllowed] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [busy, setBusy] = useState(false);

  const [editId, setEditId] = useState("");
  const [editLab, setEditLab] = useState("");
  const [scopeForm, setScopeForm] = useState({ name: "", startingAddress: "", endingAddress: "", subnetMask: "255.255.255.0", routerAddress: "", domainName: "", useThisDnsServer: true });
  const [blockToggle, setBlockToggle] = useState(false);
  const [addBlockedDomain, setAddBlockedDomain] = useState("");
  const [addAllowedDomain, setAddAllowedDomain] = useState("");
  const [blockListUrls, setBlockListUrls] = useState("");

  const flash = (msg: string) => { setToast(msg); setTimeout(() => setToast(""), 4000); };

  const load = useCallback(async () => {
    try {
      const [i, o] = await Promise.all([api.serverIdentity(), api.orchestratorStatus()]);
      setIdent(i);
      setOrch(o);
      setBlockToggle(o.blocking.enabled);
      setBlockListUrls(o.blocking.blockListUrls.join(", "));
      setBlocking(o.blocking);
      setError("");
      try { setScopes(await api.dhcpScopes()); } catch { setScopes([]); }
      try { setLeases(await api.dhcpLeases()); } catch { setLeases([]); }
      try { setBlocked(await api.listBlocked()); } catch { setBlocked([]); }
      try { setAllowed(await api.listAllowed()); } catch { setAllowed([]); }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load orchestrator");
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const saveIdentity = async () => {
    if (!editId && !editLab) { setError("Enter a server ID or lab domain"); return; }
    setBusy(true); setError("");
    try {
      await api.updateServerIdentity({ serverId: editId || undefined, labDomain: editLab || undefined });
      flash("Server identity updated");
      setEditId(""); setEditLab("");
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Update failed"); }
    finally { setBusy(false); }
  };

  const register = async () => {
    setBusy(true); setError("");
    try {
      const r = await api.registerServer();
      flash(r.registered ? "Registered with central" : `Registration: ${r.detail}`);
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Registration failed"); }
    finally { setBusy(false); }
  };

  const renewWildcard = async () => {
    setBusy(true); setError("");
    try {
      const r = await api.renewWildcard();
      const pki = r.pki ? `PKI cert #${r.pki.certId}` : "PKI skipped";
      flash(`${pki} · ACME: ${r.acme.detail}`);
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Renewal failed"); }
    finally { setBusy(false); }
  };

  const createScope = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      await api.createDhcpScope(scopeForm);
      flash(`DHCP scope ${scopeForm.name} created`);
      setScopeForm({ name: "", startingAddress: "", endingAddress: "", subnetMask: "255.255.255.0", routerAddress: "", domainName: "", useThisDnsServer: true });
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Create scope failed"); }
    finally { setBusy(false); }
  };

  const toggleBlocking = async () => {
    setBusy(true); setError("");
    try {
      await api.setBlocking({ enableBlocking: !blockToggle });
      flash(!blockToggle ? "Blocking enabled" : "Blocking disabled");
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Toggle failed"); }
    finally { setBusy(false); }
  };

  const saveBlockLists = async () => {
    setBusy(true); setError("");
    try {
      await api.setBlocking({ blockListUrls: blockListUrls.trim() || "false" });
      flash("Block lists updated");
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Update failed"); }
    finally { setBusy(false); }
  };



  return (
    <div>
      <h1>Master Orchestrator</h1>
      <p className="subtitle">
        Plug-anywhere control plane — DHCP, DNS, certificates & ad-blocking via Technitium. Works offline.
      </p>
      {error && <p className="error">{error}</p>}

      <div className="cards">
        <div className="card">
          <div className="num mono" style={{ fontSize: 16 }}>{ident?.apex ?? "—"}</div>
          <div className="label">Apex ({ident?.serverId}.{ident?.labDomain})</div>
          <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{ident?.wildcard}</div>
        </div>
        <div className="card">
          <div className="num">{orch ? (orch.technitium.reachable ? "Reachable" : "Offline") : "—"}</div>
          <div className="label">Technitium DNS · {orch?.technitium.url ?? "—"}</div>
          <div className="muted" style={{ fontSize: 12 }}>{orch?.technitium.detail ?? ""}</div>
        </div>
        <div className="card">
          <div className="num">{scopes.length}</div>
          <div className="label">DHCP scopes · {leases.length} leases</div>
        </div>
        <div className="card">
          <div className="num">{blocking?.enabled ? "On" : "Off"}</div>
          <div className="label">Ad-blocking · {blocked.length} blocked</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-title">Server identity</div>
        {!ident ? <p className="muted">Loading…</p> : (
          <>
            <table><tbody>
              <tr><td>Server ID</td><td className="mono">{ident.serverId}</td><td>{ident.registered ? <span className="badge green">registered</span> : <span className="badge amber">standalone</span>}</td></tr>
              <tr><td>Lab domain</td><td className="mono">{ident.labDomain}</td><td className="muted">{ident.apex}</td></tr>
              <tr><td>Wildcard</td><td className="mono">{ident.wildcard}</td><td className="muted">{ident.wildcardValidityDays} days · {ident.autoWildcard ? "auto" : "manual"}</td></tr>
              <tr><td>Wildcard cert</td><td>{ident.wildcardCert ? <><span className={`badge ${ident.wildcardCert.status === "issued" ? "green" : "amber"}`}>{ident.wildcardCert.status}</span> <span className="mono">{ident.wildcardCert.domains.join(", ")}</span> <span className="muted">source:{ident.wildcardCert.source ?? "—"}</span></> : <span className="muted">none yet</span>}</td><td>{ident.wildcardCert?.expiresAt ? new Date(ident.wildcardCert.expiresAt).toLocaleDateString() : ""}</td></tr>
              <tr><td>Registration</td><td className="muted mono">{ident.registerUrl ?? "(not configured)"}</td><td>{ident.centralUrl ? <span className="muted mono">{ident.centralUrl}</span> : null}</td></tr>
            </tbody></table>
            <div className="actions" style={{ marginTop: 14 }}>
              <button className="secondary small" onClick={register} disabled={busy}>Register now</button>
              <button className="secondary small" onClick={renewWildcard} disabled={busy}>Renew wildcard (PKI → ACME)</button>
            </div>
            <div className="form-row" style={{ marginTop: 14 }}>
              <input placeholder="new server ID (e.g. alpha-7f3a)" value={editId} onChange={(e) => setEditId(e.target.value)} style={{ flex: 1 }} />
              <input placeholder="lab domain (e.g. lab.innotel.us)" value={editLab} onChange={(e) => setEditLab(e.target.value)} style={{ flex: 1 }} />
              <button onClick={saveIdentity} disabled={busy}>Update identity</button>
            </div>
          </>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">DHCP scopes {scopes.length > 0 ? `(${scopes.length})` : ""}</div>
        {scopes.length === 0 ? <div className="empty">No scopes — create one below. Requires Technitium with DHCP enabled.</div> : (
          <table><thead><tr><th>Name</th><th>Range</th><th>Mask</th><th>Enabled</th><th /></tr></thead>
            <tbody>{scopes.map((s) => (
              <tr key={s.name}><td className="mono">{s.name}</td><td className="mono">{s.startingAddress} – {s.endingAddress}</td><td className="mono">{s.subnetMask}</td><td>{s.enabled ? <span className="badge green">on</span> : <span className="badge gray">off</span>}</td>
                <td>
                  <div className="actions">
                    {s.enabled
                      ? <button className="secondary small" onClick={async () => { await api.disableDhcpScope(s.name); await load(); }} disabled={busy}>Disable</button>
                      : <button className="secondary small" onClick={async () => { await api.enableDhcpScope(s.name); await load(); }} disabled={busy}>Enable</button>}
                    <button className="danger small" onClick={async () => { if (window.confirm(`Delete scope ${s.name}?`)) { await api.deleteDhcpScope(s.name); await load(); } }} disabled={busy}>Delete</button>
                  </div>
                </td></tr>
            ))}</tbody></table>
        )}
        <form onSubmit={createScope} style={{ marginTop: 16, display: "flex", flexWrap: "wrap", gap: 8, alignItems: "end" }}>
          <label><span className="muted" style={{ fontSize: 12 }}>Name</span><br /><input value={scopeForm.name} onChange={(e) => setScopeForm((s) => ({ ...s, name: e.target.value }))} placeholder="lan" required /></label>
          <label><span className="muted" style={{ fontSize: 12 }}>Start</span><br /><input value={scopeForm.startingAddress} onChange={(e) => setScopeForm((s) => ({ ...s, startingAddress: e.target.value }))} placeholder="192.168.1.100" required /></label>
          <label><span className="muted" style={{ fontSize: 12 }}>End</span><br /><input value={scopeForm.endingAddress} onChange={(e) => setScopeForm((s) => ({ ...s, endingAddress: e.target.value }))} placeholder="192.168.1.200" required /></label>
          <label><span className="muted" style={{ fontSize: 12 }}>Mask</span><br /><input value={scopeForm.subnetMask} onChange={(e) => setScopeForm((s) => ({ ...s, subnetMask: e.target.value }))} placeholder="255.255.255.0" required /></label>
          <label><span className="muted" style={{ fontSize: 12 }}>Router</span><br /><input value={scopeForm.routerAddress} onChange={(e) => setScopeForm((s) => ({ ...s, routerAddress: e.target.value }))} placeholder="192.168.1.1" /></label>
          <label><span className="muted" style={{ fontSize: 12 }}>Domain</span><br /><input value={scopeForm.domainName} onChange={(e) => setScopeForm((s) => ({ ...s, domainName: e.target.value }))} placeholder={ident?.apex ?? "lan"} /></label>
          <label style={{ display: "flex", gap: 6, alignItems: "center" }}><input type="checkbox" checked={scopeForm.useThisDnsServer} onChange={(e) => setScopeForm((s) => ({ ...s, useThisDnsServer: e.target.checked }))} /> Use this DNS</label>
          <button type="submit" disabled={busy}>Create scope</button>
        </form>
      </div>

      {leases.length > 0 && (
        <div className="panel">
          <div className="panel-title">DHCP leases ({leases.length})</div>
          <table><thead><tr><th>Scope</th><th>IP</th><th>MAC</th><th>Hostname</th><th>Expires</th></tr></thead>
            <tbody>{leases.map((l, i) => (
              <tr key={`${l.hardwareAddress}-${i}`}><td className="muted">{l.scope}</td><td className="mono">{l.address}</td><td className="mono">{l.hardwareAddress}</td><td className="muted">{l.hostName ?? "—"}</td><td className="muted">{new Date(l.leaseExpires).toLocaleString()}</td></tr>
            ))}</tbody></table>
        </div>
      )}

      <div className="panel">
        <div className="panel-title">Ad-blocking {blocking && (blocking.enabled ? "· on" : "· off")}</div>
        <div className="actions" style={{ marginBottom: 12 }}>
          <button className={blockToggle ? "danger small" : "secondary small"} onClick={toggleBlocking} disabled={busy}>{blockToggle ? "Disable blocking" : "Enable blocking"}</button>
          <button className="secondary small" onClick={async () => { await api.refreshBlockLists(); flash("Block lists refreshing"); }} disabled={busy}>Refresh lists</button>
          <span className="muted" style={{ fontSize: 12, alignSelf: "center" }}>{blocking?.detail ?? ""} · {blocked.length} blocked · {allowed.length} allowed</span>
        </div>
        <div className="form-row">
          <input value={blockListUrls} onChange={(e) => setBlockListUrls(e.target.value)} placeholder="block list URLs (comma-separated) or empty to clear" style={{ flex: 1 }} />
          <button className="secondary small" onClick={saveBlockLists} disabled={busy}>Save lists</button>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 12 }}>
          <div>
            <div className="panel-title" style={{ fontSize: 13 }}>Blocked domains</div>
            <form onSubmit={async (e) => { e.preventDefault(); if (!addBlockedDomain.trim()) return; await api.addBlocked(addBlockedDomain.trim()); setAddBlockedDomain(""); await load(); }} className="form-row">
              <input value={addBlockedDomain} onChange={(e) => setAddBlockedDomain(e.target.value)} placeholder="ads.example.com" style={{ flex: 1 }} />
              <button type="submit" className="secondary small" disabled={busy}>Block</button>
            </form>
            <div style={{ maxHeight: 200, overflow: "auto", border: "1px solid var(--border)", borderRadius: 8, padding: 6 }}>
              {blocked.length === 0 ? <div className="muted" style={{ padding: 8 }}>No blocked zones</div> :
                blocked.map((d) => (
                  <div key={d} className="form-row" style={{ marginBottom: 4 }}><span className="mono" style={{ flex: 1 }}>{d}</span><button className="danger small" onClick={async () => { await api.deleteBlocked(d); await load(); }}>✕</button></div>
                ))}
            </div>
          </div>
          <div>
            <div className="panel-title" style={{ fontSize: 13 }}>Allowed (exceptions)</div>
            <form onSubmit={async (e) => { e.preventDefault(); if (!addAllowedDomain.trim()) return; await api.addAllowed(addAllowedDomain.trim()); setAddAllowedDomain(""); await load(); }} className="form-row">
              <input value={addAllowedDomain} onChange={(e) => setAddAllowedDomain(e.target.value)} placeholder="ads.example.com" style={{ flex: 1 }} />
              <button type="submit" className="secondary small" disabled={busy}>Allow</button>
            </form>
            <div style={{ maxHeight: 200, overflow: "auto", border: "1px solid var(--border)", borderRadius: 8, padding: 6 }}>
              {allowed.length === 0 ? <div className="muted" style={{ padding: 8 }}>No allowed zones</div> :
                allowed.map((d) => (
                  <div key={d} className="form-row" style={{ marginBottom: 4 }}><span className="mono" style={{ flex: 1 }}>{d}</span><button className="danger small" onClick={async () => { await api.deleteAllowed(d); await load(); }}>✕</button></div>
                ))}
            </div>
          </div>
        </div>
      </div>

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
