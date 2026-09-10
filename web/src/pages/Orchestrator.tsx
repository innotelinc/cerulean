import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { BlockingStatus, CrsRegistryEntry, CrsStatus, DhcpLease, DhcpScope, OrchestratorStatus, ServerIdentity, ServiceApiKey } from "../types";

export default function Orchestrator() {
  const [ident, setIdent] = useState<ServerIdentity | null>(null);
  const [orch, setOrch] = useState<OrchestratorStatus | null>(null);
  const [scopes, setScopes] = useState<DhcpScope[]>([]);
  const [leases, setLeases] = useState<DhcpLease[]>([]);
  const [blocking, setBlocking] = useState<BlockingStatus | null>(null);
  const [blocked, setBlocked] = useState<string[]>([]);
  const [allowed, setAllowed] = useState<string[]>([]);
  const [crs, setCrs] = useState<CrsStatus | null>(null);
  const [registry, setRegistry] = useState<CrsRegistryEntry[]>([]);
  const [serviceKeys, setServiceKeys] = useState<ServiceApiKey[]>([]);
  const [newKeyToken, setNewKeyToken] = useState<string | null>(null);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyScopes, setNewKeyScopes] = useState("*");
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
      try { const c = await api.crsStatus(); setCrs(c as unknown as CrsStatus); } catch { setCrs(null); }
      try { const r = await api.crsRegistry(); setRegistry(r.entries as unknown as CrsRegistryEntry[]); } catch { setRegistry([]); }
      try { setServiceKeys(await api.serviceKeys()); } catch { setServiceKeys([]); }
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
        <div className="panel-title">Central Registration (CRS) — home <span className="mono" style={{ fontWeight: 400 }}>{crs?.homeUrl ?? "—"}</span></div>
        {!crs ? <p className="muted">Loading CRS…</p> : (
          <>
            <table><tbody>
              <tr><td>Desired role</td><td className="mono">{crs.desiredRole}</td><td className="muted">CRS_ROLE env</td></tr>
              <tr><td>Resolved role</td><td><span className={`badge ${crs.isAirGapped ? "amber" : crs.isMaster && crs.resolvedRole === "master" ? "green" : crs.resolvedRole === "slave" ? "green" : "gray"}`}>{crs.resolvedRole}</span>{crs.isAirGapped ? <span className="badge amber" style={{ marginLeft: 8 }}>air-gapped / isolated master</span> : null}</td><td>{crs.error ? <span className="error">{crs.error}</span> : <span className="muted">{crs.reachable === null ? "not probed yet" : crs.reachable ? (crs.isMaster && crs.resolvedRole === "master" ? "home reachable" : "master reachable") : (crs.isMaster && crs.resolvedRole === "master" ? "home unreachable — isolated" : "master unreachable")}</span>}</td></tr>
              <tr><td>Authority domain</td><td className="mono">{crs.domain}</td><td className="muted">{crs.isMaster ? "this node assigns serverIds for this domain" : `slave to ${crs.masterUrl}`}</td></tr>
              <tr><td>Master / Home</td><td className="mono" style={{ fontSize: 12 }}>{crs.masterUrl}</td><td className="muted mono" style={{ fontSize: 12 }}>{crs.homeUrl}</td></tr>
              <tr><td>Registry</td><td className="mono">{crs.registryCount} entries · {crs.localCount} replica</td><td className="muted">{crs.lastSyncAt ? `last sync ${new Date(crs.lastSyncAt).toLocaleString()}` : "never synced"}{crs.lastSyncStatus ? ` — ${crs.lastSyncStatus.slice(0, 80)}` : ""}</td></tr>
            </tbody></table>
            <div className="actions" style={{ marginTop: 12 }}>
              <button className="secondary small" onClick={async () => { setBusy(true); try { const r = await api.crsResolve(); setCrs(r.status as unknown as CrsStatus); flash(`Re-resolved → ${r.resolvedRole}`); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } }} disabled={busy}>Re-probe master</button>
              <button className="secondary small" onClick={async () => { setBusy(true); try { const r = await api.crsRegisterSelf(); flash(`Registered ${r.serverId} @ ${r.apex}`); await load(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } }} disabled={busy}>Register this node to master</button>
              <button className="secondary small" onClick={async () => { setBusy(true); try { const r = await api.crsSync(); flash(`Sync pulled ${r.pulled}`); await load(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } }} disabled={busy}>Sync registry from master</button>
            </div>
            {registry.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>Registry preview (first 50) — full list via <span className="mono">GET /api/crs/registry</span> or <span className="mono">GET /api/service/crs/registry</span></div>
                <div style={{ maxHeight: 220, overflow: "auto", border: "1px solid var(--border)", borderRadius: 8 }}>
                  <table><thead><tr><th>Server ID</th><th>Apex</th><th>Source</th><th>Seen</th></tr></thead>
                    <tbody>{registry.slice(0, 50).map((e) => (
                      <tr key={e.serverId}><td className="mono">{e.serverId}</td><td className="mono">{e.apex}</td><td><span className={`badge ${e.source === "master" ? "green" : e.source === "replica" || e.source === "home" ? "gray" : "amber"}`}>{e.source}</span> <span className="muted">{e.role}</span></td><td className="muted" style={{ fontSize: 12 }}>{new Date(e.lastSeen).toLocaleDateString()}</td></tr>
                    ))}</tbody></table>
                </div>
              </div>
            )}
          </>
        )}
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

      <div className="panel">
        <div className="panel-title">Service API keys — other stacks → Cerulean <span className="muted" style={{ fontWeight: 400 }}>(Bearer <span className="mono">ceru_…</span>)</span></div>
        <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>Create a key for another stack (or for a CRS slave) to call the service bridge. Scopes: <span className="mono">*</span>, <span className="mono">crs:register</span>, <span className="mono">dns:*</span>, <span className="mono">certs:write</span>, <span className="mono">dhcp:read</span>, etc. CRS also accepts <span className="mono">CRS_TOKEN</span> as a lightweight shared secret.</p>
        <div className="form-row" style={{ marginTop: 8 }}>
          <input placeholder="key name (e.g. innotel-core)" value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)} style={{ flex: 1 }} />
          <input placeholder="scopes (e.g. * or crs:register,dns:*)" value={newKeyScopes} onChange={(e) => setNewKeyScopes(e.target.value)} style={{ flex: 1 }} />
          <button className="secondary small" disabled={busy || !newKeyName.trim()} onClick={async () => {
            setBusy(true); setError("");
            try {
              const scopes = newKeyScopes.split(",").map((s) => s.trim()).filter(Boolean);
              const k = await api.createServiceKey({ name: newKeyName.trim(), scopes: scopes.length ? scopes : ["*"] });
              setNewKeyToken(k.token ?? null);
              setNewKeyName("");
              flash(`Created key ${k.prefix}… — copy the token now`);
              await load();
            } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
            finally { setBusy(false); }
          }}>Create key</button>
        </div>
        {newKeyToken && (
          <div style={{ marginTop: 10, padding: 10, borderRadius: 8, background: "var(--card)", border: "1px solid var(--border)" }}>
            <div className="muted" style={{ fontSize: 12 }}>Copy this token now — it is shown only once:</div>
            <div className="mono" style={{ wordBreak: "break-all", marginTop: 6, fontSize: 13 }}>{newKeyToken}</div>
            <div className="actions" style={{ marginTop: 8 }}>
              <button className="secondary small" onClick={() => { navigator.clipboard.writeText(newKeyToken); flash("Copied"); }}>Copy</button>
              <button className="secondary small" onClick={() => setNewKeyToken(null)}>Dismiss</button>
            </div>
          </div>
        )}
        {serviceKeys.length === 0 ? <p className="muted" style={{ marginTop: 10 }}>No service keys yet.</p> : (
          <table style={{ marginTop: 10 }}><thead><tr><th>Name</th><th>Prefix</th><th>Scopes</th><th>Created</th><th /></tr></thead>
            <tbody>{serviceKeys.map((k) => (
              <tr key={k.id}><td>{k.name}{k.revokedAt ? <span className="badge gray" style={{ marginLeft: 6 }}>revoked</span> : null}</td><td className="mono">{k.prefix}…</td><td className="mono" style={{ fontSize: 12 }}>{k.scopes.join(", ")}</td><td className="muted" style={{ fontSize: 12 }}>{new Date(k.createdAt).toLocaleDateString()}</td>
                <td><div className="actions">
                  {!k.revokedAt && <button className="secondary small" disabled={busy} onClick={async () => { if (!window.confirm(`Revoke key ${k.name}?`)) return; await api.revokeServiceKey(k.id); await load(); }}>Revoke</button>}
                  <button className="danger small" disabled={busy} onClick={async () => { if (!window.confirm(`Delete key ${k.name}? This cannot be undone.`)) return; await api.deleteServiceKey(k.id); await load(); }}>Delete</button>
                </div></td></tr>
            ))}</tbody></table>
        )}
        <p className="muted" style={{ fontSize: 12, marginTop: 10 }}>Service bridge (Bearer <span className="mono">ceru_…</span>): <span className="mono">GET /api/service/status</span> · <span className="mono">/service/crs/*</span> · <span className="mono">/service/domains</span> · <span className="mono">/service/certificates</span> · <span className="mono">/service/dns/records</span> · <span className="mono">/service/dhcp/*</span> · <span className="mono">/service/blocking/status</span> · <span className="mono">/service/pki/*</span></p>
      </div>

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
