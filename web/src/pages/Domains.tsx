import { useEffect, useState } from "react";
import { api } from "../api";
import type { Domain, DnsAudit, DnsRecord } from "../types";

const RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA", "PTR", "ANAME"];

export default function Domains() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");

  const [newName, setNewName] = useState("");
  const [adding, setAdding] = useState(false);

  const [openId, setOpenId] = useState<number | null>(null);
  const [records, setRecords] = useState<Record<number, DnsRecord[]>>({});
  const [recordsLoading, setRecordsLoading] = useState<Record<number, boolean>>({});
  const [recordsError, setRecordsError] = useState<Record<number, string>>({});

  const [auditFor, setAuditFor] = useState<Record<number, DnsAudit | null>>({});
  const [auditLoading, setAuditLoading] = useState<Record<number, boolean>>({});

  const runAudit = async (d: Domain) => {
    setAuditLoading((x) => ({ ...x, [d.id]: true }));
    setError("");
    try {
      const [audit] = await api.auditDns(d.name);
      setAuditFor((x) => ({ ...x, [d.id]: audit }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "DNS audit failed");
    } finally {
      setAuditLoading((x) => ({ ...x, [d.id]: false }));
    }
  };

  const [recType, setRecType] = useState("A");
  const [recName, setRecName] = useState("");
  const [recValue, setRecValue] = useState("");
  const [recTtl, setRecTtl] = useState(300);
  const [recPriority, setRecPriority] = useState(10);

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 4000);
  };

  const load = async () => {
    try {
      setDomains(await api.listDomains());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load domains");
    }
  };

  useEffect(() => { load(); }, []);

  const addDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    setAdding(true);
    setError("");
    try {
      await api.createDomain({ name: newName });
      setNewName("");
      flash(`Zone ${newName} created on Technitium`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add zone");
    } finally {
      setAdding(false);
    }
  };

  const toggleRecords = async (id: number) => {
    if (openId === id) {
      setOpenId(null);
      return;
    }
    setOpenId(id);
    if (!records[id]) {
      setRecordsLoading((r) => ({ ...r, [id]: true }));
      setRecordsError((r) => ({ ...r, [id]: "" }));
      try {
        const list = await api.listRecords(id);
        setRecords((r) => ({ ...r, [id]: list }));
      } catch (err) {
        setRecordsError((r) => ({
          ...r,
          [id]: err instanceof Error ? err.message : "Failed to fetch zone",
        }));
      } finally {
        setRecordsLoading((r) => ({ ...r, [id]: false }));
      }
    }
  };

  const submitRecord = async (e: React.FormEvent, domainId: number) => {
    e.preventDefault();
    try {
      await api.addRecord(domainId, {
        type: recType,
        name: recName,
        value: recValue,
        ttl: recTtl,
        priority: recType === "MX" || recType === "SRV" ? recPriority : undefined,
      });
      setRecName("");
      setRecValue("");
      flash(`Added ${recType} record`);
      const list = await api.listRecords(domainId);
      setRecords((r) => ({ ...r, [domainId]: list }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add record");
    }
  };

  const removeRecord = async (domainId: number, r: DnsRecord) => {
    if (!window.confirm(`Delete ${r.type} ${r.name} (${r.value})?`)) return;
    try {
      await api.deleteRecord(domainId, { type: r.type, name: r.name, value: r.value });
      flash("Record deleted");
      const list = await api.listRecords(domainId);
      setRecords((x) => ({ ...x, [domainId]: list }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete record");
    }
  };

  const removeDomain = async (d: Domain) => {
    if (!window.confirm(`Remove zone ${d.name} from Cerulean?`)) return;
    try {
      await api.deleteDomain(d.id);
      flash(`Zone ${d.name} removed`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove zone");
    }
  };

  return (
    <div>
      <h1>Domains</h1>
      <p className="subtitle">
        Authoritative zones on Technitium DNS — records managed via HTTP API (no SSH).
      </p>

      {error && <p className="error">{error}</p>}

      <div className="panel">
        <div className="panel-title">Create a zone</div>
        <form className="form-row" onSubmit={addDomain}>
          <input
            placeholder="e.g. srv-abc123.lab.innotel.us"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            style={{ flex: 1 }}
          />
          <button type="submit" disabled={adding || !newName}>
            {adding ? "Creating…" : "Create zone on Technitium"}
          </button>
        </form>
      </div>

      <div className="panel">
        <div className="panel-title">Managed zones {domains.length > 0 ? `(${domains.length})` : ""}</div>
        {domains.length === 0 ? (
          <div className="empty">No zones yet — create one above or let the orchestrator auto-create <span className="mono">&lt;serverId&gt;.lab.innotel.us</span>.</div>
        ) : (
          domains.map((d) => (
            <div key={d.id} style={{ marginBottom: 10 }}>
              <div className="form-row" style={{ marginBottom: 0 }}>
                <strong style={{ fontSize: 15 }}>{d.name}</strong>
                <span className="badge blue">Technitium</span>
                <div style={{ flex: 1 }} />
                <button className="secondary small" onClick={() => runAudit(d)} disabled={auditLoading[d.id]}>
                  {auditLoading[d.id] ? "Auditing…" : "Audit DNS"}
                </button>
                <button className="secondary small" onClick={() => toggleRecords(d.id)}>
                  {openId === d.id ? "Hide records" : "Records"}
                </button>
                <button className="danger small" onClick={() => removeDomain(d)}>
                  Remove
                </button>
              </div>

              {auditFor[d.id] && (
                <div style={{ margin: "10px 0 6px" }}>
                  <p className="panel-title" style={{ marginBottom: 6 }}>
                    DNS health:{" "}
                    <span
                      className={`badge ${auditFor[d.id]!.grade === "A" || auditFor[d.id]!.grade === "B" ? "green" : auditFor[d.id]!.grade === "C" ? "amber" : "red"}`}
                    >
                      {auditFor[d.id]!.grade} {auditFor[d.id]!.score}/100
                    </span>
                    <span className="muted" style={{ fontSize: 12 }}>
                      {" "}
                      {new Date(auditFor[d.id]!.runAt).toLocaleString()}
                    </span>
                  </p>
                  <table>
                    <tbody>
                      {auditFor[d.id]!.checks.map((c) => (
                        <tr key={c.name}>
                          <td style={{ width: 160 }}>
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

              {openId === d.id && (
                <div style={{ margin: "10px 0 6px" }}>
                  {recordsLoading[d.id] && <p className="muted">Loading zone records from Technitium…</p>}
                  {recordsError[d.id] && <p className="error">{recordsError[d.id]}</p>}
                  {records[d.id] && (
                    <table>
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>Type</th>
                          <th>TTL</th>
                          <th>Value</th>
                          <th />
                        </tr>
                      </thead>
                      <tbody>
                        {records[d.id]
                          .filter((r) => r.type !== "SOA")
                          .map((r, i) => (
                            <tr key={`${r.name}-${r.type}-${i}`}>
                              <td className="mono">{r.name}</td>
                              <td>
                                <span className="badge gray">{r.type}</span>
                              </td>
                              <td className="muted">{r.ttl}</td>
                              <td className="mono" style={{ wordBreak: "break-all" }}>
                                {r.value}
                              </td>
                              <td>
                                <button className="danger small" onClick={() => removeRecord(d.id, r)}>
                                  ✕
                                </button>
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  )}
                  {records[d.id] && (
                    <form
                      className="form-row"
                      style={{ marginTop: 12 }}
                      onSubmit={(e) => submitRecord(e, d.id)}
                    >
                      <select value={recType} onChange={(e) => setRecType(e.target.value)}>
                        {RECORD_TYPES.map((t) => (
                          <option key={t}>{t}</option>
                        ))}
                      </select>
                      <input
                        placeholder="name (e.g. www, or @ for apex)"
                        value={recName}
                        onChange={(e) => setRecName(e.target.value)}
                      />
                      <input
                        placeholder={recType === "MX" ? "10 mail.example" : "value"}
                        value={recValue}
                        onChange={(e) => setRecValue(e.target.value)}
                        style={{ flex: 1 }}
                      />
                      {(recType === "MX" || recType === "SRV") && (
                        <input
                          type="number"
                          placeholder="priority"
                          value={recPriority}
                          onChange={(e) => setRecPriority(Number(e.target.value))}
                          style={{ width: 80 }}
                        />
                      )}
                      <input
                        type="number"
                        placeholder="ttl"
                        value={recTtl}
                        onChange={(e) => setRecTtl(Number(e.target.value))}
                        style={{ width: 80 }}
                      />
                      <button type="submit" className="secondary small">
                        Add via Technitium
                      </button>
                    </form>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
