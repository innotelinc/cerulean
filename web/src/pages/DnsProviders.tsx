import { useEffect, useState } from "react";
import { api } from "../api";
import type { DnsProvider } from "../types";

interface ProviderForm {
  name: string;
  host: string;
  port: string;
  user: string;
  key_path: string;
  password: string;
  tsig_name: string;
  tsig_secret: string;
  is_default: boolean;
}

const emptyForm = (): ProviderForm => ({
  name: "",
  host: "",
  port: "22",
  user: "root",
  key_path: "",
  password: "",
  tsig_name: "",
  tsig_secret: "",
  is_default: false,
});

export default function DnsProviders() {
  const [providers, setProviders] = useState<DnsProvider[]>([]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [form, setForm] = useState<ProviderForm>(emptyForm());
  const [saving, setSaving] = useState(false);
  // inline edit: provider id → form; secrets are blank ("unchanged") unless typed
  const [editing, setEditing] = useState<Record<number, ProviderForm>>({});

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 4000);
  };

  const load = async () => {
    try {
      setProviders(await api.listDnsProviders());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load DNS providers");
    }
  };

  useEffect(() => {
    load();
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      const body = {
        name: form.name,
        host: form.host,
        port: form.port ? Number(form.port) : undefined,
        user: form.user,
        key_path: form.key_path || undefined,
        password: form.password || undefined,
        tsig_name: form.tsig_name || undefined,
        tsig_secret: form.tsig_secret || undefined,
        default: form.is_default,
      };
      await api.createDnsProvider(body);
      setForm(emptyForm());
      flash("DNS provider added");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add DNS provider");
    } finally {
      setSaving(false);
    }
  };

  const startEdit = (p: DnsProvider) => {
    setEditing((x) => ({
      ...x,
      [p.id]: {
        name: p.name,
        host: p.host,
        port: String(p.port),
        user: p.user,
        key_path: "",
        password: "",
        tsig_name: p.hasTsig ? "" : "",
        tsig_secret: "",
        is_default: p.isDefault,
      },
    }));
  };

  const saveEdit = async (p: DnsProvider) => {
    const f = editing[p.id];
    if (!f) return;
    setSaving(true);
    setError("");
    try {
      await api.updateDnsProvider(p.id, {
        name: f.name,
        host: f.host,
        port: f.port ? Number(f.port) : undefined,
        user: f.user,
        key_path: f.key_path || undefined,
        password: f.password || undefined,
        tsig_name: f.tsig_name || undefined,
        tsig_secret: f.tsig_secret || undefined,
        default: f.is_default,
      });
      setEditing((x) => {
        const next = { ...x };
        delete next[p.id];
        return next;
      });
      flash("DNS provider updated");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update DNS provider");
    } finally {
      setSaving(false);
    }
  };

  const setDefault = async (p: DnsProvider) => {
    if (p.isDefault) return;
    try {
      await api.updateDnsProvider(p.id, { default: true });
      flash(`${p.name} is now the default provider`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update DNS provider");
    }
  };

  const remove = async (p: DnsProvider) => {
    if (!window.confirm(`Delete DNS provider ${p.name}? Zones will fall back to the platform BIND.`)) return;
    try {
      await api.deleteDnsProvider(p.id);
      flash("DNS provider deleted");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete DNS provider");
    }
  };

  const set = (k: keyof ProviderForm, v: string | boolean) =>
    setForm((f) => ({ ...f, [k]: v }));
  const setEdit = (id: number, k: keyof ProviderForm, v: string | boolean) =>
    setEditing((x) => ({ ...x, [id]: { ...x[id], [k]: v } }));

  const field = (key: keyof ProviderForm, label: string, formState: ProviderForm, onChange: (v: string) => void, placeholder = "", password = false) => (
    <label style={{ flex: 1, minWidth: 160 }}>
      <span className="muted" style={{ fontSize: 12 }}>{label}</span>
      <input
        type={password ? "password" : "text"}
        value={String(formState[key])}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        style={{ width: "100%", marginTop: 2 }}
      />
    </label>
  );

  return (
    <div>
      <h1>DNS Providers</h1>
      <p className="subtitle">
        BIND servers that serve this tenant&apos;s zones. Record operations run
        against the <strong>default</strong> provider; with none configured, zones
        fall back to the platform BIND from <span className="mono">.env</span>.
      </p>

      {error && <p className="error">{error}</p>}

      <div className="panel">
        <div className="panel-title">Add a DNS provider</div>
        <form className="form-row" onSubmit={submit} style={{ flexWrap: "wrap", gap: 8 }}>
          {field("name", "Name", form, (v) => set("name", v), "prod-dns")}
          {field("host", "Host", form, (v) => set("host", v), "dns.example.com")}
          {field("port", "SSH port", form, (v) => set("port", v))}
          {field("user", "SSH user", form, (v) => set("user", v))}
          {field("key_path", "SSH key path (portal host)", form, (v) => set("key_path", v), "/root/.ssh/id_ed25519")}
          {field("password", "SSH password (or blank)", form, (v) => set("password", v), "", true)}
          {field("tsig_name", "TSIG key name", form, (v) => set("tsig_name", v), "cerulean")}
          {field("tsig_secret", "TSIG secret", form, (v) => set("tsig_secret", v), "", true)}
          <label style={{ display: "flex", alignItems: "center", gap: 6, paddingTop: 16 }}>
            <input type="checkbox" checked={form.is_default} onChange={(e) => set("is_default", e.target.checked)} />
            <span style={{ fontSize: 13 }}>Default provider</span>
          </label>
          <button type="submit" disabled={saving || !form.name || !form.host} style={{ alignSelf: "flex-end" }}>
            {saving ? "Saving…" : "Add provider"}
          </button>
        </form>
      </div>

      <div className="panel">
        <div className="panel-title">
          Providers for this tenant
          {providers.length === 0 && <span className="badge amber" style={{ marginLeft: 8 }}>platform BIND active</span>}
        </div>
        {providers.length === 0 ? (
          <div className="empty">
            No providers yet — record operations use the platform-level BIND
            configured in <span className="mono">.env</span>.
          </div>
        ) : (
          providers.map((p) => {
            const f = editing[p.id];
            return (
              <div key={p.id} style={{ marginBottom: 10 }}>
                <div className="form-row" style={{ marginBottom: 0 }}>
                  <strong style={{ fontSize: 15 }}>{p.name}</strong>
                  {p.isDefault && <span className="badge green">default</span>}
                  <span className="mono muted" style={{ fontSize: 13 }}>
                    {p.user}@{p.host}:{p.port}
                  </span>
                  <div style={{ flex: 1 }} />
                  {p.hasKey && <span className="badge blue">key</span>}
                  {p.hasPassword && <span className="badge amber">password</span>}
                  {p.hasTsig && <span className="badge blue">tsig</span>}
                  <button className="secondary small" onClick={() => setDefault(p)} disabled={p.isDefault || saving}>
                    {p.isDefault ? "Default" : "Set default"}
                  </button>
                  <button className="secondary small" onClick={() => (f ? setEditing((x) => { const n = { ...x }; delete n[p.id]; return n; }) : startEdit(p))}>
                    {f ? "Cancel" : "Edit"}
                  </button>
                  <button className="danger small" onClick={() => remove(p)} disabled={saving}>
                    Delete
                  </button>
                </div>
                {f && (
                  <div style={{ marginTop: 8 }}>
                    <div className="form-row" style={{ flexWrap: "wrap", gap: 8, marginBottom: 6 }}>
                      {field("name", "Name", f, (v) => setEdit(p.id, "name", v))}
                      {field("host", "Host", f, (v) => setEdit(p.id, "host", v))}
                      {field("port", "SSH port", f, (v) => setEdit(p.id, "port", v))}
                      {field("user", "SSH user", f, (v) => setEdit(p.id, "user", v))}
                      {field("key_path", "SSH key path", f, (v) => setEdit(p.id, "key_path", v), p.hasKey ? "(unchanged)" : "/root/.ssh/id_ed25519")}
                      {field("password", "SSH password", f, (v) => setEdit(p.id, "password", v), p.hasPassword ? "(unchanged)" : "", true)}
                      {field("tsig_name", "TSIG key name", f, (v) => setEdit(p.id, "tsig_name", v), p.hasTsig ? "(unchanged)" : "cerulean")}
                      {field("tsig_secret", "TSIG secret", f, (v) => setEdit(p.id, "tsig_secret", v), p.hasTsig ? "(unchanged)" : "", true)}
                      <button className="small" onClick={() => saveEdit(p)} disabled={saving}>
                        Save
                      </button>
                    </div>
                    <div className="muted" style={{ fontSize: 12 }}>
                      Secrets are write-only — leave blank to keep the stored value.
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
