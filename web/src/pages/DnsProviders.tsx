import { useEffect, useState } from "react";
import { api } from "../api";
import type { DnsProvider } from "../types";

interface ProviderForm {
  name: string;
  url: string;
  user: string;
  api_token: string;
  password: string;
  is_default: boolean;
}

const emptyForm = (): ProviderForm => ({
  name: "",
  url: "",
  user: "admin",
  api_token: "",
  password: "",
  is_default: false,
});

export default function DnsProviders() {
  const [providers, setProviders] = useState<DnsProvider[]>([]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [form, setForm] = useState<ProviderForm>(emptyForm());
  const [saving, setSaving] = useState(false);
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

  useEffect(() => { load(); }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      await api.createDnsProvider({
        name: form.name,
        url: form.url || undefined,
        user: form.user || undefined,
        api_token: form.api_token || undefined,
        password: form.password || undefined,
        default: form.is_default,
      });
      setForm(emptyForm());
      flash("Technitium DNS provider added");
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
        url: p.url ?? "",
        user: p.user,
        api_token: "",
        password: "",
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
        url: f.url || undefined,
        user: f.user || undefined,
        api_token: f.api_token || undefined,
        password: f.password || undefined,
        default: f.is_default,
      });
      setEditing((x) => { const n = { ...x }; delete n[p.id]; return n; });
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
    if (!window.confirm(`Delete DNS provider ${p.name}? Zones will fall back to the platform Technitium.`)) return;
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
    <label style={{ flex: 1, minWidth: 180 }}>
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
        Technitium servers that serve this tenant's zones via HTTP API. Record operations
        run against the <strong>default</strong> provider; with none configured, zones fall
        back to the platform Technitium from <span className="mono">TECHNITIUM_URL</span>.
      </p>

      {error && <p className="error">{error}</p>}

      <div className="panel">
        <div className="panel-title">Add a Technitium provider</div>
        <form className="form-row" onSubmit={submit} style={{ flexWrap: "wrap", gap: 8 }}>
          {field("name", "Name", form, (v) => set("name", v), "prod-technitium")}
          {field("url", "Technitium URL", form, (v) => set("url", v), "http://10.0.0.5:5380")}
          {field("user", "Admin user", form, (v) => set("user", v), "admin")}
          {field("api_token", "API token (preferred)", form, (v) => set("api_token", v), "", true)}
          {field("password", "Password (or blank if using token)", form, (v) => set("password", v), "", true)}
          <label style={{ display: "flex", alignItems: "center", gap: 6, paddingTop: 16 }}>
            <input type="checkbox" checked={form.is_default} onChange={(e) => set("is_default", e.target.checked)} />
            <span style={{ fontSize: 13 }}>Default provider</span>
          </label>
          <button type="submit" disabled={saving || !form.name || !form.url} style={{ alignSelf: "flex-end" }}>
            {saving ? "Saving…" : "Add provider"}
          </button>
        </form>
        <p className="muted" style={{ fontSize: 12 }}>Create an API token in Technitium → Settings → API Tokens, or use the admin user + password.</p>
      </div>

      <div className="panel">
        <div className="panel-title">
          Providers for this tenant
          {providers.length === 0 && <span className="badge amber" style={{ marginLeft: 8 }}>platform Technitium active</span>}
        </div>
        {providers.length === 0 ? (
          <div className="empty">
            No providers yet — record operations use the platform-level Technitium in <span className="mono">.env</span>.
          </div>
        ) : (
          providers.map((p) => {
            const f = editing[p.id];
            return (
              <div key={p.id} style={{ marginBottom: 10 }}>
                <div className="form-row" style={{ marginBottom: 0 }}>
                  <strong style={{ fontSize: 15 }}>{p.name}</strong>
                  {p.isDefault && <span className="badge green">default</span>}
                  <span className="badge gray">{p.kind}</span>
                  <span className="mono muted" style={{ fontSize: 13 }}>
                    {p.url ?? `http://${p.host}:${p.port}`} · {p.user}
                  </span>
                  <div style={{ flex: 1 }} />
                  {p.hasToken && <span className="badge blue">token</span>}
                  {p.hasPassword && <span className="badge amber">password</span>}
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
                      {field("url", "Technitium URL", f, (v) => setEdit(p.id, "url", v), p.url ?? "http://10.0.0.5:5380")}
                      {field("user", "Admin user", f, (v) => setEdit(p.id, "user", v))}
                      {field("api_token", "API token", f, (v) => setEdit(p.id, "api_token", v), p.hasToken ? "(unchanged)" : "", true)}
                      {field("password", "Password", f, (v) => setEdit(p.id, "password", v), p.hasPassword ? "(unchanged)" : "", true)}
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
