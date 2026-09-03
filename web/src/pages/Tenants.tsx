import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { TenantMember, TenantRow } from "../types";

interface MembersState {
  loading: boolean;
  available: boolean;
  groupExists: boolean;
  users: TenantMember[];
  hint: string;
}

export default function Tenants() {
  const [tenants, setTenants] = useState<TenantRow[]>([]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [busy, setBusy] = useState(false);
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [expanded, setExpanded] = useState<Record<string, MembersState>>({});

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 4000);
  };

  const load = useCallback(async () => {
    try {
      setTenants(await api.listTenants());
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load tenants");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!slug.trim() || !name.trim()) return;
    setBusy(true);
    setError("");
    try {
      await api.createTenant({ slug: slug.trim(), name: name.trim() });
      flash(`Tenant "${slug.trim()}" created`);
      setSlug("");
      setName("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create tenant");
    } finally {
      setBusy(false);
    }
  };

  const rename = async (t: TenantRow) => {
    const next = window.prompt(`Rename tenant "${t.name}"?`, t.name);
    if (next === null || next.trim() === "" || next.trim() === t.name) return;
    try {
      await api.renameTenant(t.id, next.trim());
      flash("Tenant renamed");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Rename failed");
    }
  };

  const toggleMembers = async (t: TenantRow) => {
    const current = expanded[t.slug];
    if (current) {
      const next = { ...expanded };
      delete next[t.slug];
      setExpanded(next);
      return;
    }
    setExpanded((prev) => ({
      ...prev,
      [t.slug]: {
        loading: true,
        available: false,
        groupExists: false,
        users: [],
        hint: "",
      },
    }));
    try {
      const result = await api.tenantMembers(t.slug);
      setExpanded((prev) => ({
        ...prev,
        [t.slug]: {
          loading: false,
          available: result.available,
          groupExists: result.groupExists,
          users: result.users,
          hint: result.hint,
        },
      }));
    } catch (err) {
      setExpanded((prev) => ({
        ...prev,
        [t.slug]: {
          loading: false,
          available: false,
          groupExists: false,
          users: [],
          hint: err instanceof Error ? err.message : "Failed to load members",
        },
      }));
    }
  };

  const rows = tenants.flatMap((t) => {
    const state = expanded[t.slug];
    const main = (
      <tr key={t.id}>
        <td>
          <strong>{t.name}</strong>
          {t.slug === "default" && (
            <span className="badge gray" style={{ marginLeft: 8 }}>
              built-in
            </span>
          )}
        </td>
        <td className="mono">{t.slug}</td>
        <td className="muted">
          {new Date(t.created_at).toLocaleDateString()}
        </td>
        <td className="muted">
          Authentik group members
        </td>
        <td>
          <div className="actions">
            <button className="secondary small" onClick={() => toggleMembers(t)}>
              {state ? "Hide" : "View"} members
            </button>
            <button className="secondary small" onClick={() => rename(t)}>
              Rename
            </button>
          </div>
        </td>
      </tr>
    );
    const detail = state
      ? [
          <tr key={`${t.slug}-members`}>
            <td colSpan={5}>
              {state.loading ? (
                <p className="muted">Loading members…</p>
              ) : (
                <>
                  <p className="muted" style={{ marginTop: 0 }}>
                    {state.hint}
                  </p>
                  {state.users.length === 0 ? (
                    <div className="empty" style={{ padding: "14px 0" }}>
                      {state.available
                        ? "No members yet — add users to the Authentik group"
                        : "Member listing unavailable"}
                    </div>
                  ) : (
                    <table>
                      <thead>
                        <tr>
                          <th>Username</th>
                          <th>Name</th>
                          <th>Email</th>
                        </tr>
                      </thead>
                      <tbody>
                        {state.users.map((u) => (
                          <tr key={u.pk}>
                            <td className="mono">{u.username}</td>
                            <td>{u.name}</td>
                            <td className="muted">{u.email || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </>
              )}
            </td>
          </tr>,
        ]
      : [];
    return [main, ...detail];
  });

  return (
    <div>
      <h1>Tenants</h1>
      <p className="subtitle">
        Organizations/tenants. Each tenant is an Authentik group: the group's
        slug is the tenant's slug, and members of that group see only this
        tenant's certificates, domains and secrets.
      </p>

      {error && <p className="error">{error}</p>}

      <div className="panel">
        <div className="panel-title">Create a tenant</div>
        <form className="form-row" onSubmit={create}>
          <input
            placeholder="slug — lowercase, no spaces (e.g. acme)"
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            style={{ minWidth: 240 }}
          />
          <input
            placeholder="display name (e.g. Acme Corp)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            style={{ minWidth: 240 }}
          />
          <button type="submit" disabled={busy || !slug.trim() || !name.trim()}>
            {busy ? "Creating…" : "Create tenant"}
          </button>
        </form>
        <p className="muted" style={{ margin: "6px 0 0" }}>
          Then create the matching <span className="mono">Authentik group</span>{" "}
          with the same slug and add users to it — membership is live as soon
          as the group exists.
        </p>
      </div>

      <div className="panel">
        <div className="panel-title">Tenants</div>
        {tenants.length === 0 ? (
          <div className="empty">No tenants yet</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Slug (Authentik group)</th>
                <th>Created</th>
                <th>Access</th>
                <th />
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
        )}
      </div>

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
