import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for per-tenant DNS providers: validation, default promotion,
 * credential write-only semantics (JSON views never leak secrets), and
 * connection resolution for record operations. `db` is mocked; the real
 * SQLite schema/DDL is exercised by the build smoke (vitest cannot load
 * node:sqlite).
 */

type DnsProviderRow = {
  id: number;
  tenant_id: number;
  name: string;
  kind: "bind-ssh";
  host: string;
  port: number;
  user: string;
  key_path: string | null;
  password: string | null;
  tsig_name: string | null;
  tsig_secret: string | null;
  is_default: number;
  created_at: string;
};

const h = vi.hoisted(() => {
  let nextId = 1;
  const rows: DnsProviderRow[] = [];
  const db = {
    listDnsProviders: (tenantId: number) =>
      rows.filter((r) => r.tenant_id === tenantId),
    getDnsProvider: (id: number, tenantId?: number) => {
      const row = rows.find(
        (r) => r.id === id && (tenantId === undefined || r.tenant_id === tenantId),
      );
      return row ? { ...row } : undefined;
    },
    createDnsProvider: (input: {
      tenantId: number;
      name: string;
      kind?: string;
      host: string;
      port?: number;
      user?: string;
      keyPath?: string;
      password?: string;
      tsigName?: string;
      tsigSecret?: string;
      isDefault?: boolean;
    }): DnsProviderRow => {
      const row: DnsProviderRow = {
        id: nextId++,
        tenant_id: input.tenantId,
        name: input.name,
        kind: "bind-ssh",
        host: input.host,
        port: input.port ?? 22,
        user: input.user ?? "root",
        key_path: input.keyPath ?? null,
        password: input.password ?? null,
        tsig_name: input.tsigName ?? null,
        tsig_secret: input.tsigSecret ?? null,
        is_default: input.isDefault ? 1 : 0,
        created_at: "2026-01-01T00:00:00.000Z",
      };
      rows.push(row);
      return { ...row };
    },
    updateDnsProvider: (
      id: number,
      tenantId: number,
      input: {
        name?: string;
        host?: string;
        port?: number;
        user?: string;
        keyPath?: string;
        password?: string | null;
        tsigName?: string;
        tsigSecret?: string;
        isDefault?: boolean;
      },
    ) => {
      const row = rows.find((r) => r.id === id && r.tenant_id === tenantId);
      if (!row) return undefined;
      Object.assign(row, {
        name: input.name ?? row.name,
        host: input.host ?? row.host,
        port: input.port ?? row.port,
        user: input.user ?? row.user,
        key_path:
          input.keyPath !== undefined
            ? input.keyPath || row.key_path
            : row.key_path,
        password:
          input.password !== undefined
            ? input.password || row.password
            : row.password,
        tsig_name:
          input.tsigName !== undefined
            ? input.tsigName || row.tsig_name
            : row.tsig_name,
        tsig_secret:
          input.tsigSecret !== undefined
            ? input.tsigSecret || row.tsig_secret
            : row.tsig_secret,
        is_default: input.isDefault !== undefined ? (input.isDefault ? 1 : 0) : row.is_default,
      });
      return { ...row };
    },
    deleteDnsProvider: (id: number, tenantId: number) => {
      const i = rows.findIndex((r) => r.id === id && r.tenant_id === tenantId);
      if (i >= 0) rows.splice(i, 1);
    },
    clearDnsProviderDefaults: (tenantId: number) => {
      for (const r of rows) if (r.tenant_id === tenantId) r.is_default = 0;
    },
  };
  return {
    db,
    reset: () => {
      rows.length = 0;
      nextId = 1;
    },
  };
});

vi.mock("../src/db", () => ({
  db: h.db,
  DEFAULT_TENANT_ID: 1,
}));

const {
  createProvider,
  ProviderError,
  providerConnectionForTenant,
  updateProvider,
} = await import("../src/services/providers");

const base = {
  name: "prod-dns",
  host: "dns.acme.example",
  user: "root",
  keyPath: "/root/.ssh/cerulean",
  tsigName: "cerulean",
  tsigSecret: "topsecret",
};

beforeEach(() => {
  h.reset();
});

describe("createProvider validation", () => {
  it("accepts a valid SSH+BIND provider", () => {
    const p = createProvider(2, base);
    expect(p.name).toBe("prod-dns");
    expect(p.host).toBe("dns.acme.example");
    expect(p.isDefault).toBe(true); // first provider auto-defaults
  });

  it("rejects invalid names and hosts", () => {
    expect(() => createProvider(2, { ...base, name: "bad name!" })).toThrow(
      ProviderError,
    );
    expect(() =>
      createProvider(2, { ...base, host: "https://dns.example/with/path" }),
    ).toThrow(/Invalid host/);
    expect(() => createProvider(2, { ...base, host: "notaipnorhost" })).toThrow(
      /Invalid host/,
    );
    expect(() => createProvider(2, { ...base, port: 0 })).toThrow(/port/);
    expect(() => createProvider(2, { ...base, user: "  " })).toThrow(
      /user is required/,
    );
  });

  it("requires credentials (key_path or password)", () => {
    expect(() =>
      createProvider(2, { name: "x", host: "dns.example.com" }),
    ).toThrow(/Credentials required/);
  });

  it("rejects duplicate names per tenant", () => {
    createProvider(2, base);
    expect(() => createProvider(2, base)).toThrow(ProviderError);
    // Same name under another tenant is fine.
    expect(createProvider(3, base).tenantId).toBe(3);
  });

  it("promotes the flagged provider to default and clears others", () => {
    createProvider(2, { ...base, name: "a" });
    const p2 = createProvider(2, { ...base, name: "b", isDefault: true });
    expect(p2.isDefault).toBe(true);
    const others = h.db.listDnsProviders(2);
    expect(others.find((r) => r.name === "a")!.is_default).toBe(0);
  });
});

describe("updateProvider", () => {
  it("merges over stored values and keeps untouched fields", () => {
    const created = createProvider(2, base);
    const updated = updateProvider(created.id, 2, { name: "prod-dns-2" });
    expect(updated.name).toBe("prod-dns-2");
    expect(updated.host).toBe("dns.acme.example");
    expect(updated.hasTsig).toBe(true);
  });

  it("404s on unknown or cross-tenant ids", () => {
    const created = createProvider(2, base);
    expect(() => updateProvider(created.id, 3, { name: "nope" })).toThrow(
      ProviderError,
    );
    expect(() => updateProvider(999, 2, { name: "nope" })).toThrow(ProviderError);
  });

  it("never exposes stored secrets in responses", () => {
    const created = createProvider(2, base);
    const body = JSON.stringify(created);
    expect(body).not.toContain("topsecret");
    expect(body).not.toContain("tsig_secret");
    expect(body).not.toContain("password");
    // A later PATCH without secrets still keeps them server-side but hides them.
    const updated = updateProvider(created.id, 2, { host: "dns2.acme.example" });
    expect(JSON.stringify(updated)).not.toContain("topsecret");
    expect(h.db.getDnsProvider(created.id)!.tsig_secret).toBe("topsecret");
  });
});

describe("providerConnectionForTenant", () => {
  it("returns null when the tenant has no providers", () => {
    expect(providerConnectionForTenant(2)).toBeNull();
  });

  it("prefers the flagged default, else the first registered", () => {
    createProvider(2, { ...base, name: "a" });
    createProvider(2, { ...base, name: "b", isDefault: true });
    const conn = providerConnectionForTenant(2)!;
    expect(conn.providerName).toBe("b");
    expect(conn.host).toBe("dns.acme.example");
    expect(conn.tsigSecret).toBe("topsecret");

    // After removing the default flag the first row wins.
    updateProvider(
      h.db.listDnsProviders(2).find((r) => r.name === "b")!.id,
      2,
      { isDefault: false },
    );
    expect(providerConnectionForTenant(2)!.providerName).toBe("a");
  });

  it("is tenant-isolated — other tenants' providers never resolve", () => {
    createProvider(2, base);
    expect(providerConnectionForTenant(3)).toBeNull();
  });
});
