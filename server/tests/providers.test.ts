import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for per-tenant Technitium DNS providers: validation,
 * default promotion, credential write-only semantics, and connection
 * resolution. `db` is mocked; real SQLite schema exercised by build.
 */

type DnsProviderRow = {
  id: number;
  tenant_id: number;
  name: string;
  kind: string;
  host: string;
  port: number;
  user: string;
  url: string | null;
  api_token: string | null;
  password: string | null;
  key_path: string | null;
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
      url?: string;
      apiToken?: string;
      password?: string;
      keyPath?: string;
      tsigName?: string;
      tsigSecret?: string;
      isDefault?: boolean;
    }): DnsProviderRow => {
      const row: DnsProviderRow = {
        id: nextId++,
        tenant_id: input.tenantId,
        name: input.name,
        kind: input.kind ?? "technitium",
        host: input.host,
        port: input.port ?? 5380,
        user: input.user ?? "admin",
        url: input.url ?? null,
        api_token: input.apiToken ?? null,
        password: input.password ?? null,
        key_path: input.keyPath ?? null,
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
        url?: string;
        apiToken?: string;
        password?: string | null;
        keyPath?: string;
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
        url: input.url ?? row.url,
        api_token: input.apiToken !== undefined ? input.apiToken || row.api_token : row.api_token,
        password: input.password !== undefined ? input.password || row.password : row.password,
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
  name: "prod-technitium",
  url: "http://10.0.0.5:5380",
  apiToken: "secret-token-123",
};

beforeEach(() => {
  h.reset();
});

describe("createProvider validation", () => {
  it("accepts a valid Technitium provider via URL + token", () => {
    const p = createProvider(2, base);
    expect(p.name).toBe("prod-technitium");
    expect(p.url).toBe("http://10.0.0.5:5380");
    expect(p.isDefault).toBe(true); // first provider auto-defaults
    expect(p.hasToken).toBe(true);
  });

  it("accepts host+port style (legacy compat)", () => {
    const p = createProvider(2, { name: "x", host: "10.0.0.6", port: 5380, password: "pw" });
    expect(p.host).toBe("10.0.0.6");
    expect(p.url).toBe("http://10.0.0.6:5380");
  });

  it("rejects invalid name or missing URL", () => {
    expect(() => createProvider(2, { ...base, name: "bad name!" })).toThrow(ProviderError);
    expect(() => createProvider(2, { name: "x", apiToken: "tok" } as never)).toThrow(/url is required/i);
  });

  it("requires credentials (token or password)", () => {
    expect(() => createProvider(2, { name: "x", url: "http://10.0.0.5:5380" })).toThrow(/Credentials required/);
  });

  it("rejects duplicate names per tenant", () => {
    createProvider(2, base);
    expect(() => createProvider(2, base)).toThrow(ProviderError);
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
    const updated = updateProvider(created.id, 2, { name: "prod-2" });
    expect(updated.name).toBe("prod-2");
    expect(updated.url).toBe("http://10.0.0.5:5380");
    expect(updated.hasToken).toBe(true);
  });

  it("404s on unknown or cross-tenant ids", () => {
    const created = createProvider(2, base);
    expect(() => updateProvider(created.id, 3, { name: "nope" })).toThrow(ProviderError);
    expect(() => updateProvider(999, 2, { name: "nope" })).toThrow(ProviderError);
  });

  it("never exposes stored secrets in responses", () => {
    const created = createProvider(2, base);
    const body = JSON.stringify(created);
    expect(body).not.toContain("secret-token-123");
    expect(body).not.toContain("api_token");
    const updated = updateProvider(created.id, 2, { name: "prod-2" });
    expect(JSON.stringify(updated)).not.toContain("secret-token-123");
    expect(h.db.getDnsProvider(created.id)!.api_token).toBe("secret-token-123");
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
    expect(conn.url).toBe("http://10.0.0.5:5380");
    expect(conn.apiToken).toBe("secret-token-123");

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
