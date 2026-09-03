import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for the tenant layer: Authentik-group membership → tenant
 * resolution, platform-admin powers, header-driven tenant switching, and
 * tenant creation rules. `db` is mocked; the real SQLite schema/DDL is
 * exercised by the build smoke (vitest cannot load node:sqlite).
 */

type TenantRow = {
  id: number;
  slug: string;
  name: string;
  created_at: string;
};

const h = vi.hoisted(() => {
  const tenants: TenantRow[] = [
    { id: 1, slug: "default", name: "Default", created_at: "2026-01-01T00:00:00.000Z" },
    { id: 2, slug: "acme", name: "Acme Corp", created_at: "2026-01-01T00:00:00.000Z" },
    { id: 3, slug: "globex", name: "Globex", created_at: "2026-01-01T00:00:00.000Z" },
  ];
  const db = {
    listTenants: () => tenants,
    getTenant: (id: number) => tenants.find((t) => t.id === id),
    getTenantBySlug: (slug: string) => tenants.find((t) => t.slug === slug),
    createTenant: (input: { slug: string; name: string }) => {
      const row: TenantRow = {
        id: tenants.length + 1,
        slug: input.slug,
        name: input.name,
        created_at: new Date().toISOString(),
      };
      tenants.push(row);
      return row;
    },
    renameTenant: (id: number, name: string) => {
      const row = tenants.find((t) => t.id === id);
      if (!row) return undefined;
      row.name = name;
      return row;
    },
  };
  return {
    db,
    reset: () => {
      tenants.length = 0;
      tenants.push(
        { id: 1, slug: "default", name: "Default", created_at: "2026-01-01T00:00:00.000Z" },
        { id: 2, slug: "acme", name: "Acme Corp", created_at: "2026-01-01T00:00:00.000Z" },
        { id: 3, slug: "globex", name: "Globex", created_at: "2026-01-01T00:00:00.000Z" },
      );
    },
  };
});

vi.mock("../src/db", () => ({
  db: h.db,
  DEFAULT_TENANT_ID: 1,
}));

const {
  createTenant,
  effectiveTenant,
  isPlatformAdmin,
  renameTenant,
  TenantError,
  tenantsForUser,
} = await import("../src/services/tenants");

type User = {
  sub: string;
  email: string;
  name: string;
  groups: string[];
  provider: "local" | "authentik";
};

const localAdmin: User = {
  sub: "admin",
  email: "",
  name: "admin",
  groups: ["admin"],
  provider: "local",
};

const member = (groups: string[]): User => ({
  sub: "u1",
  email: "u@example.com",
  name: "User",
  groups,
  provider: "authentik",
});

beforeEach(() => {
  h.reset();
});

describe("tenantsForUser / isPlatformAdmin", () => {
  it("treats local sessions as platform admins over every tenant", () => {
    expect(isPlatformAdmin(localAdmin)).toBe(true);
    expect(tenantsForUser(localAdmin).map((t) => t.slug)).toEqual([
      "default",
      "acme",
      "globex",
    ]);
  });

  it("maps Authentik group membership to tenants", () => {
    const acmeUser = member(["acme"]);
    expect(isPlatformAdmin(acmeUser)).toBe(false);
    expect(tenantsForUser(acmeUser).map((t) => t.slug)).toEqual(["acme"]);

    const multi = member(["acme", "globex"]);
    expect(tenantsForUser(multi).map((t) => t.slug)).toEqual(["acme", "globex"]);
  });

  it("grants platform admin to the configured Authentik group", () => {
    const platform = member(["cerulean-platform", "acme"]);
    expect(isPlatformAdmin(platform)).toBe(true);
    expect(tenantsForUser(platform)).toHaveLength(3);
  });

  it("returns no tenants for an Authentik user in no matching group", () => {
    expect(tenantsForUser(member(["elsewhere"]))).toEqual([]);
    expect(effectiveTenant(member(["elsewhere"]))).toBeNull();
  });
});

describe("effectiveTenant", () => {
  it("defaults platform admins to the default tenant", () => {
    const t = effectiveTenant(localAdmin);
    expect(t?.id).toBe(1);
    expect(t?.slug).toBe("default");
  });

  it("lets platform admins switch tenants with the header", () => {
    const t = effectiveTenant(localAdmin, "acme");
    expect(t?.slug).toBe("acme");
    expect(effectiveTenant(localAdmin, "no-such")).toBeNull();
  });

  it("picks the member's only tenant, or honors the header among several", () => {
    expect(effectiveTenant(member(["acme"]))?.slug).toBe("acme");

    const multi = member(["acme", "globex"]);
    expect(effectiveTenant(multi)?.slug).toBe("acme"); // first allowed
    expect(effectiveTenant(multi, "globex")?.slug).toBe("globex");
    expect(effectiveTenant(multi, "default")).toBeNull(); // not a member
  });
});

describe("createTenant", () => {
  it("validates slugs and rejects duplicates", () => {
    expect(() => createTenant({ slug: "Bad Slug!", name: "x" })).toThrow(
      /Invalid slug/,
    );
    expect(() => createTenant({ slug: "acme", name: "Dup" })).toThrow(
      TenantError,
    );
    const created = createTenant({ slug: "zeta", name: "Zeta Inc" });
    expect(created.slug).toBe("zeta");
    expect(dbListSlugs()).toContain("zeta");
  });
});

describe("renameTenant", () => {
  it("renames by id, keeps the slug, and validates input", () => {
    const renamed = renameTenant(2, "Acme Corp (US)");
    expect(renamed?.name).toBe("Acme Corp (US)");
    expect(renamed?.slug).toBe("acme"); // slug is the stable identity

    expect(() => renameTenant(2, "   ")).toThrow(/1-128/);
    expect(() => renameTenant(99_999, "New Name")).toThrow(TenantError);
  });
});

function dbListSlugs(): string[] {
  return h.db.listTenants().map((t: TenantRow) => t.slug);
}
