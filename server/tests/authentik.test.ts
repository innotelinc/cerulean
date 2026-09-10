import { afterEach, describe, expect, it, vi } from "vitest";

// Admin API credentials must be set before the config singleton loads (first
// dynamic import below imports ../src/config transitively). Authentik 2024.12
// removed the admin-login endpoint, so the bootstrap token is used as a
// Bearer token.
process.env.AUTHENTIK_API_URL = "https://auth.example.test";
process.env.AUTHENTIK_ADMIN_USER = "akadmin";
process.env.AUTHENTIK_ADMIN_PASSWORD = "admin-secret";
process.env.AUTHENTIK_BOOTSTRAP_TOKEN = "bootstrap-token-1";

function jsonResponse(obj: unknown, status = 200): Response {
  return {
    ok: status < 400,
    status,
    json: async () => obj,
    text: async () => JSON.stringify(obj),
  } as unknown as Response;
}

const requests: { method: string; path: string; query: string }[] = [];

function installMockFetch() {
  vi.stubGlobal(
    "fetch",
    async (url: string | URL, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const parsed = new URL(String(url));
      requests.push({ method, path: parsed.pathname, query: parsed.search });
      // Tenant slug → exact group-name lookup (groups have no slug in
      // Authentik 2025.x+).
      if (parsed.pathname === "/api/v3/core/groups/") {
        if (parsed.searchParams.get("name") === "acme") {
          return jsonResponse({
            pagination: { count: 1 },
            results: [{ pk: "1f0f6d5a-0000-4000-8000-000000000001", name: "acme" }],
          });
        }
        return jsonResponse({ pagination: { count: 0 }, results: [] });
      }
      // Members come from the users collection (the per-group users endpoint
      // was removed in Authentik 2026.x).
      if (parsed.pathname === "/api/v3/core/users/") {
        if (parsed.searchParams.get("groups_by_name") === "acme") {
          return jsonResponse({
            pagination: { count: 2 },
            results: [
              { pk: 11, username: "alice", email: "alice@example.com", name: "Alice" },
              { pk: 12, username: "bob", email: "bob@example.com", name: "Bob" },
            ],
          });
        }
        return jsonResponse({ pagination: { count: 0 }, results: [] });
      }
      throw new Error(`Unexpected request: ${method} ${parsed.pathname}`);
    },
  );
}

const { listGroupMembers } = await import("../src/services/authentik");

afterEach(() => {
  vi.unstubAllGlobals();
  requests.length = 0;
});

describe("listGroupMembers", () => {
  it("authenticates with the bootstrap token and returns the group's users", async () => {
    installMockFetch();
    const result = await listGroupMembers("acme");
    expect(result.groupExists).toBe(true);
    expect(result.users.map((u) => u.username)).toEqual(["alice", "bob"]);
    expect(result.users[0].email).toBe("alice@example.com");
    expect(
      requests.some(
        (r) => r.path === "/api/v3/core/groups/" && r.query.includes("name=acme"),
      ),
    ).toBe(true);
    expect(
      requests.some(
        (r) =>
          r.path === "/api/v3/core/users/" &&
          r.query.includes("groups_by_name=acme"),
      ),
    ).toBe(true);
    expect(requests.some((r) => r.path === "/api/v3/core/auth/admin/")).toBe(
      false,
    );
  });

  it("reports a missing Authentik group instead of failing", async () => {
    installMockFetch();
    const result = await listGroupMembers("nonexistent");
    expect(result.groupExists).toBe(false);
    expect(result.users).toEqual([]);
    expect(requests.some((r) => r.path === "/api/v3/core/users/")).toBe(false);
  });
});
