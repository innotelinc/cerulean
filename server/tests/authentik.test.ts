import { afterEach, describe, expect, it, vi } from "vitest";

// Admin credentials must be set before the config singleton loads (first
// dynamic import below imports ../src/config transitively).
process.env.AUTHENTIK_API_URL = "https://auth.example.test";
process.env.AUTHENTIK_ADMIN_USER = "akadmin";
process.env.AUTHENTIK_ADMIN_PASSWORD = "admin-secret";

function jsonResponse(obj: unknown, status = 200): Response {
  return {
    ok: status < 400,
    status,
    json: async () => obj,
    text: async () => JSON.stringify(obj),
  } as unknown as Response;
}

const requests: { method: string; path: string }[] = [];

function installMockFetch() {
  vi.stubGlobal(
    "fetch",
    async (url: string | URL, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const path = new URL(String(url)).pathname;
      requests.push({ method, path });
      if (path === "/api/v3/core/auth/admin/" && method === "POST") {
        return jsonResponse({ token: "admin-token-1" });
      }
      if (path === "/api/v3/core/groups/acme/users/") {
        return jsonResponse({
          pagination: { count: 2 },
          results: [
            { pk: 11, username: "alice", email: "alice@example.com", name: "Alice" },
            { pk: 12, username: "bob", email: "bob@example.com", name: "Bob" },
          ],
        });
      }
      if (path === "/api/v3/core/groups/nonexistent/users/") {
        return jsonResponse({ detail: "Not found" }, 404);
      }
      throw new Error(`Unexpected request: ${method} ${path}`);
    },
  );
}

const { listGroupMembers } = await import("../src/services/authentik");

afterEach(() => {
  vi.unstubAllGlobals();
  requests.length = 0;
});

describe("listGroupMembers", () => {
  it("logs in with admin credentials and returns the group's users", async () => {
    installMockFetch();
    const result = await listGroupMembers("acme");
    expect(result.groupExists).toBe(true);
    expect(result.users.map((u) => u.username)).toEqual(["alice", "bob"]);
    expect(result.users[0].email).toBe("alice@example.com");
    expect(requests.some((r) => r.path === "/api/v3/core/auth/admin/")).toBe(
      true,
    );
  });

  it("reports a missing Authentik group instead of failing", async () => {
    installMockFetch();
    const result = await listGroupMembers("nonexistent");
    expect(result.groupExists).toBe(false);
    expect(result.users).toEqual([]);
  });
});
