import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Technitium invalid-token recovery.
 *
 * A *configured* token is used as-is, so nothing refreshes it, and Technitium
 * answering `invalid-token` used to be the end of the road: the cache-clear helped
 * only a token obtained by logging in, and the thrown error told the *caller* to
 * retry. On 2026-09-13 that turned into five hours of DNS reads returning 500 on
 * this platform — every publish failed identically, with an instruction to do the
 * one thing that could not work.
 *
 * What is pinned here is the recovery, on the wire: the token is tried, rejected,
 * a login is performed, and the request is retried with the session — plus the limits
 * of it: one retry and no more, and the operator told once rather than on every call.
 */

interface Wire {
  path: string;
  token: string | null;
}

interface Scripted {
  status?: string;
  token?: string;
  zones?: Array<{ name: string; type: string; disabled: boolean }>;
}

function installFetch(handler: (path: string, token: string | null) => Scripted) {
  const wire: Wire[] = [];
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    const header = new Headers(init?.headers as HeadersInit | undefined).get("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : null;
    wire.push({ path, token });
    const body = handler(path, token);
    return {
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify(body),
      json: async () => body,
    } as unknown as Response;
  });
  return wire;
}

const ZONE = { name: "innotel.us", type: "Primary", disabled: false };

const CONN = {
  url: "http://technitium.test:5380",
  token: "dead-static-token",
  user: "admin",
  password: "admin-password",
  providerName: null,
};

/** A fresh module per test: the warn-once flag is module state. */
async function service() {
  vi.resetModules();
  return await import("../src/services/technitium");
}

describe("technitium invalid-token recovery", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("logs in and retries when a configured token is rejected", async () => {
    const wire = installFetch((path, token) => {
      if (path === "/api/user/login") return { status: "ok", token: "fresh-session" };
      return token === "fresh-session" ? { status: "ok", zones: [ZONE] } : { status: "invalid-token" };
    });
    vi.spyOn(console, "warn").mockImplementation(() => {});

    const { listZones } = await service();
    const zones = await listZones(CONN);

    expect(zones).toEqual([ZONE]);
    expect(wire.map((call) => call.path)).toEqual([
      "/api/zones/list",
      "/api/user/login",
      "/api/zones/list",
    ]);
    expect(wire[0].token).toBe("dead-static-token");
    expect(wire[2].token).toBe("fresh-session");
  });

  it("warns once, not on every request, while the token stays dead", async () => {
    installFetch((path, token) => {
      if (path === "/api/user/login") return { status: "ok", token: "fresh-session" };
      return token === "fresh-session"
        ? { status: "ok", zones: [ZONE] }
        : { status: "invalid-token" };
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const { listZones } = await service();
    await listZones(CONN);
    await listZones(CONN);

    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toMatch(/invalid-token/);
  });

  it("does not loop when the login is rejected too", async () => {
    const wire = installFetch((path) =>
      path === "/api/user/login"
        ? { status: "ok", token: "still-rejected" }
        : { status: "invalid-token" },
    );
    vi.spyOn(console, "warn").mockImplementation(() => {});

    const { listZones } = await service();

    await expect(listZones(CONN)).rejects.toThrow(/session expired/);
    // one attempt, one retry — a second retry would spin against an upstream that is
    // not going to answer differently.
    expect(wire.filter((call) => call.path === "/api/zones/list")).toHaveLength(2);
  });

  it("recovers an expired session, not only a dead configured token", async () => {
    // The same answer arrives when a session Technitium lost (a restart will do it)
    // is used: no token is configured here, so the fallback has to log in again
    // rather than merely drop the configured token.
    let logins = 0;
    const wire = installFetch((path, token) => {
      if (path === "/api/user/login") return { status: "ok", token: `session-${++logins}` };
      return token === "session-2" ? { status: "ok", zones: [] } : { status: "invalid-token" };
    });

    const { listZones } = await service();
    await listZones({ ...CONN, token: "" });

    expect(wire.map((call) => call.path)).toEqual([
      "/api/user/login",
      "/api/zones/list",
      "/api/user/login",
      "/api/zones/list",
    ]);
  });
});
