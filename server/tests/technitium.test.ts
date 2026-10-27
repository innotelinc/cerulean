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

/**
 * Record deletes, on the wire.
 *
 * Technitium matches a delete against the whole RDATA and validates it field by
 * field, so a type whose delete payload does not carry those fields is accepted by
 * the bridge and refused by Technitium. SRV was exactly that: it had no delete
 * branch, so every SRV delete failed with `Parameter 'priority' missing` and the
 * records stayed in the zone — the last six of a retired domain, left behind
 * because there was no way to remove them. Priority 0 also has to survive the
 * query-string builder, which drops empty values.
 */
describe("technitium record deletes", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  function installRecordingFetch() {
    const calls: URL[] = [];
    vi.stubGlobal("fetch", async (url: string | URL) => {
      calls.push(new URL(String(url)));
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        text: async () => JSON.stringify({ status: "ok" }),
        json: async () => ({ status: "ok" }),
      } as unknown as Response;
    });
    return calls;
  }

  it("sends a SRV delete with every field of its RDATA, priority 0 included", async () => {
    const calls = installRecordingFetch();
    const { deleteRecord } = await service();

    await deleteRecord(
      { zone: "innotel.us", type: "SRV", name: "_autodiscover._tcp", value: "0 5 443 autodiscover.innotel.us" },
      CONN,
    );

    expect(calls).toHaveLength(1);
    expect(calls[0].pathname).toBe("/api/zones/records/delete");
    const q = calls[0].searchParams;
    expect(q.get("domain")).toBe("_autodiscover._tcp.innotel.us");
    expect(q.get("type")).toBe("SRV");
    expect(q.get("priority")).toBe("0");
    expect(q.get("weight")).toBe("5");
    expect(q.get("port")).toBe("443");
    expect(q.get("target")).toBe("autodiscover.innotel.us");
    expect(q.get("text")).toBeNull();
  });

  it("refuses a SRV delete that does not carry the full RDATA", async () => {
    const calls = installRecordingFetch();
    const { deleteRecord } = await service();

    await expect(
      deleteRecord({ zone: "innotel.us", type: "SRV", name: "_autodiscover._tcp", value: "autodiscover.innotel.us" }, CONN),
    ).rejects.toThrow(/priority weight port target/);
    // Nothing was sent: guessing the missing fields would delete a different record.
    expect(calls).toHaveLength(0);
  });

  it("sends CAA and PTR deletes under the names Technitium validates", async () => {
    const calls = installRecordingFetch();
    const { deleteRecord } = await service();

    await deleteRecord(
      { zone: "innotel.us", type: "CAA", name: "@", value: '0 issue "letsencrypt.org"' },
      CONN,
    );
    await deleteRecord({ zone: "1.1.168.192.in-addr.arpa", type: "PTR", name: "10", value: "host.innotel.us" }, CONN);

    const caa = calls[0].searchParams;
    expect(caa.get("flags")).toBe("0");
    expect(caa.get("tag")).toBe("issue");
    expect(caa.get("value")).toBe("letsencrypt.org");
    expect(caa.get("text")).toBeNull();

    const ptr = calls[1].searchParams;
    expect(ptr.get("ptrName")).toBe("host.innotel.us");
    expect(ptr.get("text")).toBeNull();
  });

  it("refuses a CAA delete that does not carry flags, tag and value", async () => {
    const calls = installRecordingFetch();
    const { deleteRecord } = await service();

    await expect(
      deleteRecord({ zone: "innotel.us", type: "CAA", name: "@", value: "letsencrypt.org" }, CONN),
    ).rejects.toThrow(/flags tag value/);
    expect(calls).toHaveLength(0);
  });

  it("still deletes MX by preference and exchange", async () => {
    const calls = installRecordingFetch();
    const { deleteRecord } = await service();

    await deleteRecord({ zone: "innotel.us", type: "MX", name: "@", value: "10 mail.innotel.us" }, CONN);

    const q = calls[0].searchParams;
    expect(q.get("type")).toBe("MX");
    expect(q.get("preference")).toBe("10");
    expect(q.get("exchange")).toBe("mail.innotel.us");
  });
});
