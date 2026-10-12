import express from "express";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

/**
 * The service bridge has to be able to *unregister*.
 *
 * `/service/domains` could create a zone but not delete one. A stack that
 * registered a name therefore could never hand it back: the zone kept answering
 * after the domain it was for was gone, and nothing in the estate would ever
 * clean it up. These are HTTP-level assertions, because what was missing was the
 * mounted route itself.
 */

type ServiceKeyRow = {
  id: number;
  name: string;
  prefix: string;
  hash: string;
  scopes_json: string;
  tenant_id: number | null;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
};

type DomainRow = { id: number; name: string; tenant_id: number; created_at: string };

const state = vi.hoisted(() => ({
  keys: new Map<string, unknown>(),
  domains: [] as DomainRow[],
  deleted: [] as Array<{ id: number; tenantId?: number }>,
  zoneDeletes: [] as string[],
  calls: [] as string[],
}));

vi.mock("../src/db", () => {
  const handlers: Record<string, (...args: unknown[]) => unknown> = {
    getServiceKeyByHash: (hash) => state.keys.get(String(hash)),
    touchServiceKey: () => undefined,
    addActivity: () => undefined,
    getDomainByName: (name, tenantId) =>
      state.domains.find((d) => d.name === String(name) && (!tenantId || d.tenant_id === tenantId)),
    deleteDomain: (id, tenantId) => {
      state.deleted.push({ id: Number(id), tenantId: tenantId as number | undefined });
      state.domains = state.domains.filter((d) => d.id !== Number(id));
    },
    listDomains: (tenantId) => state.domains.filter((d) => !tenantId || d.tenant_id === tenantId),
  };

  const db = new Proxy(
    {},
    {
      get(_target, property) {
        const name = String(property);
        return (...args: unknown[]) => {
          state.calls.push(name);
          const handler = handlers[name];
          return handler ? handler(...args) : undefined;
        };
      },
    },
  );

  return { db, DEFAULT_TENANT_ID: 1 };
});

vi.mock("../src/services/technitium", () => ({
  ensureZone: async () => undefined,
  listZone: async () => [],
  deleteZone: async (zone: string) => {
    state.zoneDeletes.push(zone);
  },
}));

vi.mock("../src/services/providers", () => ({
  providerConnectionForTenant: () => null,
}));

vi.mock("../src/services/serverIdentity", () => ({
  currentIdentity: () => ({
    serverId: "lab",
    labDomain: "example.test",
    apex: "lab.example.test",
    wildcard: "*.lab.example.test",
    registered: true,
    wildcardCertId: 1,
  }),
}));

import { hashServiceToken, prefixOfServiceToken, generateServiceToken } from "../src/services/serviceAuth";
import router from "../src/routes";

let server: { close: (cb?: () => void) => void };
let base = "";

function installKey(scopes: string[], tenantId: number | null = null): string {
  const token = generateServiceToken();
  const row: ServiceKeyRow = {
    id: state.keys.size + 1,
    name: `test-${scopes.join("-")}`,
    prefix: prefixOfServiceToken(token),
    hash: hashServiceToken(token),
    scopes_json: JSON.stringify(scopes),
    tenant_id: tenantId,
    created_at: new Date().toISOString(),
    last_used_at: null,
    revoked_at: null,
  };
  state.keys.set(row.hash, row);
  return token;
}

function messageOf(payload: unknown): string {
  if (payload && typeof payload === "object" && "error" in payload) {
    return String((payload as { error?: unknown }).error ?? "");
  }
  return String(payload);
}

async function call(path: string, token?: string, method = "GET", body?: unknown) {
  const response = await fetch(base + path, {
    method,
    headers: {
      accept: "application/json",
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await response.text();
  let payload: unknown = text;
  try {
    payload = JSON.parse(text);
  } catch {
    /* a non-JSON body is itself worth seeing in the assertion */
  }
  return { status: response.status, payload };
}

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/api", router);
  const httpServer = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => httpServer.once("listening", () => resolve()));
  server = httpServer;
  base = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}/api`;
});

afterAll(() => {
  server?.close();
});

describe("service bridge — domain zones", () => {
  it("refuses a delete with no key", async () => {
    const response = await call("/service/domains", undefined, "DELETE", { name: "gone.example" });
    expect(response.status).toBe(401);
    expect(messageOf(response.payload)).toContain("service API key");
  });

  it("refuses a key that can read DNS but not write", async () => {
    const token = installKey(["dns:read"]);
    const response = await call("/service/domains", token, "DELETE", { name: "gone.example" });
    expect(response.status).toBe(403);
    expect(messageOf(response.payload)).toContain("Insufficient scope");
  });

  it("deletes the zone from the resolver and the registration together", async () => {
    state.domains = [{ id: 42, name: "gone.example", tenant_id: 1, created_at: new Date().toISOString() }];
    state.zoneDeletes = [];
    state.deleted = [];
    const token = installKey(["dns:write"]);
    const response = await call("/service/domains", token, "DELETE", { name: "gone.example" });
    expect(response.status).toBe(200);
    expect(response.payload).toEqual({ ok: true, domain: "gone.example" });
    expect(state.zoneDeletes).toEqual(["gone.example"]);
    expect(state.deleted).toEqual([{ id: 42, tenantId: 1 }]);
    expect(state.domains).toHaveLength(0);
  });

  it("takes the name from the query string too", async () => {
    state.domains = [{ id: 43, name: "query.example", tenant_id: 1, created_at: new Date().toISOString() }];
    const token = installKey(["domains:write"]);
    const response = await call("/service/domains?name=query.example", token, "DELETE");
    expect(response.status).toBe(200);
    expect(response.payload).toEqual({ ok: true, domain: "query.example" });
  });

  it("404s a zone the tenant never registered", async () => {
    state.domains = [];
    const token = installKey(["dns:write"]);
    const response = await call("/service/domains", token, "DELETE", { name: "never.example" });
    expect(response.status).toBe(404);
    expect(messageOf(response.payload)).toContain("not registered");
  });

  it("never deletes a platform zone, even with a wildcard key", async () => {
    const token = installKey(["*"]);
    for (const zone of ["example.test", "lab.example.test"]) {
      const response = await call("/service/domains", token, "DELETE", { name: zone });
      expect(response.status).toBe(403);
      expect(messageOf(response.payload)).toContain("platform zone");
    }
  });
});
