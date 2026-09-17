import express from "express";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

/**
 * The service bridge has to be able to *publish*.
 *
 * Publishing a site is two acts on Cerulean — point the name (DNS record) and
 * put the name on the edge (nginx proxy manager) — and only the first was
 * reachable with a service key. A stack holding a key could therefore resolve a
 * name at a host that never answered for it, which is worse than failing: the
 * publish reported success and the site was unreachable.
 *
 * These are HTTP-level assertions rather than unit tests of a helper, because
 * what went wrong was the *mounting* of the routes: the DNS half was registered
 * under `/service/*` and the NPM half was not. A test of the handler would have
 * passed the whole time.
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

const state = vi.hoisted(() => ({
  /** The one key the mocked store knows, as the caller presents it. */
  keys: new Map<string, unknown>(),
  certs: new Map<number, unknown>(),
  hosts: [] as Array<Record<string, unknown>>,
  calls: [] as string[],
}));

vi.mock("../src/db", () => {
  const handlers: Record<string, (...args: unknown[]) => unknown> = {
    getServiceKeyByHash: (hash) => state.keys.get(String(hash)),
    getCertificate: (id) => state.certs.get(Number(id)),
    touchServiceKey: () => undefined,
    addActivity: () => undefined,
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

vi.mock("../src/services/npm", () => ({
  MTLS_CA_CONTAINER_PATH: "/tmp/cerulean-client-ca.pem",
  materializeClientCaFile: () => null,
  applyMtlsConfig: () => undefined,
  npm: {
    listProxyHosts: async () => {
      state.calls.push("npm.listProxyHosts");
      return state.hosts;
    },
    listCertificates: async () => [],
    createProxyHost: async (input: Record<string, unknown>) => {
      state.calls.push("npm.createProxyHost");
      return { id: 501, ...input };
    },
    updateProxyHost: async (id: number) => {
      state.calls.push("npm.updateProxyHost");
      return { id };
    },
    deleteProxyHost: async () => {
      state.calls.push("npm.deleteProxyHost");
    },
    importCertificate: async () => {
      state.calls.push("npm.importCertificate");
      return 77;
    },
  },
}));

import { hashServiceToken, prefixOfServiceToken, generateServiceToken } from "../src/services/serviceAuth";
import router from "../src/routes";

let server: { close: (cb?: () => void) => void };
let base = "";

/** A key as the store would hold it, paired with the token the caller sends. */
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

/** The error message in a refusal body (`{ error }`), as a string. */
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

describe("service bridge — nginx proxy manager", () => {
  it("refuses a request with no key, naming what is missing", async () => {
    const response = await call("/service/npm/hosts");
    expect(response.status).toBe(401);
    expect(messageOf(response.payload)).toContain("service API key");
  });

  it("lists proxy hosts with an npm scope", async () => {
    state.hosts = [{ id: 79, domain_names: ["site.example"] }];
    const token = installKey(["npm:read"]);
    const response = await call("/service/npm/hosts", token);
    expect(response.status).toBe(200);
    expect(response.payload).toEqual([{ id: 79, domain_names: ["site.example"] }]);
  });

  it("refuses a key that can do DNS but not the edge", async () => {
    const token = installKey(["dns:read"]);
    const response = await call("/service/npm/hosts", token);
    expect(response.status).toBe(403);
    expect(messageOf(response.payload)).toContain("Insufficient scope");
  });

  it("puts a name on the edge with npm:write", async () => {
    const token = installKey(["npm:write"]);
    const response = await call("/service/npm/hosts", token, "POST", {
      domain: "published.example",
      forward_host: "192.0.2.10",
      forward_port: 20130,
      forward_scheme: "http",
      certificate_id: 20,
    });
    expect(response.status).toBe(201);
    expect(state.calls).toContain("npm.createProxyHost");
    expect((response.payload as { domainNames: string[] }).domainNames).toEqual(["published.example"]);
  });

  it("exports certificate material to the edge", async () => {
    state.certs.set(20, {
      id: 20,
      name: "*.studio.example",
      domain: "studio.example",
      wildcard: 1,
      status: "issued",
      domains_json: JSON.stringify(["studio.example", "*.studio.example"]),
      certificate: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
      key: "-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----",
    });
    const token = installKey(["npm:*"]);
    const response = await call("/service/npm/export-cert", token, "POST", { certificate_id: 20 });
    expect(response.status).toBe(201);
    expect(response.payload).toMatchObject({ npmCertificateId: 77 });
  });

  it("reports a certificate the tenant does not have as missing, not as a crash", async () => {
    const token = installKey(["npm:write"]);
    const response = await call("/service/npm/export-cert", token, "POST", { certificate_id: 9999 });
    expect(response.status).toBe(404);
  });

  it("removes a name from the edge with npm:write", async () => {
    state.hosts = [{ id: 79, domain_names: ["site.example"] }];
    const token = installKey(["npm:write"]);
    const response = await call("/service/npm/hosts/79", token, "DELETE");
    expect(response.status).toBe(200);
    expect(response.payload).toEqual({ deleted: true, id: 79 });
  });

  it("404s an id that is not a proxy host", async () => {
    state.hosts = [];
    const token = installKey(["npm:write"]);
    const response = await call("/service/npm/hosts/4242", token, "DELETE");
    expect(response.status).toBe(404);
  });
});
