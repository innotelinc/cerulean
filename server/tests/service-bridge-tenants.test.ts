import type { AddressInfo } from "node:net";
import express from "express";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Creating a tenant has to be one write, and it has to go through Cerulean.
 *
 * A tenant is a name the resolver answers for *and* a mail domain with an
 * identity and a mailbox behind it. A caller holds one Cerulean key; it does not
 * hold a resolver token or a mail token. So `POST /service/tenants` is the whole
 * integration: Cerulean registers the zone itself (it is the only principal that
 * may touch the resolver) and then has the mail side built by the mail host —
 * with the *caller's* key forwarded, so the mail host adjudicates that key
 * against Cerulean rather than trusting the caller's story.
 *
 * These are HTTP-level assertions because what was missing was the mounted
 * route, and because the forwarding is the part that must not silently become
 * "Cerulean's platform credential did it".
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

type TenantRow = { id: number; slug: string; name: string; created_at: string };
type DomainRow = { id: number; name: string; tenant_id: number; created_at: string };

const state = vi.hoisted(() => ({
  keys: new Map<string, unknown>(),
  tenants: [{ id: 1, slug: "innotel", name: "Innotel", created_at: "" }] as TenantRow[],
  domains: [] as DomainRow[],
  zonesEnsured: [] as string[],
  zonesDeleted: [] as string[],
  zoneDeleteFails: false,
  zonesServed: [] as string[],
  domainsDeleted: [] as number[],
  domainsCreated: [] as string[],
  activities: [] as string[],
  groupsEnsured: [] as string[],
  authentikConfigured: false,
  groupFailure: false,
  mailCalls: [] as Array<{ path?: string; authorization?: string; body: Record<string, unknown> }>,
  mailStatus: 201,
  mailReply: null as unknown,
}));

vi.mock("../src/db", () => {
  const handlers: Record<string, (...args: unknown[]) => unknown> = {
    getServiceKeyByHash: (hash) => state.keys.get(String(hash)),
    touchServiceKey: () => undefined,
    addActivity: (kind) => {
      state.activities.push(String(kind));
    },
    listTenants: () => state.tenants,
    getDomainByName: (name, tenantId) =>
      state.domains.find((d) => d.name === String(name) && (!tenantId || d.tenant_id === tenantId)),
    deleteDomain: (id) => {
      state.domainsDeleted.push(Number(id));
      state.domains = state.domains.filter((d) => d.id !== Number(id));
    },
    createDomain: (input) => {
      const value = (input || {}) as { name?: unknown; tenantId?: unknown };
      const row: DomainRow = {
        id: state.domains.length + 100,
        name: String(value.name),
        tenant_id: Number(value.tenantId ?? 1),
        created_at: new Date().toISOString(),
      };
      state.domains.push(row);
      state.domainsCreated.push(row.name);
      return row;
    },
  };

  const db = new Proxy(
    {},
    {
      get(_target, property) {
        const name = String(property);
        return (...args: unknown[]) => {
          const handler = handlers[name];
          return handler ? handler(...args) : undefined;
        };
      },
    },
  );

  return { db, DEFAULT_TENANT_ID: 1 };
});

vi.mock("../src/services/technitium", () => ({
  ensureZone: async (zone: string) => {
    state.zonesEnsured.push(zone);
  },
  listZone: async () => [],
  deleteZone: async (zone: string) => {
    state.zonesDeleted.push(zone);
    if (state.zoneDeleteFails) throw new Error("Technitium said no");
  },
  addRecord: async () => undefined,
  listZones: async () => state.zonesServed.map((name) => ({ name, type: "Primary", disabled: false })),
  deleteRecord: async () => undefined,
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

vi.mock("../src/services/authentik", () => ({
  adminConfigured: () => state.authentikConfigured,
  ensureGroup: async (name: string) => {
    if (state.groupFailure) throw new Error("authentik said no");
    state.groupsEnsured.push(name);
  },
  listGroupMembers: async () => [],
}));

import { config } from "../src/config";
import { generateServiceToken, hashServiceToken, prefixOfServiceToken } from "../src/services/serviceAuth";
import router from "../src/routes";

let server: { close: (cb?: () => void) => void };
let mailServer: { close: (cb?: () => void) => void };
let base = "";
let mailBase = "";

function installKey(scopes: string[], tenantId: number | null = 1): string {
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

/** The mail host, stubbed: it records the key it was handed and answers on cue. */
function startMailHost(): Promise<{ close: (cb?: () => void) => void }> {
  const app = express();
  app.use(express.json());
  app.post("/api/service/provision", (req, res) => {
    state.mailCalls.push({
      path: "/api/service/provision",
      authorization: req.headers.authorization,
      body: (req.body || {}) as Record<string, unknown>,
    });
    const status = state.mailStatus;
    res
      .status(status)
      .json(state.mailReply ?? { ok: status < 400, created: status === 201, password: status === 201 ? "one-time" : null });
  });
  const httpServer = app.listen(0, "127.0.0.1");
  app.post("/api/service/deprovision", (req, res) => {
    state.mailCalls.push({
      path: "/api/service/deprovision",
      authorization: req.headers.authorization,
      body: (req.body || {}) as Record<string, unknown>,
    });
    const status = state.mailStatus;
    res
      .status(status)
      .json(state.mailReply ?? {
        ok: status < 400,
        account: { email: req.body?.email, removed: status < 400 },
        domainRemoved: req.body?.removeDomain
          ? { domain: req.body?.domain, destroyed: true, removed: true }
          : null,
      });
  });
  return new Promise((resolve) => {
    httpServer.once("listening", () => resolve(httpServer));
  });
}

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/api", router);
  const httpServer = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => httpServer.once("listening", () => resolve()));
  server = httpServer;
  base = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}/api`;

  mailServer = await startMailHost();
  mailBase = `http://127.0.0.1:${(mailServer as unknown as { address: () => AddressInfo }).address().port}`;
});

afterAll(() => {
  server?.close();
  mailServer?.close();
});

beforeEach(() => {
  state.tenants = [{ id: 1, slug: "innotel", name: "Innotel", created_at: "" }];
  state.domains = [];
  state.zonesEnsured = [];
  state.zonesDeleted = [];
  state.zoneDeleteFails = false;
  state.zonesServed = [];
  state.domainsDeleted = [];
  state.domainsCreated = [];
  state.activities = [];
  state.groupsEnsured = [];
  state.authentikConfigured = false;
  state.groupFailure = false;
  state.mailCalls = [];
  state.mailStatus = 201;
  state.mailReply = null;
  config.mail.provisionUrl = mailBase;
});

describe("service bridge — tenant provisioning", () => {
  it("refuses a provision with no key", async () => {
    const response = await call("/service/tenants", undefined, "POST", {
      domain: "acme.example",
      email: "ops@acme.example",
    });
    expect(response.status).toBe(401);
    expect(messageOf(response.payload)).toContain("service API key");
  });

  it("refuses a key that may provision mail but not tenants", async () => {
    const token = installKey(["mail:provision"]);
    const response = await call("/service/tenants", token, "POST", {
      domain: "acme.example",
      email: "ops@acme.example",
    });
    expect(response.status).toBe(403);
    expect(messageOf(response.payload)).toContain("Insufficient scope");
  });

  it("refuses an account that is not at the domain being provisioned", async () => {
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "POST", {
      domain: "acme.example",
      email: "ops@elsewhere.example",
    });
    expect(response.status).toBe(400);
    expect(messageOf(response.payload)).toContain("must be an address at acme.example");
    expect(state.zonesEnsured).toEqual([]);
    expect(state.mailCalls).toEqual([]);
  });

  it("registers the zone and has the mail host build the tenant, on the caller's own key", async () => {
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "POST", {
      domain: "acme.example",
      email: "ops@acme.example",
      name: "Acme Ops",
      groups: ["paid_users"],
    });

    expect(response.status).toBe(201);
    // The resolver was touched by Cerulean, not by the caller.
    expect(state.zonesEnsured).toEqual(["acme.example"]);
    expect(state.domainsCreated).toEqual(["acme.example"]);
    // The mail host was asked with the caller's key — never a platform credential.
    expect(state.mailCalls).toHaveLength(1);
    expect(state.mailCalls[0].authorization).toBe(`Bearer ${token}`);
    expect(state.mailCalls[0].body).toMatchObject({
      domain: "acme.example",
      email: "ops@acme.example",
      name: "Acme Ops",
      groups: ["paid_users"],
    });
    expect((response.payload as { tenant?: { slug?: string } }).tenant?.slug).toBe("innotel");
    expect((response.payload as { mail?: { password?: string } }).mail?.password).toBe("one-time");
    expect(state.activities).toContain("tenant-provision");
  });

  it("is idempotent: a retry finds the zone and answers 200 without a second creation", async () => {
    const token = installKey(["tenants:write", "mail:provision"]);
    await call("/service/tenants", token, "POST", { domain: "acme.example", email: "ops@acme.example" });

    state.mailStatus = 200;
    state.mailReply = { ok: true, created: false, password: null };
    const retry = await call("/service/tenants", token, "POST", {
      domain: "acme.example",
      email: "ops@acme.example",
    });

    expect(retry.status).toBe(200);
    expect(state.zonesEnsured).toEqual(["acme.example"]);
    expect(state.domainsCreated).toEqual(["acme.example"]);
    expect((retry.payload as { domain?: { created?: boolean } }).domain?.created).toBe(false);
    expect((retry.payload as { mail?: { password?: string | null } }).mail?.password).toBeNull();
    // Still asked, so a tenant deleted behind the platform's back is rebuilt.
    expect(state.mailCalls).toHaveLength(2);
  });

  it("says the mail half is unconfigured rather than half-building a tenant in silence", async () => {
    config.mail.provisionUrl = "";
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "POST", {
      domain: "acme.example",
      email: "ops@acme.example",
    });

    expect(response.status).toBe(503);
    expect(messageOf(response.payload)).toContain("MAIL_PROVISION_URL");
    // The zone result is reported, because a caller has to know what did happen.
    expect((response.payload as { domain?: { created?: boolean } }).domain?.created).toBe(true);
    expect(state.mailCalls).toEqual([]);
  });

  it("surfaces the mail host's refusal with the zone result attached", async () => {
    state.mailStatus = 403;
    state.mailReply = { error: "this key is not scoped for mail:provision in Cerulean" };
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "POST", {
      domain: "acme.example",
      email: "ops@acme.example",
    });

    expect(response.status).toBe(502);
    expect(messageOf(response.payload)).toContain("not scoped for mail:provision");
    expect((response.payload as { domain?: { created?: boolean } }).domain?.created).toBe(true);
  });

  it("ensures the tenant's own sign-in group when Authentik is configured", async () => {
    state.authentikConfigured = true;
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "POST", {
      domain: "acme.example",
      email: "ops@acme.example",
    });

    expect(response.status).toBe(201);
    expect(state.groupsEnsured).toEqual(["innotel"]);
  });

  it("reports a group it could not ensure without failing the tenant", async () => {
    state.authentikConfigured = true;
    state.groupFailure = true;
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "POST", {
      domain: "acme.example",
      email: "ops@acme.example",
    });

    expect(response.status).toBe(201);
    expect(String((response.payload as { warning?: string }).warning)).toContain("authentik said no");
  });
});

describe("service bridge — tenant teardown", () => {
  it("refuses a teardown with no key", async () => {
    const response = await call("/service/tenants", undefined, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
    });
    expect(response.status).toBe(401);
    expect(messageOf(response.payload)).toContain("service API key");
  });

  it("refuses a key that may provision mail but not tenants", async () => {
    const token = installKey(["mail:provision"]);
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
    });
    expect(response.status).toBe(403);
    expect(messageOf(response.payload)).toContain("Insufficient scope");
    expect(state.mailCalls).toEqual([]);
  });

  it("refuses a request that asks for nothing", async () => {
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "DELETE", { domain: "acme.example" });
    expect(response.status).toBe(400);
    expect(messageOf(response.payload)).toContain("nothing to remove");
    // Nothing was asked for, so nothing was visited.
    expect(state.mailCalls).toEqual([]);
    expect(state.zonesDeleted).toEqual([]);
  });

  it("refuses a platform zone before anything is touched", async () => {
    const token = installKey(["tenants:write", "mail:provision"]);
    for (const platform of ["example.test", "lab.example.test"]) {
      const response = await call("/service/tenants", token, "DELETE", {
        domain: platform,
        removeDomain: true,
      });
      expect(response.status).toBe(403);
      expect(messageOf(response.payload)).toContain("platform zone");
    }
    expect(state.mailCalls).toEqual([]);
  });

  it("removes the mailbox on the caller's own key, and leaves the domain alone", async () => {
    state.domains.push({ id: 101, name: "acme.example", tenant_id: 1, created_at: "" });
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
    });

    expect(response.status).toBe(200);
    expect(state.mailCalls).toHaveLength(1);
    expect(state.mailCalls[0].path).toBe("/api/service/deprovision");
    // The caller's key travels, exactly as it does for the provision.
    expect(state.mailCalls[0].authorization).toBe(`Bearer ${token}`);
    expect(state.mailCalls[0].body).toMatchObject({
      domain: "acme.example",
      email: "ops@acme.example",
      removeDomain: false,
    });
    expect((response.payload as { domain?: { removed?: boolean } }).domain?.removed).toBe(true);
    // The zone stays: only a mailbox was removed.
    expect(state.zonesDeleted).toEqual([]);
    expect(state.domainsDeleted).toEqual([]);
    expect(state.activities).toContain("tenant-deprovision");
  });

  it("hands the zone back when the domain goes, so the name stops answering", async () => {
    state.domains.push({ id: 101, name: "acme.example", tenant_id: 1, created_at: "" });
    const token = installKey(["tenants:write", "mail:provision"]);
    state.mailReply = {
      account: { email: "ops@acme.example", removed: true },
      domainRemoved: { domain: "acme.example", destroyed: true, removed: true },
    };
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
      removeDomain: true,
    });

    expect(response.status).toBe(200);
    const payload = response.payload as { domain?: { zoneRemoved?: boolean; removed?: boolean } };
    expect(payload.domain?.zoneRemoved).toBe(true);
    expect(payload.domain?.removed).toBe(true);
    expect(state.zonesDeleted).toEqual(["acme.example"]);
    expect(state.domainsDeleted).toEqual([101]);
  });

  it("never removes, and never claims, a zone registered to another tenant", async () => {
    // The caller's own tenant is 1; this zone belongs to tenant 2, and the
    // resolver still serves it — which is the only reason it is not "handed back".
    state.domains.push({ id: 201, name: "acme.example", tenant_id: 2, created_at: "" });
    state.zonesServed = ["acme.example"];
    const token = installKey(["tenants:write", "mail:provision"], 1);
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      removeDomain: true,
    });

    expect(response.status).toBe(200);
    const payload = response.payload as { domain?: { zoneRemoved?: boolean; zoneDetail?: string } };
    expect(payload.domain?.zoneRemoved).toBe(false);
    expect(String(payload.domain?.zoneDetail)).toContain("still served");
    expect(state.zonesDeleted).toEqual([]);
    expect(state.domainsDeleted).toEqual([]);
  });

  it("passes the mail host's refusal through as a conflict, not a bridge failure", async () => {
    state.mailStatus = 400;
    state.mailReply = {
      error:
        "refusing to remove acme.example: 2 other account(s) still live on it (ops@acme.example, postmaster@acme.example)",
    };
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "someone@acme.example",
      removeDomain: true,
    });

    expect(response.status).toBe(409);
    expect(messageOf(response.payload)).toContain("still live on it");
    // A refusal must not leave the resolver half-torn-down.
    expect(state.zonesDeleted).toEqual([]);
    expect(state.domainsDeleted).toEqual([]);
  });

  it("answers 404 when the mail host has nothing to remove", async () => {
    state.mailStatus = 404;
    state.mailReply = { error: "ops@acme.example: no such user" };
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
    });

    expect(response.status).toBe(404);
    expect(state.zonesDeleted).toEqual([]);
  });

  it("reports an unreachable mail host rather than claiming a teardown", async () => {
    state.mailStatus = 500;
    state.mailReply = { error: "boom" };
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
    });

    expect(response.status).toBe(502);
  });

  it("says the mail half is unconfigured rather than removing the zone alone", async () => {
    config.mail.provisionUrl = "";
    state.domains.push({ id: 101, name: "acme.example", tenant_id: 1, created_at: "" });
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
      removeDomain: true,
    });

    expect(response.status).toBe(503);
    expect(messageOf(response.payload)).toContain("MAIL_PROVISION_URL");
    expect(state.zonesDeleted).toEqual([]);
  });

  it("is idempotent: a retry of a finished teardown reports nothing was there", async () => {
    const token = installKey(["tenants:write", "mail:provision"]);
    state.mailReply = {
      account: { email: "ops@acme.example", removed: false, detail: "no such mailbox" },
      domainRemoved: { domain: "acme.example", removed: false, detail: "no such mail domain" },
    };
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
      removeDomain: true,
    });

    expect(response.status).toBe(200);
    expect((response.payload as { domain?: { removed?: boolean } }).domain?.removed).toBe(false);
    expect(state.zonesDeleted).toEqual([]);
  });

  it("refuses an invalid domain and an account that is not at it", async () => {
    const token = installKey(["tenants:write", "mail:provision"]);
    const bad = await call("/service/tenants", token, "DELETE", { domain: "nodots", email: "a@nodots" });
    expect(bad.status).toBe(400);
    const elsewhere = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@elsewhere.example",
    });
    expect(elsewhere.status).toBe(400);
    expect(messageOf(elsewhere.payload)).toContain("must be an address at acme.example");
    expect(state.mailCalls).toEqual([]);
  });
});

describe("service bridge — tenant teardown, the zone half", () => {
  // Cerulean removes the zone as part of removing a mail domain (the mail host's
  // remove_domain calls back into DELETE /service/domains), so by the time the
  // outer request looks there is usually no row left. That is the zone being
  // handed back, and reporting it as "not removed" would call a finished teardown
  // unfinished — which is exactly the bug this pins down.
  it("credits a zone that went with the mail domain instead of calling it missing", async () => {
    const token = installKey(["tenants:write", "mail:provision"]);
    state.mailReply = {
      account: { email: "ops@acme.example", removed: true },
      domainRemoved: { domain: "acme.example", destroyed: true, removed: true },
    };
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
      removeDomain: true,
    });

    expect(response.status).toBe(200);
    const payload = response.payload as { domain?: { zoneRemoved?: boolean; removed?: boolean; zoneDetail?: string } };
    expect(payload.domain?.zoneRemoved).toBe(true);
    expect(payload.domain?.removed).toBe(true);
    expect(String(payload.domain?.zoneDetail)).toContain("went with the mail domain");
    // Nothing was registered here, so nothing was deleted here either.
    expect(state.zonesDeleted).toEqual([]);
    expect(state.domainsDeleted).toEqual([]);
  });

  it("does not claim a zone that was never registered, and no mail domain either", async () => {
    const token = installKey(["tenants:write", "mail:provision"]);
    state.mailReply = {
      account: { email: "ops@acme.example", removed: false, detail: "no such mailbox" },
      domainRemoved: { domain: "acme.example", removed: false, detail: "no such mail domain" },
    };
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
      removeDomain: true,
    });

    expect(response.status).toBe(200);
    const payload = response.payload as { domain?: { zoneRemoved?: boolean; removed?: boolean; zoneDetail?: string } };
    expect(payload.domain?.zoneRemoved).toBe(false);
    expect(payload.domain?.removed).toBe(false);
    expect(String(payload.domain?.zoneDetail)).toContain("No zone was registered");
  });

  it("keeps the registration when the resolver refuses, so a retry can try again", async () => {
    state.domains.push({ id: 101, name: "acme.example", tenant_id: 1, created_at: "" });
    state.zoneDeleteFails = true;
    state.mailReply = {
      account: { email: "ops@acme.example", removed: true },
      domainRemoved: { domain: "acme.example", destroyed: true, removed: true },
    };
    const token = installKey(["tenants:write", "mail:provision"]);
    const response = await call("/service/tenants", token, "DELETE", {
      domain: "acme.example",
      email: "ops@acme.example",
      removeDomain: true,
    });

    expect(response.status).toBe(200);
    const payload = response.payload as { domain?: { zoneRemoved?: boolean }; warning?: string };
    expect(payload.domain?.zoneRemoved).toBe(false);
    expect(String(payload.warning)).toContain("Technitium said no");
    // The row has to survive, or the next attempt would find nothing to remove and
    // report a success against a name that still answers.
    expect(state.domainsDeleted).toEqual([]);
    expect(state.zonesDeleted).toEqual(["acme.example"]);
  });
});

describe("service bridge — whoami", () => {
  it("refuses an anonymous caller", async () => {
    const response = await call("/service/whoami");
    expect(response.status).toBe(401);
    expect(messageOf(response.payload)).toContain("service API key");
  });

  it("describes the key in Cerulean's own words, scopes included", async () => {
    const token = installKey(["tenants:write", "mail:provision"], 1);
    const response = await call("/service/whoami", token);

    expect(response.status).toBe(200);
    expect(response.payload).toMatchObject({
      name: "test-tenants:write-mail:provision",
      scopes: ["tenants:write", "mail:provision"],
      tenantId: 1,
    });
  });
});
