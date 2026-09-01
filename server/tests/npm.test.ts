import { afterEach, describe, expect, it, vi } from "vitest";

// ── Mocked certificate row (npm.ts only reads db.getCertificate) ───────────
interface MockCertRow {
  id: number;
  name: string;
  domain: string;
  wildcard: number;
  strategy: string;
  status: string;
  error: string | null;
  domains_json: string;
  certificate: string | null;
  key: string | null;
  expires_at: string | null;
  issued_at: string | null;
  auto_renew: number;
  created_at: string;
}

function defaultCert(): MockCertRow {
  return {
    id: 1,
    name: "cerulean.innotel.us",
    domain: "cerulean.innotel.us",
    wildcard: 0,
    strategy: "bind",
    status: "issued",
    error: null,
    domains_json: JSON.stringify(["cerulean.innotel.us"]),
    certificate:
      "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
    key: "-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----",
    expires_at: "2030-01-01T00:00:00.000Z",
    issued_at: "2026-01-01T00:00:00.000Z",
    auto_renew: 1,
    created_at: "2026-01-01T00:00:00.000Z",
  };
}

function wildcardCert(): MockCertRow {
  return {
    ...defaultCert(),
    name: "innotel.us",
    domain: "innotel.us",
    wildcard: 1,
    domains_json: JSON.stringify(["innotel.us", "*.innotel.us"]),
  };
}

let mockCert: MockCertRow = defaultCert();

vi.mock("../src/db", () => ({
  db: {
    getCertificate: () => mockCert,
  },
}));

import { config } from "../src/config";
import { npm } from "../src/services/npm";

// ── Stubbed NPM API ─────────────────────────────────────────────────────────
let mockHosts: Record<string, unknown>[] = [];
let mockCerts: Record<string, unknown>[] = [];
const requests: { method: string; path: string; body?: unknown }[] = [];

function jsonResponse(obj: unknown, status = 200): Response {
  return {
    ok: status < 400,
    status,
    json: async () => obj,
    text: async () => JSON.stringify(obj),
  } as unknown as Response;
}

function installMockFetch() {
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const path = new URL(String(url)).pathname;
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    requests.push({ method, path, body });

    if (path === "/api/tokens") {
      return jsonResponse({ token: "test-token", expires: "2099-01-01" });
    }
    if (path === "/api/nginx/proxy-hosts" && method === "GET") {
      return jsonResponse(mockHosts);
    }
    if (path === "/api/nginx/certificates" && method === "GET") {
      return jsonResponse(mockCerts);
    }
    if (path === "/api/nginx/certificates" && method === "POST") {
      const created = { id: 99, ...body };
      mockCerts.push(created);
      return jsonResponse(created, 201);
    }
    if (path.startsWith("/api/nginx/certificates/") && method === "PUT") {
      return jsonResponse({ id: Number(path.split("/").pop()), ...body });
    }
    if (path.startsWith("/api/nginx/proxy-hosts/") && method === "PUT") {
      const id = Number(path.split("/").pop());
      const updated = { id, ...body };
      mockHosts = mockHosts.map((h) => (h.id === id ? updated : h));
      return jsonResponse(updated);
    }
    throw new Error(`Unexpected request: ${method} ${path}`);
  });
}

function makeHost(overrides: Record<string, unknown> = {}) {
  return {
    id: 7,
    domain_names: ["cerulean.innotel.us"],
    forward_scheme: "http",
    forward_host: "10.0.0.5",
    forward_port: 3000,
    certificate_id: 0,
    ssl_forced: false,
    http2_support: true,
    enabled: true,
    meta: { letsencrypt_agree: false, dns_challenge: false },
    ...overrides,
  };
}

function callCount(pathPrefix: string, method: string): number {
  return requests.filter((r) => r.path.startsWith(pathPrefix) && r.method === method)
    .length;
}

function bodyOf(path: string, method: string) {
  return requests.find((r) => r.path === path && r.method === method)?.body;
}

// ── Tests ───────────────────────────────────────────────────────────────────
describe("npm.syncCertificateToNpm", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    mockHosts = [];
    mockCerts = [];
    requests.length = 0;
    mockCert = defaultCert();
    config.npm.wildcardAttach = true;
  });

  it("is a no-op when no proxy host matches the certificate's domains", async () => {
    installMockFetch();
    mockHosts = [makeHost({ domain_names: ["other.innotel.us"] })];

    const result = await npm.syncCertificateToNpm(1);

    expect(result.attached).toEqual([]);
    expect(callCount("/api/nginx/certificates", "POST")).toBe(0);
    expect(callCount("/api/nginx/proxy-hosts/", "PUT")).toBe(0);
  });

  it("imports the certificate and attaches it to the matching proxy host", async () => {
    installMockFetch();
    mockHosts = [makeHost()];

    const result = await npm.syncCertificateToNpm(1);

    expect(result.attached).toEqual(["cerulean.innotel.us"]);
    // certificate imported as a custom ("other") cert
    const created = bodyOf("/api/nginx/certificates", "POST") as {
      provider: string;
      domain_names: string[];
      nice_name: string;
    };
    expect(created.provider).toBe("other");
    expect(created.domain_names).toEqual(["cerulean.innotel.us"]);
    expect(created.nice_name).toBe("cerulean-cerulean.innotel.us");
    // proxy host updated with the new cert id + forced SSL
    const updated = bodyOf("/api/nginx/proxy-hosts/7", "PUT") as {
      certificate_id: number;
      ssl_forced: boolean;
      forward_host: string;
      forward_port: number;
    };
    expect(updated.certificate_id).toBe(99);
    expect(updated.ssl_forced).toBe(true);
    expect(updated.forward_host).toBe("10.0.0.5");
    expect(updated.forward_port).toBe(3000);
  });

  it("reuses and refreshes an existing custom certificate instead of duplicating", async () => {
    installMockFetch();
    mockHosts = [makeHost()];
    mockCerts = [
      {
        id: 3,
        nice_name: "cerulean-cerulean.innotel.us",
        provider: "other",
        domain_names: ["cerulean.innotel.us"],
        expires_on: null,
      },
    ];

    const result = await npm.syncCertificateToNpm(1);

    expect(result.attached).toEqual(["cerulean.innotel.us"]);
    // no new cert created — the existing one is refreshed in place
    expect(callCount("/api/nginx/certificates", "POST")).toBe(0);
    const refreshed = bodyOf("/api/nginx/certificates/3", "PUT") as {
      meta: { certificate: string };
    };
    expect(refreshed.meta.certificate).toContain("BEGIN CERTIFICATE");
    // host points at the refreshed cert
    const updated = bodyOf("/api/nginx/proxy-hosts/7", "PUT") as {
      certificate_id: number;
    };
    expect(updated.certificate_id).toBe(3);
  });

  it("skips hosts that already have this certificate attached", async () => {
    installMockFetch();
    mockCerts = [
      {
        id: 3,
        nice_name: "cerulean-cerulean.innotel.us",
        provider: "other",
        domain_names: ["cerulean.innotel.us"],
        expires_on: null,
      },
    ];
    mockHosts = [makeHost({ certificate_id: 3, ssl_forced: true })];

    const result = await npm.syncCertificateToNpm(1);

    expect(result.attached).toEqual([]);
    expect(callCount("/api/nginx/proxy-hosts/", "PUT")).toBe(0);
    // material is still refreshed so NPM serves the renewed cert
    expect(callCount("/api/nginx/certificates/3", "PUT")).toBe(1);
  });

  it("is a no-op when the certificate has no material yet", async () => {
    installMockFetch();
    mockHosts = [makeHost()];
    mockCert = { ...defaultCert(), certificate: null, key: null };

    const result = await npm.syncCertificateToNpm(1);

    expect(result.attached).toEqual([]);
    expect(callCount("/api/nginx/certificates", "POST")).toBe(0);
  });

  it("attaches a wildcard cert to a matching subdomain proxy host", async () => {
    installMockFetch();
    mockCert = wildcardCert();
    mockHosts = [makeHost()]; // cerulean.innotel.us, no certificate yet

    const result = await npm.syncCertificateToNpm(1);

    expect(result.attached).toEqual(["cerulean.innotel.us"]);
    const created = bodyOf("/api/nginx/certificates", "POST") as {
      domain_names: string[];
      nice_name: string;
    };
    expect(created.domain_names).toEqual(["innotel.us", "*.innotel.us"]);
    expect(created.nice_name).toBe("cerulean-innotel.us-wildcard");
    const updated = bodyOf("/api/nginx/proxy-hosts/7", "PUT") as {
      certificate_id: number;
      ssl_forced: boolean;
    };
    expect(updated.certificate_id).toBe(99);
    expect(updated.ssl_forced).toBe(true);
  });

  it("never replaces an existing certificate with a wildcard", async () => {
    installMockFetch();
    mockCert = wildcardCert();
    mockHosts = [makeHost({ certificate_id: 5, ssl_forced: true })];

    const result = await npm.syncCertificateToNpm(1);

    expect(result.attached).toEqual([]);
    expect(callCount("/api/nginx/proxy-hosts/", "PUT")).toBe(0);
    // the wildcard is still imported so future hosts without a cert can use it
    expect(callCount("/api/nginx/certificates", "POST")).toBe(1);
  });

  it("does not wildcard-match deeper subdomains; the apex matches exactly", async () => {
    installMockFetch();
    mockCert = wildcardCert(); // SANs: innotel.us + *.innotel.us
    mockHosts = [
      makeHost({ id: 1, domain_names: ["a.b.innotel.us"] }),
      makeHost({ id: 2, domain_names: ["innotel.us"] }),
    ];

    const result = await npm.syncCertificateToNpm(1);

    // a.b.innotel.us is not covered by *.innotel.us (only one level deep);
    // the apex innotel.us matches the cert's exact SAN.
    expect(result.attached).toEqual(["innotel.us"]);
    expect(callCount("/api/nginx/proxy-hosts/1", "PUT")).toBe(0);
    expect(callCount("/api/nginx/proxy-hosts/2", "PUT")).toBe(1);
  });

  it("respects NPM_WILDCARD_ATTACH=0", async () => {
    installMockFetch();
    config.npm.wildcardAttach = false;
    mockCert = wildcardCert();
    mockHosts = [makeHost()];

    const result = await npm.syncCertificateToNpm(1);

    expect(result.attached).toEqual([]);
    expect(callCount("/api/nginx/certificates", "POST")).toBe(0);
    expect(callCount("/api/nginx/proxy-hosts/", "PUT")).toBe(0);
  });
});
