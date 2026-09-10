const TOKEN_KEY = "cerulean_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

function readCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export function adoptCookieToken(): void {
  if (getToken()) return;
  const cookie = readCookie(TOKEN_KEY);
  if (cookie) {
    setToken(cookie);
    document.cookie = `${TOKEN_KEY}=; Path=/; Max-Age=0`;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const token = getToken();
  const res = await fetch(`/api${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (res.status === 401) {
    clearToken();
    window.location.hash = "#/login";
    throw new Error("Session expired — please log in again");
  }
  if (!res.ok) {
    const message =
      typeof data === "object" && data !== null && "error" in (data as object)
        ? String((data as { error: unknown }).error)
        : `Request failed (HTTP ${res.status})`;
    throw new Error(message);
  }
  return data as T;
}

export const api = {
  login: (password: string) =>
    request<{ token: string }>("POST", "/auth/login", { password }),
  logout: () => request<{ ok: boolean }>("POST", "/auth/logout"),
  authConfig: () => request<import("./types").AuthConfig>("GET", "/auth/config"),
  me: () =>
    request<{
      user: import("./types").SessionUser | null;
      tenant?: { id: number; slug: string; name: string } | null;
      tenants?: { id: number; slug: string; name: string }[];
      platform?: boolean;
    }>("GET", "/auth/me"),
  status: () => request<import("./types").StatusResponse>("GET", "/status"),
  activities: () => request<import("./types").Activity[]>("GET", "/activities"),

  vaultSync: () => request<{ ok: boolean; written: string[] }>("POST", "/vault/sync"),

  listDiscovered: () =>
    request<import("./types").DiscoveredCertificate[]>("GET", "/discovery/certificates"),
  scanDiscovery: () =>
    request<{ ok: boolean; added: number; updated: number; sources: { npm: number; file: number } }>(
      "POST",
      "/discovery/scan",
    ),
  deleteDiscovered: (id: number) =>
    request<{ ok: boolean }>("DELETE", `/discovery/certificates/${id}`),

  auditDns: (domain?: string) =>
    request<import("./types").DnsAudit[]>(
      "GET",
      `/audit/dns${domain ? `?domain=${encodeURIComponent(domain)}` : ""}`,
    ),
  auditHistory: () =>
    request<
      { id: number; domain: string; runAt: string; score: number; checks: import("./types").HealthCheck[] }[]
    >("GET", "/audit/dns/history"),
  certHealth: (id: number) =>
    request<import("./types").CertHealth>("GET", `/certificates/${id}/health`),

  listDomains: () => request<import("./types").Domain[]>("GET", "/domains"),
  createDomain: (input: { name: string }) =>
    request<import("./types").Domain>("POST", "/domains", input),
  deleteDomain: (id: number) =>
    request<{ ok: boolean }>("DELETE", `/domains/${id}`),
  listRecords: (id: number) =>
    request<import("./types").DnsRecord[]>("GET", `/domains/${id}/records`),
  addRecord: (
    id: number,
    input: {
      type: string;
      name: string;
      value: string;
      ttl?: number;
      priority?: number;
    },
  ) => request<{ ok: boolean }>("POST", `/domains/${id}/records`, input),
  deleteRecord: (
    id: number,
    input: { type: string; name: string; value?: string },
  ) => request<{ ok: boolean }>("DELETE", `/domains/${id}/records`, input),

  listCertificates: () =>
    request<import("./types").Certificate[]>("GET", "/certificates"),
  createCertificate: (input: {
    name?: string;
    domain?: string;
    wildcard?: boolean;
  }) => request<import("./types").Certificate>("POST", "/certificates", input),
  getCertificate: (id: number) =>
    request<import("./types").Certificate>("GET", `/certificates/${id}`),
  renewCertificate: (id: number) =>
    request<{ ok: boolean }>("POST", `/certificates/${id}/renew`),
  deleteCertificate: (id: number) =>
    request<{ ok: boolean }>("DELETE", `/certificates/${id}`),
  certMaterial: (id: number) =>
    request<{ certificate: string; key: string }>(
      "GET",
      `/certificates/${id}/material`,
    ),

  npmHosts: () => request<import("./types").NpmProxyHost[]>("GET", "/npm/hosts"),
  npmCertificates: () =>
    request<import("./types").NpmCertificate[]>("GET", "/npm/certificates"),
  exportCert: (input: { certificate_id: number; nice_name?: string }) =>
    request<{ npmCertificateId: number; niceName: string }>(
      "POST",
      "/npm/export-cert",
      input,
    ),
  createNpmHost: (input: {
    domain: string;
    forward_host: string;
    forward_port: number;
    forward_scheme?: string;
    certificate_id?: number;
    ssl_forced?: boolean;
    http2_support?: boolean;
  }) => request<import("./types").NpmProxyHost>("POST", "/npm/hosts", input),

  // ── DNS providers (Technitium) ───────────────────────────────────────────
  listDnsProviders: () =>
    request<import("./types").DnsProvider[]>("GET", "/dns/providers"),
  createDnsProvider: (input: {
    name: string;
    url?: string;
    host?: string;
    port?: number;
    user?: string;
    api_token?: string;
    apiToken?: string;
    password?: string;
    default?: boolean;
    isDefault?: boolean;
  }) => request<import("./types").DnsProvider>("POST", "/dns/providers", input),
  updateDnsProvider: (
    id: number,
    input: {
      name?: string;
      url?: string;
      host?: string;
      port?: number;
      user?: string;
      api_token?: string;
      apiToken?: string;
      password?: string;
      default?: boolean;
      isDefault?: boolean;
    },
  ) => request<import("./types").DnsProvider>("PATCH", `/dns/providers/${id}`, input),
  deleteDnsProvider: (id: number) =>
    request<{ ok: boolean }>("DELETE", `/dns/providers/${id}`),

  // ── Server identity + orchestrator ───────────────────────────────────────
  serverIdentity: () =>
    request<import("./types").ServerIdentity>("GET", "/server/identity"),
  updateServerIdentity: (input: { serverId?: string; labDomain?: string }) =>
    request<import("./types").ServerIdentity>("POST", "/server/identity", input),
  registerServer: () =>
    request<{ registered: boolean; detail: string }>("POST", "/server/register"),
  renewWildcard: () =>
    request<{ ok: boolean; pki: { certId: number; domain: string } | null; acme: { upgraded: boolean; detail: string }; identity: import("./types").ServerIdentity }>("POST", "/server/wildcard/renew"),
  orchestratorStatus: () =>
    request<import("./types").OrchestratorStatus>("GET", "/orchestrator/status"),

  // ── DHCP ─────────────────────────────────────────────────────────────────
  dhcpScopes: () =>
    request<import("./types").DhcpScope[]>("GET", "/dhcp/scopes"),
  createDhcpScope: (input: {
    name: string;
    startingAddress: string;
    endingAddress: string;
    subnetMask: string;
    routerAddress?: string;
    domainName?: string;
    dnsServers?: string;
    useThisDnsServer?: boolean;
    leaseTimeDays?: number;
  }) => request<{ ok: boolean }>("POST", "/dhcp/scopes", input),
  deleteDhcpScope: (name: string) =>
    request<{ ok: boolean }>("DELETE", `/dhcp/scopes/${encodeURIComponent(name)}`),
  enableDhcpScope: (name: string) =>
    request<{ ok: boolean }>("POST", `/dhcp/scopes/${encodeURIComponent(name)}/enable`),
  disableDhcpScope: (name: string) =>
    request<{ ok: boolean }>("POST", `/dhcp/scopes/${encodeURIComponent(name)}/disable`),
  dhcpLeases: () =>
    request<import("./types").DhcpLease[]>("GET", "/dhcp/leases"),
  deleteDhcpLease: (scope: string, hardwareAddress: string) =>
    request<{ ok: boolean }>("DELETE", "/dhcp/leases", { scope, hardwareAddress }),
  addReservedLease: (scope: string, input: { hardwareAddress: string; ipAddress: string; hostName?: string }) =>
    request<{ ok: boolean }>("POST", `/dhcp/scopes/${encodeURIComponent(scope)}/reserved`, input),
  deleteReservedLease: (scope: string, mac: string) =>
    request<{ ok: boolean }>("DELETE", `/dhcp/scopes/${encodeURIComponent(scope)}/reserved/${encodeURIComponent(mac)}`),

  // ── Ad-blocking ──────────────────────────────────────────────────────────
  blockingStatus: () =>
    request<import("./types").BlockingStatus>("GET", "/blocking/status"),
  setBlocking: (input: { enableBlocking?: boolean; blockListUrls?: string; blockingType?: string }) =>
    request<{ ok: boolean }>("POST", "/blocking", input),
  listBlocked: () => request<string[]>("GET", "/blocking/blocked"),
  addBlocked: (domain: string) =>
    request<{ ok: boolean }>("POST", "/blocking/blocked", { domain }),
  deleteBlocked: (domain: string) =>
    request<{ ok: boolean }>("DELETE", `/blocking/blocked/${encodeURIComponent(domain)}`),
  listAllowed: () => request<string[]>("GET", "/blocking/allowed"),
  addAllowed: (domain: string) =>
    request<{ ok: boolean }>("POST", "/blocking/allowed", { domain }),
  deleteAllowed: (domain: string) =>
    request<{ ok: boolean }>("DELETE", `/blocking/allowed/${encodeURIComponent(domain)}`),
  refreshBlockLists: () =>
    request<{ ok: boolean }>("POST", "/blocking/refresh"),

  listTenants: () => request<import("./types").TenantRow[]>("GET", "/tenants"),
  createTenant: (input: { slug: string; name: string }) =>
    request<import("./types").TenantRow>("POST", "/tenants", input),
  renameTenant: (id: number, name: string) =>
    request<import("./types").TenantRow>("PATCH", `/tenants/${id}`, { name }),
  tenantMembers: (slug: string) =>
    request<{
      available: boolean;
      users: import("./types").TenantMember[];
      groupExists: boolean;
      hint: string;
    }>("GET", `/tenants/${encodeURIComponent(slug)}/members`),

  crsStatus: () => request<import("./types").CrsStatus & { identity: import("./types").ServerIdentity | null }>("GET", "/crs/status"),
  crsRegistry: () => request<{ entries: import("./types").CrsRegistryEntry[]; count: number; status: import("./types").CrsStatus }>("GET", "/crs/registry"),
  crsSync: () => request<{ ok: boolean; pulled: number; detail: string; before: import("./types").CrsStatus; after: import("./types").CrsStatus }>("POST", "/crs/sync"),
  crsRegisterSelf: () => request<{ ok: boolean; serverId: string; apex: string; wildcard: string; status: import("./types").CrsStatus }>("POST", "/crs/register-self"),
  crsResolve: () => request<{ resolvedRole: string; status: import("./types").CrsStatus }>("POST", "/crs/resolve"),

  serviceKeys: () => request<import("./types").ServiceApiKey[]>("GET", "/service/keys"),
  createServiceKey: (input: { name: string; scopes?: string[] | string; tenantId?: number | null }) => request<import("./types").ServiceApiKey>("POST", "/service/keys", input),
  deleteServiceKey: (id: number) => request<{ ok: boolean }>("DELETE", `/service/keys/${id}`),
  revokeServiceKey: (id: number) => request<import("./types").ServiceApiKey>("POST", `/service/keys/${id}/revoke`),

  pkiStatus: () => request<import("./types").PkiStatus>("GET", "/pki/status"),
  pkiInit: (commonName?: string) =>
    request<import("./types").PkiStatus>(
      "POST",
      "/pki/init",
      commonName ? { commonName } : {},
    ),
  pkiCa: () => request<import("./types").PkiCa>("GET", "/pki/ca"),
  pkiCertificates: () =>
    request<import("./types").ClientCertificate[]>("GET", "/pki/certificates"),
  issuePkiCertificate: (input: { name: string; email?: string }) =>
    request<import("./types").ClientCertificate>(
      "POST",
      "/pki/certificates",
      input,
    ),
  pkiCertificateMaterial: (id: number) =>
    request<{ certificate: string; key: string | null; ca: string }>(
      "GET",
      `/pki/certificates/${id}/material`,
    ),
  pkiEnrollmentProfile: (name: string) =>
    request<string>(
      "GET",
      `/pki/enrollment/profile?name=${encodeURIComponent(name)}`,
    ),
  revokePkiCertificate: (id: number) =>
    request<import("./types").ClientCertificate>(
      "POST",
      `/pki/certificates/${id}/revoke`,
    ),
};
