export interface Domain {
  id: number;
  name: string;
  created_at: string;
}

export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  value: string;
  disabled?: boolean;
}

export interface HealthSummary {
  score: number;
  grade: string;
}

export interface HealthCheck {
  name: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

export interface CertHealth extends HealthSummary {
  checks: HealthCheck[];
}

export interface Certificate {
  id: number;
  name: string;
  domain: string;
  wildcard: boolean;
  status: "issuing" | "issued" | "error";
  error: string | null;
  domains: string[];
  expiresAt: string | null;
  issuedAt: string | null;
  autoRenew: boolean;
  createdAt: string;
  hasMaterial: boolean;
  source: string | null;
  health: HealthSummary;
}

export interface DiscoveredCertificate {
  id: number;
  source: string;
  sourceId: string | null;
  name: string;
  domains: string[];
  issuer: string | null;
  fingerprint: string | null;
  expiresAt: string | null;
  issuedAt: string | null;
  firstSeen: string;
  lastSeen: string;
  hasMaterial: boolean;
  health: HealthSummary;
}

export interface DnsAudit {
  domain: string;
  runAt: string;
  score: number;
  grade: string;
  checks: HealthCheck[];
}

export interface Activity {
  id: number;
  ts: string;
  kind: string;
  message: string;
  detail: string | null;
}

export interface NpmProxyHost {
  id: number;
  domain_names: string[];
  forward_scheme: string;
  forward_host: string;
  forward_port: number;
  certificate_id: number;
  ssl_forced: boolean;
  http2_support: boolean;
  enabled: boolean;
}

export interface NpmCertificate {
  id: number;
  nice_name: string;
  provider: string;
  domain_names: string[];
  expires_on: string | null;
}

export interface TenantRow {
  id: number;
  slug: string;
  name: string;
  created_at: string;
}

export interface TenantMember {
  pk: string;
  username: string;
  email: string;
  name: string;
}

export interface DnsProvider {
  id: number;
  tenantId: number;
  name: string;
  kind: string;
  host: string;
  port: number;
  url: string | null;
  user: string;
  hasToken: boolean;
  hasPassword: boolean;
  hasKey: boolean;
  hasTsig: boolean;
  isDefault: boolean;
  createdAt: string;
}

export interface PkiStatus {
  initialized: boolean;
  commonName: string | null;
  caFingerprint: string | null;
  caExpiresAt: string | null;
  createdAt: string | null;
  issued: number;
  revoked: number;
}

export interface PkiCa {
  certificate: string;
  commonName: string;
  fingerprint: string;
  expiresAt: string;
  createdAt: string;
}

export interface ClientCertificate {
  id: number;
  name: string;
  email: string | null;
  serial: string;
  status: "issued" | "revoked";
  fingerprint: string | null;
  expiresAt: string | null;
  issuedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

export interface AuthConfig {
  localEnabled: boolean;
  oidc: {
    enabled: boolean;
    issuerUrl: string;
    redirectUri: string;
  };
}

export interface SessionUser {
  sub: string;
  email: string;
  name: string;
  groups: string[];
  provider: "local" | "authentik";
}

// ── Orchestrator / Technitium / DHCP / Blocking ───────────────────────────

export interface ServerIdentity {
  serverId: string;
  labDomain: string;
  apex: string;
  wildcard: string;
  registered: boolean;
  wildcardCertId: number | null;
  wildcardCert?: Certificate | null;
  centralUrl: string | null;
  registeredAt: string | null;
  autoWildcard: boolean;
  wildcardValidityDays: number;
  registerUrl: string | null;
  orchestrator: { enabled: boolean; dhcpEnabled: boolean; blockingEnabled: boolean };
}

export interface DhcpScope {
  name: string;
  enabled: boolean;
  startingAddress: string;
  endingAddress: string;
  subnetMask: string;
  networkAddress?: string;
  broadcastAddress?: string;
  routerAddress?: string;
  domainName?: string;
  dnsServers?: string;
  leaseTimeDays?: number;
}

export interface DhcpLease {
  scope: string;
  type: string;
  hardwareAddress: string;
  address: string;
  hostName: string | null;
  leaseObtained: string;
  leaseExpires: string;
  clientIdentifier?: string;
}

export interface BlockingStatus {
  enabled: boolean;
  blockListUrls: string[];
  blockedZones: number;
  allowedZones: number;
  detail: string;
}

export interface CrsStatus {
  homeUrl: string;
  masterUrl: string;
  desiredRole: "auto" | "master" | "slave";
  resolvedRole: "master" | "slave" | "isolated-master" | "offline-slave";
  domain: string;
  isMaster: boolean;
  isSlave: boolean;
  isAirGapped: boolean;
  lastSyncAt: string | null;
  lastSyncStatus: string | null;
  reachable: boolean | null;
  registryCount: number;
  localCount: number;
  error: string | null;
}

export interface CrsRegistryEntry {
  serverId: string;
  labDomain: string;
  apex: string;
  wildcard: string;
  role: string;
  source: string;
  firstSeen: string;
  lastSeen: string;
  metadata: Record<string, unknown> | null;
}

export interface ServiceApiKey {
  id: number;
  name: string;
  prefix: string;
  scopes: string[];
  tenantId: number | null;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  token?: string;
}

export interface OrchestratorStatus {
  server: { serverId: string; labDomain: string; apex: string; wildcard: string; registered: boolean; wildcardCertId: number | null };
  technitium: { reachable: boolean; detail: string; url: string };
  dhcp: { reachable: boolean; scopes: number; leases: number; detail: string };
  blocking: BlockingStatus;
  vault: { enabled: boolean; status: string; addr: string };
  config: { orchestrator: { enabled: boolean; dhcpEnabled: boolean; blockingEnabled: boolean }; server: { id: string; labDomain: string; wildcardValidityDays: number; autoWildcard: boolean } };
}

export interface StatusResponse {
  bind: { status: string; detail: string };
  technitium: { status: string; detail: string; url: string };
  dhcp: { status: string; detail: string; scopes: number; leases: number; enabled: boolean };
  blocking: { status: string; detail: string; enabled: boolean; blockedZones: number; allowedZones: number; urls: string[] };
  npm: { status: string };
  auth: {
    oidcEnabled: boolean;
    localEnabled: boolean;
    issuerUrl: string;
    redirectUri: string;
  };
  vault: {
    enabled: boolean;
    status: string;
    addr: string;
  };
  discovery: {
    dirs: string[];
    count: number;
  };
  pki: PkiStatus;
  server: {
    serverId: string;
    labDomain: string;
    apex: string;
    wildcard: string;
    registered: boolean;
    wildcardCertId: number | null;
    autoWildcard: boolean;
    wildcardValidityDays: number;
    registerUrl: string | null;
  };
  orchestrator: {
    enabled: boolean;
    dhcpEnabled: boolean;
    blockingEnabled: boolean;
  };
  config: {
    zone: string;
    acmeDirectoryUrl: string;
    acmeEmail: string;
    bindHost: string;
    npmApiUrl: string;
    tsigConfigured: boolean;
    technitiumUrl: string;
    bindMode: string;
    npmMode: string;
  };
}
