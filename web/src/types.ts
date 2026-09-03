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

export interface StatusResponse {
  bind: { status: string; detail: string };
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
  config: {
    zone: string;
    acmeDirectoryUrl: string;
    acmeEmail: string;
    bindHost: string;
    npmApiUrl: string;
    tsigConfigured: boolean;
  };
}
