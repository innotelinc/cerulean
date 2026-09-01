export interface Domain {
  id: number;
  name: string;
  strategy: "acme-dns" | "bind";
  acmedns_subdomain: string | null;
  acmedns_fulldomain: string | null;
  created_at: string;
}

export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  value: string;
}

export interface Certificate {
  id: number;
  name: string;
  domain: string;
  wildcard: boolean;
  strategy: "acme-dns" | "bind";
  status: "issuing" | "issued" | "error";
  error: string | null;
  domains: string[];
  expiresAt: string | null;
  issuedAt: string | null;
  autoRenew: boolean;
  createdAt: string;
  hasMaterial: boolean;
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

export interface StatusResponse {
  bind: { status: string; detail: string };
  acmedns: { status: string };
  npm: { status: string };
  config: {
    zone: string;
    acmeDirectoryUrl: string;
    acmeEmail: string;
    bindHost: string;
    acmednsApiUrl: string;
    acmednsDomain: string;
    acmednsPublicIp: string;
    npmApiUrl: string;
    tsigConfigured: boolean;
  };
}
