import { config } from "../config";
import { db } from "../db";

export interface NpmProxyHost {
  id: number;
  domain_names: string[];
  forward_scheme: string;
  forward_host: string;
  forward_port: number;
  certificate_id: number | string;
  ssl_forced: boolean;
  http2_support: boolean;
  enabled: boolean;
  meta: Record<string, unknown>;
  block_exploits?: boolean;
  caching_enabled?: boolean;
  allow_websocket_upgrade?: boolean;
  access_list_id?: number;
  advanced_config?: string;
}

export interface NpmCertificate {
  id: number;
  nice_name: string;
  provider: string;
  domain_names: string[];
  expires_on: string | null;
}

interface TokenResponse {
  token: string;
  expires: string;
}

class NpmClient {
  private token: string | null = null;
  private tokenExpires = 0;

  private get baseUrl(): string {
    if (!config.npm.apiUrl) {
      throw new Error("NPM_API_URL is not configured — set it in .env");
    }
    return config.npm.apiUrl.replace(/\/$/, "");
  }

  private async getToken(): Promise<string> {
    if (this.token && Date.now() < this.tokenExpires - 60_000) {
      return this.token;
    }
    const res = await fetch(`${this.baseUrl}/api/tokens`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        identity: config.npm.email,
        secret: config.npm.password,
      }),
    });
    if (!res.ok) {
      throw new Error(
        `NPM token request failed (HTTP ${res.status}). Check NPM_EMAIL/NPM_PASSWORD in .env.`,
      );
    }
    const data = (await res.json()) as TokenResponse;
    this.token = data.token;
    // NPM tokens are valid for 1 day; refresh a bit early.
    this.tokenExpires = Date.now() + 20 * 60 * 60 * 1000;
    return this.token;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const token = await this.getToken();
    const res = await fetch(`${this.baseUrl}/api${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let data: T = null as T;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text as unknown as T;
      }
    }
    if (!res.ok) {
      let message: string | undefined;
      if (typeof data === "object" && data !== null && "error" in data) {
        message = (data as { error?: { message?: string } }).error?.message;
      }
      throw new Error(
        `NPM ${method} ${path} failed (HTTP ${res.status}): ${message || text}`,
      );
    }
    return data;
  }

  /** Verify connectivity + credentials. */
  async test(): Promise<string> {
    try {
      await this.getToken();
      return "ok";
    } catch (err) {
      return err instanceof Error ? err.message : "error";
    }
  }

  listProxyHosts(): Promise<NpmProxyHost[]> {
    return this.request<NpmProxyHost[]>("GET", "/nginx/proxy-hosts");
  }

  listCertificates(): Promise<NpmCertificate[]> {
    return this.request<NpmCertificate[]>("GET", "/nginx/certificates");
  }

  /**
   * Import a Cerulean-issued certificate into NPM as a custom ("other")
   * certificate. Returns the NPM certificate id.
   */
  async importCertificate(input: {
    niceName: string;
    domainNames: string[];
    certificate: string;
    key: string;
  }): Promise<number> {
    const created = await this.request<{ id: number }>(
      "POST",
      "/nginx/certificates",
      {
        provider: "other",
        nice_name: input.niceName,
        domain_names: input.domainNames,
        meta: {
          certificate: input.certificate,
          certificate_key: input.key,
        },
      },
    );
    return created.id;
  }

  /**
   * Create a proxy host. When `certificateId` is 0/null, no SSL is attached.
   */
  async createProxyHost(input: {
    domainNames: string[];
    forwardScheme: string;
    forwardHost: string;
    forwardPort: number;
    certificateId?: number;
    sslForced: boolean;
    http2Support: boolean;
    blockExploits?: boolean;
    websocketSupport?: boolean;
  }): Promise<NpmProxyHost> {
    return this.request<NpmProxyHost>("POST", "/nginx/proxy-hosts", {
      domain_names: input.domainNames,
      forward_scheme: input.forwardScheme,
      forward_host: input.forwardHost,
      forward_port: input.forwardPort,
      certificate_id: input.certificateId ?? 0,
      ssl_forced: input.sslForced,
      http2_support: input.http2Support,
      block_exploits: input.blockExploits ?? true,
      caching_enabled: false,
      allow_websocket_upgrade: input.websocketSupport ?? true,
      access_list_id: 0,
      advanced_config: "",
      meta: {
        letsencrypt_agree: false,
        dns_challenge: false,
      },
    });
  }

  /** Refresh the material of an existing custom certificate (renewals). */
  async updateCertificate(
    id: number,
    input: {
      niceName: string;
      domainNames: string[];
      certificate: string;
      key: string;
    },
  ): Promise<void> {
    await this.request("PUT", `/nginx/certificates/${id}`, {
      provider: "other",
      nice_name: input.niceName,
      domain_names: input.domainNames,
      meta: {
        certificate: input.certificate,
        certificate_key: input.key,
      },
    });
  }

  /**
   * Update a proxy host in place — used to attach a certificate. Preserves the
   * host's routing and options; only the SSL certificate changes.
   */
  async updateProxyHost(
    id: number,
    host: NpmProxyHost,
    certificateId: number | string,
  ): Promise<NpmProxyHost> {
    return this.request<NpmProxyHost>("PUT", `/nginx/proxy-hosts/${id}`, {
      domain_names: host.domain_names,
      forward_scheme: host.forward_scheme,
      forward_host: host.forward_host,
      forward_port: host.forward_port,
      certificate_id: certificateId,
      ssl_forced: true,
      http2_support: host.http2_support,
      block_exploits: host.block_exploits ?? true,
      caching_enabled: host.caching_enabled ?? false,
      allow_websocket_upgrade: host.allow_websocket_upgrade ?? true,
      access_list_id: host.access_list_id ?? 0,
      advanced_config: host.advanced_config ?? "",
      meta: host.meta ?? { letsencrypt_agree: false, dns_challenge: false },
    });
  }

  /**
   * After a certificate is issued or renewed, keep NPM in sync: for every
   * proxy host whose domain is covered by the certificate, import (or refresh)
   * the certificate in NPM and attach it to the host. Returns the domains of
   * the hosts that were updated.
   *
   * A wildcard certificate (e.g. *.innotel.us) also covers one-level subdomain
   * proxy hosts (e.g. cerulean.innotel.us) when NPM_WILDCARD_ATTACH is on, but
   * never overrides a certificate a host already has.
   *
   * Safe to call anytime — it is a no-op when NPM is not configured, the
   * certificate has no material yet, or no proxy host matches its domains.
   */
  async syncCertificateToNpm(certId: number): Promise<{ attached: string[] }> {
    if (!config.npm.apiUrl || !config.npm.email || !config.npm.password) {
      return { attached: [] };
    }
    const cert = db.getCertificate(certId);
    if (!cert || !cert.certificate || !cert.key) {
      return { attached: [] };
    }
    const domains: string[] = JSON.parse(cert.domains_json);
    const exactDomains = domains.filter((d) => !d.startsWith("*."));
    const wildcardDomains = domains.filter((d) => d.startsWith("*."));
    const hosts = await this.listProxyHosts();

    const matches = hosts.filter((h) => {
      const hostDomain = (h.domain_names || [])[0];
      if (!hostDomain) return false;
      if (exactDomains.includes(hostDomain)) return true;
      return (
        config.npm.wildcardAttach &&
        wildcardDomains.some((wc) => wildcardCovers(wc, hostDomain))
      );
    });
    if (matches.length === 0) {
      return { attached: [] };
    }

    // Reuse an existing NPM custom certificate with the same domains so
    // renewals refresh in place instead of piling up duplicates.
    const sameDomains = (names?: string[]) =>
      !!names &&
      names.length === domains.length &&
      domains.every((d) => names.includes(d));
    const existing = (await this.listCertificates()).find(
      (c) => c.provider === "other" && sameDomains(c.domain_names),
    );
    let npmCertId: number;
    if (existing) {
      await this.updateCertificate(existing.id, {
        niceName: existing.nice_name,
        domainNames: domains,
        certificate: cert.certificate,
        key: cert.key,
      });
      npmCertId = existing.id;
    } else {
      npmCertId = await this.importCertificate({
        niceName: `cerulean-${cert.domain}${cert.wildcard ? "-wildcard" : ""}`,
        domainNames: domains,
        certificate: cert.certificate,
        key: cert.key,
      });
    }

    const attached: string[] = [];
    for (const host of matches) {
      if (host.certificate_id === npmCertId && host.ssl_forced) continue;
      const coveredExactly = exactDomains.some((d) =>
        (host.domain_names || []).includes(d),
      );
      // A wildcard match never replaces a certificate already on the host.
      if (!coveredExactly && host.certificate_id) continue;
      await this.updateProxyHost(host.id, host, npmCertId);
      attached.push((host.domain_names || []).join(", "));
    }
    return { attached };
  }
}

/**
 * True when the wildcard domain `*.base` covers `hostDomain` — i.e. the host
 * is a single-label subdomain of base (cerulean.innotel.us ← *.innotel.us),
 * but not the apex itself and not a deeper subdomain (a.b.innotel.us).
 */
function wildcardCovers(wildcardDomain: string, hostDomain: string): boolean {
  const base = wildcardDomain.replace(/^\*\./, "");
  if (!base || !hostDomain.endsWith(`.${base}`)) return false;
  const label = hostDomain.slice(0, -(base.length + 1));
  return label.length > 0 && !label.includes(".");
}

export const npm = new NpmClient();
