import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { config } from "../config";
import { db } from "../db";
import { vault } from "./vault";

// ── Device mTLS (client certificates at the reverse proxy) ────────────────
// "Auto-allow": a proxy host is configured to demand a TLS client certificate
// and to trust exactly the Cerulean internal root CA, so any device holding a
// certificate Cerulean issued is let straight through and anything else is
// rejected by nginx itself — no app changes needed.

/** Client-CA file as the NPM container sees it (its mounted data dir). */
export const MTLS_CA_CONTAINER_PATH = "/data/cerulean-client-ca.pem";
const MTLS_MARK = "# cerulean-mtls";
const MTLS_MARK_END = "# /cerulean-mtls";

/**
 * Insert (or remove) the mTLS snippet into a proxy host's custom nginx
 * configuration. `on` demands a valid client certificate (mode "on"); `off`
 * strips the block. Idempotent and marker-delimited, so re-runs never
 * duplicate the block and existing custom config is preserved.
 */
export function applyMtlsConfig(
  advancedConfig: string,
  mode: "on" | "off",
): string {
  const lines = (advancedConfig ?? "").split("\n");
  const kept: string[] = [];
  let skipping = false;
  for (const line of lines) {
    if (line.trim() === MTLS_MARK) {
      skipping = true;
      continue;
    }
    if (line.trim() === MTLS_MARK_END) {
      skipping = false;
      continue;
    }
    if (!skipping) kept.push(line);
  }
  const base = kept.join("\n").replace(/\n{3,}/g, "\n\n").trim();
  if (mode === "off") return base;

  const block = [
    MTLS_MARK,
    "# Device TLS client certificates signed by the Cerulean internal CA:",
    "# any device presenting a valid certificate is auto-allowed; requests",
    "# without one are rejected here, at the TLS layer.",
    `ssl_client_certificate ${MTLS_CA_CONTAINER_PATH};`,
    "ssl_verify_client on;",
    MTLS_MARK_END,
  ].join("\n");
  return base ? `${base}\n\n${block}\n` : `${block}\n`;
}

/**
 * Write the internal root CA where the bundled NPM container reads it as the
 * client-certificate trust store (NPM_MODE=local: both containers share the
 * host ./data/npm directory). Returns the host path written, or null in
 * remote mode — there you must place the CA on the NPM host yourself at
 * {@link MTLS_CA_CONTAINER_PATH}.
 */
export function materializeClientCaFile(): string | null {
  if (config.npm.mode !== "local") return null;
  const ca = db.getCa();
  if (!ca) {
    throw new Error(
      "Internal CA is not initialized — initialize it first (POST /api/pki/init)",
    );
  }
  const hostPath = join(config.dataDir, "npm", "cerulean-client-ca.pem");
  mkdirSync(dirname(hostPath), { recursive: true });
  writeFileSync(hostPath, ca.certificate, "utf8");
  return hostPath;
}

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
    // The password may be a vault:// reference resolved from the secret vault.
    const secret = await vault.resolveSecretValue(config.npm.password);
    const res = await fetch(`${this.baseUrl}/api/tokens`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        identity: config.npm.email,
        secret,
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
    return this.parseResponse<T>(res, method, path);
  }

  private async parseResponse<T>(
    res: Response,
    method: string,
    path: string,
  ): Promise<T> {
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

  /**
   * POST the PEM files for a custom ("other") certificate via the multipart
   * /nginx/certificates/:id/upload route. In current NPM builds the JSON
   * create only stores the row + meta — the PEM files land on disk (and nginx
   * becomes able to serve the cert) only through this upload route, which
   * validates the pair and writes /data/custom_ssl/npm-<id>/.
   */
  private async uploadCertFiles(
    id: number,
    certificate: string,
    key: string,
  ): Promise<void> {
    const token = await this.getToken();
    const form = new FormData();
    form.append("certificate", new Blob([certificate]), "certificate.pem");
    form.append("certificate_key", new Blob([key]), "privkey.pem");
    const res = await fetch(
      `${this.baseUrl}/api/nginx/certificates/${id}/upload`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      },
    );
    await this.parseResponse<void>(res, "POST", `/nginx/certificates/${id}/upload`);
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

  /** Fetch a single certificate (includes `meta` with the PEM material). */
  getCertificate(id: number): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("GET", `/nginx/certificates/${id}`);
  }

  /**
   * Import a Cerulean-issued certificate into NPM as a custom ("other")
   * certificate. Returns the NPM certificate id.
   *
   * Current NPM builds require two calls: the JSON create stores the row and
   * its meta, and the multipart /upload materializes the PEM files on disk
   * (without it nginx cannot load the certificate). Older NPM builds that
   * write files directly from the create meta return 404/405 on /upload —
   * there the create alone is sufficient, so those errors are ignored.
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
    await this.tryUpload(created.id, input.certificate, input.key);
    return created.id;
  }

  /** Upload cert files, ignoring "route not found" on older NPM builds. */
  private async tryUpload(
    id: number,
    certificate: string,
    key: string,
  ): Promise<void> {
    try {
      await this.uploadCertFiles(id, certificate, key);
    } catch (err) {
      const status = err instanceof Error ? /HTTP (\d+)/.exec(err.message)?.[1] : "";
      if (status === "404" || status === "405") {
        return; // older NPM: create already wrote the files
      }
      throw err;
    }
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

  /**
   * Refresh the material of an existing custom certificate (renewals).
   *
   * Current NPM builds have no PUT route for certificates: the way to refresh
   * an "other" certificate in place is the multipart /upload route, which
   * updates the row's meta and rewrites the PEM files on disk. On older builds
   * that accept PUT, fall back to it (a 404/405 here means the reverse — this
   * build expects PUT, which writes the files from the updated meta).
   */
  async updateCertificate(
    id: number,
    input: {
      niceName: string;
      domainNames: string[];
      certificate: string;
      key: string;
    },
  ): Promise<void> {
    try {
      await this.uploadCertFiles(id, input.certificate, input.key);
    } catch (err) {
      const status = err instanceof Error ? /HTTP (\d+)/.exec(err.message)?.[1] : "";
      if (status === "404" || status === "405") {
        await this.request("PUT", `/nginx/certificates/${id}`, {
          provider: "other",
          nice_name: input.niceName,
          domain_names: input.domainNames,
          meta: {
            certificate: input.certificate,
            certificate_key: input.key,
          },
        });
        return;
      }
      throw err;
    }
  }

  /**
   * Update a proxy host in place — used to attach a certificate. Preserves the
   * host's routing and options; only the SSL certificate changes.
   */
  async updateProxyHost(
    id: number,
    host: NpmProxyHost,
    certificateId: number | string,
    advancedConfig?: string,
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
      advanced_config: advancedConfig ?? host.advanced_config ?? "",
      meta: host.meta ?? { letsencrypt_agree: false, dns_challenge: false },
    });
  }

  /**
   * Gate (or ungate) a proxy host behind device client certificates issued by
   * the Cerulean internal CA. `on` requires a valid certificate — nginx then
   * auto-allows every trusted device and rejects everything else. The host
   * needs an SSL certificate of its own first (its `certificate_id`).
   */
  async setHostMtls(
    host: NpmProxyHost,
    mode: "on" | "off",
  ): Promise<NpmProxyHost> {
    if (mode === "on" && !Number(host.certificate_id)) {
      throw new Error(
        `Host ${host.domain_names.join(", ")} has no SSL certificate yet — ` +
          "issue one for its domain and attach it before enabling device mTLS",
      );
    }
    return this.updateProxyHost(
      host.id,
      host,
      host.certificate_id,
      applyMtlsConfig(host.advanced_config ?? "", mode),
    );
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

    // Reuse an existing NPM custom certificate for this Cerulean cert so
    // renewals refresh in place instead of piling up duplicates. Prefer the
    // stable nice_name (cerulean-<domain>[-wildcard]): NPM's /upload route
    // rewrites a custom cert's domain_names to just its CN, so a wildcard
    // cert ends up listed as the apex only and exact-domain matching would
    // miss it on the next run.
    const expectedNiceName = `cerulean-${cert.domain}${cert.wildcard ? "-wildcard" : ""}`;
    const sameDomains = (names?: string[]) =>
      !!names &&
      names.length === domains.length &&
      domains.every((d) => names.includes(d));
    const byName = (c: NpmCertificate) =>
      c.provider === "other" && c.nice_name === expectedNiceName;
    const byDomains = (c: NpmCertificate) =>
      c.provider === "other" && sameDomains(c.domain_names);
    const all = await this.listCertificates();
    const existing = all.find(byName) || all.find(byDomains);
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
