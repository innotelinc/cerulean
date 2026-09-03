import { config } from "../config";

/**
 * Minimal HashiCorp Vault client (KV v2 engine). When enabled, Cerulean can:
 *
 *  1. Resolve `vault://<path>#<key>` references in .env values — e.g.
 *     `NPM_PASSWORD=vault://cerulean/npm#password` — so real credentials
 *     never live in the repo or shell history.
 *  2. Mirror certificate private keys and ACME account keys into Vault
 *     (`POST /api/vault/sync`) for off-host storage.
 *
 * KV v2 paths are addressed as `secret/data/<path>` under the configured
 * mount prefix.
 */

export interface VaultSecretValue {
  path: string;
  key?: string;
}

/** Parse `vault://<path>#<key>` (or `vault://<path>`). */
export function parseVaultRef(value: string): VaultSecretValue | undefined {
  if (!value.startsWith("vault://")) return undefined;
  const rest = value.slice("vault://".length);
  const hash = rest.indexOf("#");
  if (hash === -1) return { path: rest };
  return { path: rest.slice(0, hash), key: rest.slice(hash + 1) };
}

/**
 * Parse `infisical://<name>` — an Infisical (SecretOps) secret reference.
 * Infisical secret keys are flat names (folders are addressed separately),
 * so no `#key` split is needed; the whole rest is the secret name.
 */
export function parseInfisicalRef(value: string): string | undefined {
  if (!value.startsWith("infisical://")) return undefined;
  const name = value.slice("infisical://".length).trim();
  return name || undefined;
}

class VaultClient {
  isEnabled(): boolean {
    return config.vault.enabled;
  }

  private apiUrl(path: string): string {
    const base = config.vault.addr.replace(/\/$/, "");
    const prefix = config.vault.prefix.replace(/^\/+|\/+$/g, "");
    return `${base}/v1/${prefix}/data/${path.replace(/^\/+/, "")}`;
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; data: unknown }> {
    const res = await fetch(this.apiUrl(path), {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-Vault-Token": config.vault.token,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(15_000),
    });
    const text = await res.text();
    let data: unknown = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }
    return { status: res.status, data };
  }

  async readKV(path: string): Promise<Record<string, string> | undefined> {
    const { status, data } = await this.request("GET", path);
    if (status === 404) return undefined;
    if (status !== 200) {
      throw new Error(
        `Vault read ${path} failed (HTTP ${status}): ${JSON.stringify(data).slice(0, 300)}`,
      );
    }
    const d = data as { data?: { data?: Record<string, unknown> } };
    if (!d.data?.data) return undefined;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(d.data.data)) {
      out[k] = typeof v === "string" ? v : JSON.stringify(v);
    }
    return out;
  }

  async writeKV(path: string, data: Record<string, unknown>): Promise<void> {
    const { status } = await this.request("POST", path, { data });
    if (status !== 200 && status !== 204) {
      throw new Error(`Vault write ${path} failed (HTTP ${status})`);
    }
  }

  async deleteKV(path: string): Promise<void> {
    const { status } = await this.request("DELETE", path);
    if (status !== 204 && status !== 200) {
      throw new Error(`Vault delete ${path} failed (HTTP ${status})`);
    }
  }

  /** Health check — reports "ok" or an error string (never throws). */
  async test(): Promise<string> {
    if (!this.isEnabled()) return "not-configured";
    try {
      await this.readKV("__health__");
      return "ok";
    } catch (err) {
      // A missing key is fine (proves auth + connectivity); a network or
      // permission error is not.
      if (err instanceof Error && /404/.test(err.message)) return "ok";
      return err instanceof Error ? err.message : "error";
    }
  }

  /**
   * Resolve a single .env-style value. `infisical://<name>` reads from
   * Infisical (SecretOps, the Innotel Platform Stack default);
   * `vault://path#key` reads from Vault (legacy). Anything else is returned
   * unchanged.
   */
  async resolveSecretValue(value: string): Promise<string> {
    const infisicalName = parseInfisicalRef(value);
    if (infisicalName) {
      if (!infisical.isEnabled()) {
        throw new Error(
          `Value "${value}" references Infisical but INFISICAL_ADDR/INFISICAL_TOKEN are not configured`,
        );
      }
      return infisical.readSecret(infisicalName);
    }
    const ref = parseVaultRef(value);
    if (!ref) return value;
    if (!this.isEnabled()) {
      throw new Error(
        `Value "${value}" references Vault but VAULT_ADDR/VAULT_TOKEN are not configured`,
      );
    }
    const secret = await this.readKV(ref.path);
    if (!secret) {
      throw new Error(`Vault secret not found: ${ref.path}`);
    }
    if (ref.key) {
      if (!(ref.key in secret)) {
        throw new Error(`Vault secret ${ref.path} has no key "${ref.key}"`);
      }
      return secret[ref.key];
    }
    const first = Object.values(secret)[0];
    if (first === undefined) {
      throw new Error(`Vault secret ${ref.path} is empty`);
    }
    return first;
  }

  /**
   * Mirror sensitive material into Vault: certificate private keys + fullchain
   * and ACME account keys. Returns the paths written.
   */
  async sync(): Promise<{ written: string[] }> {
    if (!this.isEnabled()) {
      return { written: [] };
    }
    // Lazy import keeps the sqlite-backed db out of the module-load graph for
    // components that only need secret resolution (ssh, npm).
    const { db } = await import("../db");
    const written: string[] = [];
    // Per-tenant KV paths: each tenant's material lives under its own prefix
    // (certs/<tenant>/<id>, ...) so vault ACLs can isolate tenants. The root
    // CA and ACME accounts are platform-wide.
    const tenantSlug = (tenantId: number): string =>
      db.getTenant(tenantId)?.slug ?? "default";

    // Infisical mirror: flat secret names (dots/underscores only), written
    // best-effort so vault sync never fails because SecretOps is unreachable.
    const mirror = async (name: string, value: string): Promise<void> => {
      if (!infisical.isEnabled() || !value) return;
      try {
        await infisical.writeSecret(name, value);
      } catch (err) {
        console.error(
          `infisical mirror ${name} failed: ${err instanceof Error ? err.message : err}`,
        );
      }
    };

    for (const cert of db.listCertificates()) {
      if (!cert.certificate && !cert.key) continue;
      const slug = tenantSlug(cert.tenant_id);
      const path = `certs/${slug}/${cert.id}`;
      await this.writeKV(path, {
        certificate: cert.certificate ?? "",
        key: cert.key ?? "",
      });
      written.push(path);
      await mirror(`certs.${slug}.${cert.id}.certificate`, cert.certificate ?? "");
      await mirror(`certs.${slug}.${cert.id}.key`, cert.key ?? "");
    }

    for (const account of db.listAcmeAccounts()) {
      const path = `acme/${account.email}`;
      await this.writeKV(path, { key: account.key });
      written.push(path);
      await mirror(
        `acme.${account.email.replace(/[^A-Za-z0-9._-]/g, "_")}.key`,
        account.key,
      );
    }

    // Private PKI: the root CA key and every issued client-certificate key.
    const ca = db.getCa();
    if (ca) {
      const path = "pki/ca";
      await this.writeKV(path, {
        certificate: ca.certificate,
        key: ca.key,
      });
      written.push(path);
      await mirror("pki.ca.certificate", ca.certificate);
      await mirror("pki.ca.key", ca.key);
    }
    for (const cert of db.listClientCertificates()) {
      if (!cert.key) continue; // CSR-enrolled: the device holds the key
      const slug = tenantSlug(cert.tenant_id);
      const path = `pki/certs/${slug}/${cert.id}`;
      await this.writeKV(path, {
        certificate: cert.certificate,
        key: cert.key,
      });
      written.push(path);
      await mirror(`pki.certs.${slug}.${cert.id}.key`, cert.key);
    }

    return { written };
  }
}

class InfisicalClient {
  isEnabled(): boolean {
    return config.infisical.enabled;
  }

  private apiUrl(path: string): string {
    return `${config.infisical.addr.replace(/\/$/, "")}${path}`;
  }

  private query(): string {
    const q = new URLSearchParams({
      workspaceId: config.infisical.workspaceId,
      environment: config.infisical.environment,
      secretPath: "/",
    });
    return q.toString();
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; data: unknown }> {
    const res = await fetch(this.apiUrl(path), {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.infisical.token}`,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(15_000),
    });
    const text = await res.text();
    let data: unknown = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }
    return { status: res.status, data };
  }

  async readSecret(name: string): Promise<string> {
    const { status, data } = await this.request(
      "GET",
      `/api/v3/secrets/raw/${encodeURIComponent(name)}?${this.query()}`,
    );
    if (status !== 200) {
      throw new Error(
        `Infisical read ${name} failed (HTTP ${status}): ${JSON.stringify(data).slice(0, 300)}`,
      );
    }
    const d = data as { secret?: { secretValue?: string } };
    const value = d.secret?.secretValue;
    if (value === undefined) {
      throw new Error(`Infisical secret not found: ${name}`);
    }
    return value;
  }

  async writeSecret(name: string, value: string): Promise<void> {
    const { status } = await this.request(
      "POST",
      `/api/v3/secrets/raw/${encodeURIComponent(name)}`,
      {
        workspaceId: config.infisical.workspaceId,
        environment: config.infisical.environment,
        secretPath: "/",
        type: "shared",
        secretValue: value,
      },
    );
    if (status !== 200 && status !== 201) {
      throw new Error(`Infisical write ${name} failed (HTTP ${status})`);
    }
  }

  /** Health check — reports "ok" or an error string (never throws). */
  async test(): Promise<string> {
    if (!this.isEnabled()) return "not-configured";
    try {
      await this.readSecret("__probe__");
      return "ok";
    } catch (err) {
      if (err instanceof Error && /404/.test(err.message)) return "ok";
      return err instanceof Error ? err.message : "error";
    }
  }
}

export const infisical = new InfisicalClient();
export const vault = new VaultClient();
