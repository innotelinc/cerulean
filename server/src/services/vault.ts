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
   * Resolve a single .env-style value: `vault://path#key` reads from Vault,
   * anything else is returned unchanged.
   */
  async resolveSecretValue(value: string): Promise<string> {
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

    for (const cert of db.listCertificates()) {
      if (!cert.certificate && !cert.key) continue;
      const path = `certs/${cert.id}`;
      await this.writeKV(path, {
        certificate: cert.certificate ?? "",
        key: cert.key ?? "",
      });
      written.push(path);
    }

    for (const account of db.listAcmeAccounts()) {
      const path = `acme/${account.email}`;
      await this.writeKV(path, { key: account.key });
      written.push(path);
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
    }
    for (const cert of db.listClientCertificates()) {
      const path = `pki/certs/${cert.id}`;
      await this.writeKV(path, {
        certificate: cert.certificate,
        key: cert.key,
      });
      written.push(path);
    }

    return { written };
  }
}

export const vault = new VaultClient();
