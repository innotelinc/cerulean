import { config } from "../config";
import { db, type DnsProviderRow } from "../db";

/**
 * Per-tenant DNS providers — now Technitium HTTP API endpoints.
 * A tenant can register its own Technitium server(s); record ops on that
 * tenant's zones run against its default provider. Without a provider,
 * zones fall back to the platform Technitium from .env.
 */

export class ProviderError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "ProviderError";
  }
}

export interface DnsProviderInput {
  name: string;
  host?: string;
  port?: number;
  url?: string;
  apiToken?: string;
  user?: string;
  password?: string;
  isDefault?: boolean;
  // legacy (accepted but ignored)
  keyPath?: string;
  tsigName?: string;
  tsigSecret?: string;
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function normalizeUrl(input: DnsProviderInput): { url: string; host: string; port: number } {
  let url = (input.url || "").trim();
  if (!url && input.host) {
    const host = input.host.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
    const port = input.port ?? 5380;
    url = `http://${host}:${port}`;
    return { url, host, port };
  }
  if (url) {
    if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
    url = url.replace(/\/$/, "");
    try {
      const u = new URL(url);
      return { url, host: u.hostname, port: Number(u.port) || (u.protocol === "https:" ? 443 : 5380) };
    } catch {
      throw new ProviderError(400, "Invalid url — must be http(s)://host:port");
    }
  }
  // No url/host provided — will use platform Technitium (but provider needs its own URL)
  throw new ProviderError(400, "url is required (Technitium HTTP API, e.g. http://10.0.0.5:5380)");
}

function validate(input: DnsProviderInput): { name: string; url: string; host: string; port: number } {
  const name = input.name.trim();
  if (!NAME_RE.test(name)) throw new ProviderError(400, "Invalid name — letters, digits, '.', '_' or '-', 1-64 chars");
  const { url, host, port } = normalizeUrl(input);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new ProviderError(400, "port must be 1-65535");
  if (!host) throw new ProviderError(400, "Invalid host in url");
  // Technitium needs either an API token or a user+password pair for the initial login
  if (!input.apiToken && !(input.user && input.password) && !input.password) {
    // Allow empty if relying on platform token, but per-tenant provider should have its own creds
    // We accept token OR password; if neither, we still allow creation but probe will fail — clearer to require one
    throw new ProviderError(400, "Credentials required — set apiToken (Technitium API token) or user+password");
  }
  return { name, url, host, port };
}

export function providerToJson(row: DnsProviderRow) {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    kind: row.kind,
    host: row.host,
    port: row.port,
    url: row.url,
    user: row.user,
    hasToken: Boolean(row.api_token),
    hasPassword: Boolean(row.password),
    // legacy flags (always false now, kept for UI compat)
    hasKey: false,
    hasTsig: false,
    isDefault: row.is_default === 1,
    createdAt: row.created_at,
  };
}

export function listProviders(tenantId: number) {
  return db.listDnsProviders(tenantId).map(providerToJson);
}

export function createProvider(tenantId: number, input: DnsProviderInput): ReturnType<typeof providerToJson> {
  const v = validate(input);
  if (db.listDnsProviders(tenantId).some((p) => p.name === v.name)) {
    throw new ProviderError(409, `Provider "${v.name}" already exists in this tenant`);
  }
  if (input.isDefault) db.clearDnsProviderDefaults(tenantId);
  return providerToJson(
    db.createDnsProvider({
      tenantId,
      name: v.name,
      kind: "technitium",
      host: v.host,
      port: v.port,
      url: v.url,
      apiToken: input.apiToken,
      user: input.user ?? "admin",
      password: input.password,
      isDefault: input.isDefault ?? db.listDnsProviders(tenantId).length === 0,
    }),
  );
}

export function updateProvider(id: number, tenantId: number, input: Partial<DnsProviderInput>): ReturnType<typeof providerToJson> {
  const existing = db.getDnsProvider(id, tenantId);
  if (!existing) throw new ProviderError(404, "DNS provider not found");

  const merged: DnsProviderInput = {
    name: (input.name ?? existing.name).trim(),
    url: input.url !== undefined ? input.url : existing.url ?? undefined,
    host: input.host ?? existing.host,
    port: input.port ?? existing.port,
    apiToken: input.apiToken !== undefined ? input.apiToken || (existing.api_token ?? undefined) : existing.api_token ?? undefined,
    user: input.user ?? existing.user,
    password: input.password !== undefined ? input.password || (existing.password ?? undefined) : existing.password ?? undefined,
    isDefault: input.isDefault ?? existing.is_default === 1,
  };
  const v = validate(merged);
  if (merged.isDefault) db.clearDnsProviderDefaults(tenantId);
  db.updateDnsProvider(id, tenantId, {
    name: v.name,
    host: v.host,
    port: v.port,
    url: v.url,
    apiToken: merged.apiToken,
    user: merged.user,
    password: merged.password,
    isDefault: merged.isDefault,
  });
  return providerToJson(db.getDnsProvider(id, tenantId)!);
}

export function deleteProvider(id: number, tenantId: number): void {
  db.deleteDnsProvider(id, tenantId);
}

export function providerConnectionForTenant(
  tenantId: number,
): { url: string; apiToken: string; host: string; port: number; user: string; password: string; providerName: string | null } | null {
  const rows = db.listDnsProviders(tenantId);
  const row = rows.find((p) => p.is_default === 1) ?? rows[0] ?? null;
  if (!row) return null;
  return {
    url: row.url ?? `http://${row.host}:${row.port}`,
    apiToken: row.api_token ?? "",
    host: row.host,
    port: row.port,
    user: row.user,
    password: row.password ?? "",
    providerName: row.name,
  };
}

export function platformConnection(): { url: string; token: string; host: string; port: number; user: string; password: string; providerName: null } {
  const u = new URL(config.technitium.url);
  return {
    url: config.technitium.url,
    token: config.technitium.token,
    host: u.hostname,
    port: Number(u.port) || 5380,
    user: config.technitium.user,
    password: config.technitium.password,
    providerName: null,
  };
}

/** Back-compat alias: some routes still import providerConnectionForTenant */
export const effectiveTechnitiumConnection = providerConnectionForTenant;
