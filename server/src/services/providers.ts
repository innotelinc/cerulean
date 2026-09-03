import { config } from "../config";
import { db, type DnsProviderRow } from "../db";

/**
 * Per-tenant DNS providers. A tenant can register its own BIND servers
 * (SSH + nsupdate + TSIG) — record operations on the tenant's zones then run
 * against that server instead of the platform-level BIND from .env. The
 * first provider is used by default; one can be flagged as the default.
 *
 * Everything here is tenant-scoped: members manage their own tenant's
 * providers and can never see another tenant's credentials.
 */

export class ProviderError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ProviderError";
  }
}

export interface DnsProviderInput {
  name: string;
  host: string;
  port?: number;
  user?: string;
  keyPath?: string;
  password?: string;
  tsigName?: string;
  tsigSecret?: string;
  isDefault?: boolean;
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function validate(input: DnsProviderInput): {
  name: string;
  host: string;
  port: number;
  user: string;
} {
  const name = input.name.trim();
  if (!NAME_RE.test(name)) {
    throw new ProviderError(
      400,
      "Invalid name — letters, digits, '.', '_' or '-', 1-64 chars",
    );
  }
  const host = input.host
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/$/, "");
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  const isHostname =
    /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(host) && host.includes(".");
  if (!host || (!isIpv4 && !isHostname)) {
    throw new ProviderError(400, "Invalid host — hostname or IP address only");
  }
  const port = input.port ?? 22;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ProviderError(400, "port must be 1-65535");
  }
  const user = (input.user ?? "root").trim();
  if (!user) throw new ProviderError(400, "user is required");
  if (!input.keyPath && !input.password) {
    throw new ProviderError(
      400,
      "Credentials required — set key_path (PEM path on the portal host) or password",
    );
  }
  return { name, host, port, user };
}

/** JSON-safe view: credentials never leave the server in list/detail bodies. */
export function providerToJson(row: DnsProviderRow) {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    kind: row.kind,
    host: row.host,
    port: row.port,
    user: row.user,
    hasKey: Boolean(row.key_path),
    hasPassword: Boolean(row.password),
    hasTsig: Boolean(row.tsig_name && row.tsig_secret),
    isDefault: row.is_default === 1,
    createdAt: row.created_at,
  };
}

export function listProviders(tenantId: number) {
  return db.listDnsProviders(tenantId).map(providerToJson);
}

export function createProvider(
  tenantId: number,
  input: DnsProviderInput,
): ReturnType<typeof providerToJson> {
  const v = validate(input);
  if (db.listDnsProviders(tenantId).some((p) => p.name === v.name)) {
    throw new ProviderError(409, `Provider "${v.name}" already exists in this tenant`);
  }
  if (input.isDefault) db.clearDnsProviderDefaults(tenantId);
  return providerToJson(
    db.createDnsProvider({
      tenantId,
      name: v.name,
      host: v.host,
      port: v.port,
      user: v.user,
      keyPath: input.keyPath,
      password: input.password,
      tsigName: input.tsigName,
      tsigSecret: input.tsigSecret,
      isDefault: input.isDefault ?? db.listDnsProviders(tenantId).length === 0,
    }),
  );
}

export function updateProvider(
  id: number,
  tenantId: number,
  input: Partial<DnsProviderInput>,
): ReturnType<typeof providerToJson> {
  const existing = db.getDnsProvider(id, tenantId);
  if (!existing) throw new ProviderError(404, "DNS provider not found");
  // Merge over the stored row: absent fields keep their stored value, and a
  // blank secret means "unchanged" (secrets are write-only).
  const merged: DnsProviderInput = {
    name: (input.name ?? existing.name).trim(),
    host: input.host ?? existing.host,
    port: input.port ?? existing.port,
    user: input.user ?? existing.user,
    keyPath:
      input.keyPath !== undefined
        ? input.keyPath || (existing.key_path ?? undefined)
        : (existing.key_path ?? undefined),
    password:
      input.password !== undefined
        ? input.password || (existing.password ?? undefined)
        : (existing.password ?? undefined),
    tsigName:
      input.tsigName !== undefined
        ? input.tsigName || (existing.tsig_name ?? undefined)
        : (existing.tsig_name ?? undefined),
    tsigSecret:
      input.tsigSecret !== undefined
        ? input.tsigSecret || (existing.tsig_secret ?? undefined)
        : (existing.tsig_secret ?? undefined),
    isDefault: input.isDefault ?? existing.is_default === 1,
  };
  validate(merged);
  if (merged.isDefault) db.clearDnsProviderDefaults(tenantId);
  db.updateDnsProvider(id, tenantId, {
    name: merged.name,
    host: merged.host,
    port: merged.port,
    user: merged.user,
    keyPath: merged.keyPath,
    password: merged.password,
    tsigName: merged.tsigName,
    tsigSecret: merged.tsigSecret,
    isDefault: merged.isDefault,
  });
  // The row is guaranteed to exist (checked above), so re-fetch for the
  // post-update view. Credentials never leave the server.
  return providerToJson(db.getDnsProvider(id, tenantId)!);
}

export function deleteProvider(id: number, tenantId: number): void {
  db.deleteDnsProvider(id, tenantId);
}

/**
 * Connection settings for a tenant's zones: its default provider, or the
 * first one registered, or null to fall back to the platform BIND (.env).
 */
export function providerConnectionForTenant(
  tenantId: number,
): {
  host: string;
  port: number;
  user: string;
  keyPath: string;
  password: string;
  tsigName: string;
  tsigSecret: string;
  providerName: string | null;
} | null {
  const rows = db.listDnsProviders(tenantId);
  const row =
    rows.find((p) => p.is_default === 1) ??
    rows[0] ??
    null;
  if (!row) return null;
  return {
    host: row.host,
    port: row.port,
    user: row.user,
    keyPath: row.key_path ?? "",
    password: row.password ?? "",
    tsigName: row.tsig_name ?? "",
    tsigSecret: row.tsig_secret ?? "",
    providerName: row.name,
  };
}

/** Convenience: platform BIND connection from .env (the fallback target). */
export function platformConnection(): {
  host: string;
  port: number;
  user: string;
  keyPath: string;
  password: string;
  tsigName: string;
  tsigSecret: string;
  providerName: null;
} {
  const b = config.bind;
  return {
    host: b.host,
    port: b.port,
    user: b.user,
    keyPath: b.keyPath,
    password: b.password,
    tsigName: b.tsigName,
    tsigSecret: b.tsigSecret,
    providerName: null,
  };
}
