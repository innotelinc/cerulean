import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { config } from "./config";

export interface TenantRow {
  id: number;
  slug: string;
  name: string;
  created_at: string;
}

export interface DnsProviderRow {
  id: number;
  tenant_id: number;
  name: string;
  kind: string; // "technitium" | legacy "bind-ssh"
  host: string;
  port: number;
  user: string;
  key_path: string | null;
  password: string | null;
  tsig_name: string | null;
  tsig_secret: string | null;
  /** Technitium HTTP API fields */
  url: string | null;
  api_token: string | null;
  is_default: number;
  created_at: string;
}

/** Master orchestrator server identity (singleton) */
export interface ServerIdentityRow {
  id: number; // always 1
  server_id: string;
  lab_domain: string;
  wildcard_domain: string; // <id>.lab.innotel.us
  base_domain: string; // *.<id>.lab.innotel.us display
  registered: number; // 0/1
  registered_at: string | null;
  central_url: string | null;
  wildcard_cert_id: number | null;
  created_at: string;
  updated_at: string;
}

export interface CrsRegistryRow {
  server_id: string; // PK = serverId slug
  lab_domain: string;
  apex: string;
  wildcard: string;
  role: string; // master | slave | isolated-master | offline-slave
  source: string; // local | replica | master | home
  first_seen: string;
  last_seen: string;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
}

export interface CrsStateRow {
  id: number; // always 1
  desired_role: string;
  resolved_role: string;
  domain: string;
  home_url: string;
  master_url: string;
  is_air_gapped: number;
  last_sync: string | null;
  last_sync_status: string | null;
  created_at: string;
  updated_at: string;
}

export interface ServiceApiKeyRow {
  id: number;
  name: string;
  prefix: string; // 16 hex chars of the token (for lookup)
  hash: string; // sha256(secret) hex
  scopes_json: string; // JSON string[]
  tenant_id: number | null;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

/** Slug of the built-in tenant that pre-tenant data belongs to. */
export const DEFAULT_TENANT_ID = 1;

export interface DomainRow {
  id: number;
  name: string;
  strategy: string; // "technitium" (legacy "bind" migrated)
  tenant_id: number;
  created_at: string;
}

export interface CertificateRow {
  id: number;
  name: string;
  domain: string;
  wildcard: number;
  strategy: string; // "technitium"
  status: string; // issuing | issued | error
  error: string | null;
  domains_json: string;
  certificate: string | null;
  key: string | null;
  expires_at: string | null;
  issued_at: string | null;
  auto_renew: number;
  tenant_id: number;
  source: string | null; // "pki" | "acme" | null (legacy)
  created_at: string;
}

export interface ActivityRow {
  id: number;
  ts: string;
  kind: string;
  message: string;
  detail: string | null;
}

export interface AcmeAccountRow {
  id: number;
  directory_url: string;
  email: string;
  key: string;
  created_at: string;
}

export interface DiscoveredCertRow {
  id: number;
  source: string; // "npm" | "file"
  source_id: string | null;
  name: string;
  domains_json: string;
  issuer: string | null;
  serial: string | null;
  fingerprint: string | null;
  certificate: string | null;
  key: string | null;
  expires_at: string | null;
  issued_at: string | null;
  first_seen: string;
  last_seen: string;
  tenant_id: number;
}

export interface CaRow {
  id: number; // always 1 (singleton)
  common_name: string;
  certificate: string; // root CA PEM
  key: string; // root CA private key (PKCS#8 PEM)
  serial: number; // last issued serial number (counter)
  created_at: string;
}

export interface ClientCertificateRow {
  id: number;
  name: string; // subject CN + stable device/owner identifier
  email: string | null;
  serial_hex: string;
  status: string; // issued | revoked
  certificate: string; // client cert PEM
  key: string; // client private key (PKCS#8 PEM; "" when CSR-enrolled)
  fingerprint: string | null;
  expires_at: string | null;
  issued_at: string | null;
  revoked_at: string | null;
  tenant_id: number;
  created_at: string;
}

export interface DnsAuditRow {
  id: number;
  domain: string;
  run_at: string;
  score: number;
  checks_json: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

class Database {
  private db: DatabaseSync;

  constructor() {
    if (!fs.existsSync(config.dataDir)) {
      fs.mkdirSync(config.dataDir, { recursive: true });
    }
    this.db = new DatabaseSync(path.join(config.dataDir, "cerulean.db"));
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tenants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS dns_providers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id INTEGER NOT NULL DEFAULT 1,
        name TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT 'technitium',
        host TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 5380,
        user TEXT NOT NULL DEFAULT 'admin',
        key_path TEXT,
        password TEXT,
        tsig_name TEXT,
        tsig_secret TEXT,
        url TEXT,
        api_token TEXT,
        is_default INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        UNIQUE(tenant_id, name)
      );
      CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        strategy TEXT NOT NULL DEFAULT 'technitium',
        tenant_id INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        domain TEXT NOT NULL,
        wildcard INTEGER NOT NULL DEFAULT 0,
        strategy TEXT NOT NULL DEFAULT 'technitium',
        status TEXT NOT NULL DEFAULT 'issuing',
        error TEXT,
        domains_json TEXT NOT NULL DEFAULT '[]',
        certificate TEXT,
        key TEXT,
        expires_at TEXT,
        issued_at TEXT,
        auto_renew INTEGER NOT NULL DEFAULT 1,
        tenant_id INTEGER NOT NULL DEFAULT 1,
        source TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        kind TEXT NOT NULL,
        message TEXT NOT NULL,
        detail TEXT
      );
      CREATE TABLE IF NOT EXISTS acme_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        directory_url TEXT NOT NULL,
        email TEXT NOT NULL,
        key TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(directory_url, email)
      );
      CREATE TABLE IF NOT EXISTS discovered_certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        source_id TEXT,
        name TEXT NOT NULL,
        domains_json TEXT NOT NULL DEFAULT '[]',
        issuer TEXT,
        serial TEXT,
        fingerprint TEXT,
        certificate TEXT,
        key TEXT,
        expires_at TEXT,
        issued_at TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        tenant_id INTEGER NOT NULL DEFAULT 1,
        UNIQUE(source, source_id)
      );
      CREATE TABLE IF NOT EXISTS dns_audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        run_at TEXT NOT NULL,
        score INTEGER NOT NULL,
        checks_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_dns_audits_domain ON dns_audits (domain);

      CREATE TABLE IF NOT EXISTS ca (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        common_name TEXT NOT NULL,
        certificate TEXT NOT NULL,
        key TEXT NOT NULL,
        serial INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS client_certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT,
        serial_hex TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'issued',
        certificate TEXT NOT NULL,
        key TEXT NOT NULL,
        fingerprint TEXT,
        expires_at TEXT,
        issued_at TEXT,
        revoked_at TEXT,
        tenant_id INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_client_certs_status
        ON client_certificates (status);

      -- Master orchestrator: server identity (singleton)
      CREATE TABLE IF NOT EXISTS server_identity (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        server_id TEXT NOT NULL,
        lab_domain TEXT NOT NULL,
        wildcard_domain TEXT NOT NULL,
        base_domain TEXT NOT NULL,
        registered INTEGER NOT NULL DEFAULT 0,
        registered_at TEXT,
        central_url TEXT,
        wildcard_cert_id INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      -- Central Registration Server (CRS): authoritative registry + replica
      CREATE TABLE IF NOT EXISTS crs_registry (
        server_id TEXT PRIMARY KEY,
        lab_domain TEXT NOT NULL,
        apex TEXT NOT NULL,
        wildcard TEXT NOT NULL,
        role TEXT NOT NULL,
        source TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        metadata_json TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS crs_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        desired_role TEXT NOT NULL,
        resolved_role TEXT NOT NULL,
        domain TEXT NOT NULL,
        home_url TEXT NOT NULL,
        master_url TEXT NOT NULL,
        is_air_gapped INTEGER NOT NULL DEFAULT 0,
        last_sync TEXT,
        last_sync_status TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      -- Cross-stack service API keys (other stacks → Cerulean)
      CREATE TABLE IF NOT EXISTS service_api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        prefix TEXT NOT NULL,
        hash TEXT NOT NULL UNIQUE,
        scopes_json TEXT NOT NULL DEFAULT '[]',
        tenant_id INTEGER,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        revoked_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_service_keys_prefix ON service_api_keys (prefix);
      CREATE INDEX IF NOT EXISTS idx_service_keys_tenant ON service_api_keys (tenant_id);
    `);

    this.db
      .prepare(
        `INSERT OR IGNORE INTO tenants (id, slug, name, created_at)
         VALUES (1, 'default', 'Default', ?)`,
      )
      .run(nowIso());

    // Migrate legacy schemas
    for (const table of [
      "domains",
      "certificates",
      "discovered_certificates",
      "client_certificates",
    ]) {
      this.ensureColumn(table, "tenant_id", "INTEGER NOT NULL DEFAULT 1");
      this.db.exec(
        `CREATE INDEX IF NOT EXISTS idx_${table}_tenant ON ${table} (tenant_id);`,
      );
    }
    this.ensureColumn("certificates", "source", "TEXT");
    this.ensureColumn("dns_providers", "kind", "TEXT NOT NULL DEFAULT 'technitium'");
    this.ensureColumn("dns_providers", "url", "TEXT");
    this.ensureColumn("dns_providers", "api_token", "TEXT");
    // Legacy BIND columns remain for backup compatibility but are unused
    this.ensureColumn("dns_providers", "key_path", "TEXT");
    this.ensureColumn("dns_providers", "password", "TEXT");
    this.ensureColumn("dns_providers", "tsig_name", "TEXT");
    this.ensureColumn("dns_providers", "tsig_secret", "TEXT");

    // Normalize old strategy values: bind -> technitium
    try {
      this.db.exec(`UPDATE domains SET strategy='technitium' WHERE strategy='bind'`);
      this.db.exec(`UPDATE certificates SET strategy='technitium' WHERE strategy='bind'`);
      this.db.exec(`UPDATE dns_providers SET kind='technitium' WHERE kind='bind-ssh'`);
    } catch {
      // ignore if columns missing
    }

    this.db.exec(`
      DROP INDEX IF EXISTS idx_client_certs_active_name;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_client_certs_active_name
        ON client_certificates (tenant_id, name) WHERE status = 'issued';
    `);

    // Seed server_identity if empty, using config.server defaults
    const existing = this.db.prepare("SELECT id FROM server_identity WHERE id=1").get();
    if (!existing) {
      const sid = config.server.id;
      const lab = config.server.labDomain;
      const wildcard = `${sid}.${lab}`;
      this.db
        .prepare(
          `INSERT OR IGNORE INTO server_identity
           (id, server_id, lab_domain, wildcard_domain, base_domain, registered, central_url, created_at, updated_at)
           VALUES (1, ?, ?, ?, ?, 0, ?, ?, ?)`,
        )
        .run(sid, lab, wildcard, `*.${wildcard}`, config.server.registerUrl || null, nowIso(), nowIso());
    } else {
      // Keep lab_domain in sync if env changed (but don't overwrite manual server_id)
      try {
        const row = this.db.prepare("SELECT server_id, lab_domain FROM server_identity WHERE id=1").get() as { server_id: string; lab_domain: string };
        if (row && row.lab_domain !== config.server.labDomain) {
          const newWildcard = `${row.server_id}.${config.server.labDomain}`;
          this.db.prepare(`UPDATE server_identity SET lab_domain=?, wildcard_domain=?, base_domain=?, updated_at=? WHERE id=1`)
            .run(config.server.labDomain, newWildcard, `*.${newWildcard}`, nowIso());
        }
      } catch { /* ignore */ }
    }
  }

  private ensureColumn(table: string, column: string, ddl: string): void {
    const cols = this.db
      .prepare(`PRAGMA table_info(${table})`)
      .all() as { name: string }[];
    if (!cols.some((c) => c.name === column)) {
      this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl};`);
    }
  }

  // ── Server identity ────────────────────────────────────────────────────
  getServerIdentity(): ServerIdentityRow | undefined {
    return this.db.prepare("SELECT * FROM server_identity WHERE id=1").get() as ServerIdentityRow | undefined;
  }

  upsertServerIdentity(input: { serverId: string; labDomain: string; centralUrl?: string | null }): ServerIdentityRow {
    const wildcard = `${input.serverId}.${input.labDomain}`;
    const base = `*.${wildcard}`;
    const existing = this.getServerIdentity();
    if (existing) {
      this.db
        .prepare(
          `UPDATE server_identity SET server_id=?, lab_domain=?, wildcard_domain=?, base_domain=?, central_url=COALESCE(?, central_url), updated_at=? WHERE id=1`,
        )
        .run(input.serverId, input.labDomain, wildcard, base, input.centralUrl ?? null, nowIso());
      return this.getServerIdentity()!;
    }
    this.db
      .prepare(
        `INSERT OR REPLACE INTO server_identity
         (id, server_id, lab_domain, wildcard_domain, base_domain, registered, central_url, created_at, updated_at)
         VALUES (1, ?, ?, ?, ?, 0, ?, ?, ?)`,
      )
      .run(input.serverId, input.labDomain, wildcard, base, input.centralUrl ?? null, nowIso(), nowIso());
    return this.getServerIdentity()!;
  }

  setServerRegistered(registered: boolean, centralUrl?: string): void {
    this.db
      .prepare(`UPDATE server_identity SET registered=?, registered_at=?, central_url=COALESCE(?, central_url), updated_at=? WHERE id=1`)
      .run(registered ? 1 : 0, registered ? nowIso() : null, centralUrl ?? null, nowIso());
  }

  setServerWildcardCert(certId: number | null): void {
    this.db.prepare(`UPDATE server_identity SET wildcard_cert_id=?, updated_at=? WHERE id=1`).run(certId, nowIso());
  }

  // ── Tenants ────────────────────────────────────────────────────────────
  listTenants(): TenantRow[] {
    return this.db.prepare("SELECT * FROM tenants ORDER BY id").all() as unknown as TenantRow[];
  }

  getTenant(id: number): TenantRow | undefined {
    return this.db.prepare("SELECT * FROM tenants WHERE id = ?").get(id) as TenantRow | undefined;
  }

  getTenantBySlug(slug: string): TenantRow | undefined {
    return this.db.prepare("SELECT * FROM tenants WHERE slug = ?").get(slug) as TenantRow | undefined;
  }

  createTenant(input: { slug: string; name: string }): TenantRow {
    const result = this.db
      .prepare(`INSERT INTO tenants (slug, name, created_at) VALUES (?, ?, ?)`)
      .run(input.slug, input.name, nowIso());
    return this.getTenant(Number(result.lastInsertRowid))!;
  }

  renameTenant(id: number, name: string): TenantRow | undefined {
    const result = this.db.prepare("UPDATE tenants SET name = ? WHERE id = ?").run(name, id);
    if (Number(result.changes) === 0) return undefined;
    return this.getTenant(id);
  }

  // ── DNS providers (now Technitium HTTP API) ────────────────────────────
  listDnsProviders(tenantId: number): DnsProviderRow[] {
    return this.db
      .prepare("SELECT * FROM dns_providers WHERE tenant_id = ? ORDER BY name")
      .all(tenantId) as unknown as DnsProviderRow[];
  }

  getDnsProvider(id: number, tenantId?: number): DnsProviderRow | undefined {
    const row = tenantId
      ? this.db.prepare("SELECT * FROM dns_providers WHERE id = ? AND tenant_id = ?").get(id, tenantId)
      : this.db.prepare("SELECT * FROM dns_providers WHERE id = ?").get(id);
    return row as DnsProviderRow | undefined;
  }

  createDnsProvider(input: {
    tenantId: number;
    name: string;
    kind?: string;
    host: string;
    port?: number;
    user?: string;
    keyPath?: string;
    password?: string;
    tsigName?: string;
    tsigSecret?: string;
    url?: string;
    apiToken?: string;
    isDefault?: boolean;
  }): DnsProviderRow {
    const result = this.db
      .prepare(
        `INSERT INTO dns_providers
           (tenant_id, name, kind, host, port, user, key_path, password,
            tsig_name, tsig_secret, url, api_token, is_default, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.tenantId,
        input.name,
        input.kind ?? "technitium",
        input.host,
        input.port ?? 5380,
        input.user ?? "admin",
        input.keyPath ?? null,
        input.password ?? null,
        input.tsigName ?? null,
        input.tsigSecret ?? null,
        input.url ?? null,
        input.apiToken ?? null,
        input.isDefault ? 1 : 0,
        nowIso(),
      );
    return this.getDnsProvider(Number(result.lastInsertRowid), input.tenantId)!;
  }

  updateDnsProvider(
    id: number,
    tenantId: number,
    input: {
      name?: string;
      host?: string;
      port?: number;
      user?: string;
      keyPath?: string;
      password?: string | null;
      tsigName?: string;
      tsigSecret?: string;
      url?: string;
      apiToken?: string;
      isDefault?: boolean;
    },
  ): DnsProviderRow | undefined {
    const existing = this.getDnsProvider(id, tenantId);
    if (!existing) return undefined;
    const next = {
      name: input.name ?? existing.name,
      host: input.host ?? existing.host,
      port: input.port ?? existing.port,
      user: input.user ?? existing.user,
      keyPath: input.keyPath !== undefined ? input.keyPath || existing.key_path : existing.key_path,
      password: input.password !== undefined ? input.password || existing.password : existing.password,
      tsigName: input.tsigName !== undefined ? input.tsigName || existing.tsig_name : existing.tsig_name,
      tsigSecret: input.tsigSecret !== undefined ? input.tsigSecret || existing.tsig_secret : existing.tsig_secret,
      url: input.url !== undefined ? input.url || existing.url : existing.url,
      apiToken: input.apiToken !== undefined ? input.apiToken || existing.api_token : existing.api_token,
      isDefault: input.isDefault !== undefined ? input.isDefault : existing.is_default === 1,
    };
    this.db
      .prepare(
        `UPDATE dns_providers SET
           name = ?, host = ?, port = ?, user = ?, key_path = ?, password = ?,
           tsig_name = ?, tsig_secret = ?, url = ?, api_token = ?, is_default = ?
         WHERE id = ? AND tenant_id = ?`,
      )
      .run(
        next.name,
        next.host,
        next.port,
        next.user,
        next.keyPath,
        next.password,
        next.tsigName,
        next.tsigSecret,
        next.url,
        next.apiToken,
        next.isDefault ? 1 : 0,
        id,
        tenantId,
      );
    return this.getDnsProvider(id, tenantId);
  }

  deleteDnsProvider(id: number, tenantId: number): void {
    this.db.prepare("DELETE FROM dns_providers WHERE id = ? AND tenant_id = ?").run(id, tenantId);
  }

  clearDnsProviderDefaults(tenantId: number): void {
    this.db.prepare("UPDATE dns_providers SET is_default = 0 WHERE tenant_id = ?").run(tenantId);
  }

  // ── Domains ────────────────────────────────────────────────────────────
  listDomains(tenantId?: number): DomainRow[] {
    const rows = tenantId
      ? this.db.prepare("SELECT * FROM domains WHERE tenant_id = ? ORDER BY name").all(tenantId)
      : this.db.prepare("SELECT * FROM domains ORDER BY name").all();
    return rows as unknown as DomainRow[];
  }

  getDomain(id: number, tenantId?: number): DomainRow | undefined {
    const row = tenantId
      ? this.db.prepare("SELECT * FROM domains WHERE id = ? AND tenant_id = ?").get(id, tenantId)
      : this.db.prepare("SELECT * FROM domains WHERE id = ?").get(id);
    return row as DomainRow | undefined;
  }

  getDomainByName(name: string, tenantId?: number): DomainRow | undefined {
    const row = tenantId
      ? this.db.prepare("SELECT * FROM domains WHERE name = ? AND tenant_id = ?").get(name.toLowerCase().replace(/\.$/, ""), tenantId)
      : this.db.prepare("SELECT * FROM domains WHERE name = ?").get(name.toLowerCase().replace(/\.$/, ""));
    return row as DomainRow | undefined;
  }

  createDomain(input: { name: string; tenantId?: number }): DomainRow {
    const result = this.db
      .prepare(
        `INSERT INTO domains (name, strategy, tenant_id, created_at)
         VALUES (?, 'technitium', ?, ?)`,
      )
      .run(input.name.toLowerCase().replace(/\.$/, ""), input.tenantId ?? DEFAULT_TENANT_ID, nowIso());
    return this.getDomain(Number(result.lastInsertRowid))!;
  }

  deleteDomain(id: number, tenantId?: number): void {
    if (tenantId) {
      this.db.prepare("DELETE FROM domains WHERE id = ? AND tenant_id = ?").run(id, tenantId);
      return;
    }
    this.db.prepare("DELETE FROM domains WHERE id = ?").run(id);
  }

  // ── Certificates ───────────────────────────────────────────────────────
  listCertificates(tenantId?: number): CertificateRow[] {
    const rows = tenantId
      ? this.db.prepare("SELECT * FROM certificates WHERE tenant_id = ? ORDER BY id DESC").all(tenantId)
      : this.db.prepare("SELECT * FROM certificates ORDER BY id DESC").all();
    return rows as unknown as CertificateRow[];
  }

  getCertificate(id: number, tenantId?: number): CertificateRow | undefined {
    const row = tenantId
      ? this.db.prepare("SELECT * FROM certificates WHERE id = ? AND tenant_id = ?").get(id, tenantId)
      : this.db.prepare("SELECT * FROM certificates WHERE id = ?").get(id);
    return row as CertificateRow | undefined;
  }

  createCertificate(input: {
    name: string;
    domain: string;
    wildcard: boolean;
    autoRenew?: boolean;
    tenantId?: number;
    source?: string;
  }): CertificateRow {
    const result = this.db
      .prepare(
        `INSERT INTO certificates (name, domain, wildcard, strategy, domains_json, auto_renew, tenant_id, source, created_at)
         VALUES (?, ?, ?, 'technitium', ?, ?, ?, ?, ?)`,
      )
      .run(
        input.name,
        input.domain.toLowerCase().replace(/\.$/, ""),
        input.wildcard ? 1 : 0,
        JSON.stringify(input.wildcard ? [input.domain, `*.${input.domain}`] : [input.domain]),
        input.autoRenew === false ? 0 : 1,
        input.tenantId ?? DEFAULT_TENANT_ID,
        input.source ?? null,
        nowIso(),
      );
    return this.getCertificate(Number(result.lastInsertRowid))!;
  }

  updateCertificateStatus(id: number, status: string, error?: string): void {
    this.db.prepare("UPDATE certificates SET status = ?, error = ? WHERE id = ?").run(status, error ?? null, id);
  }

  saveCertificateMaterial(
    id: number,
    certificate: string,
    key: string,
    expiresAt: string,
    source?: string,
  ): void {
    if (source) {
      this.db
        .prepare(
          `UPDATE certificates SET certificate = ?, key = ?, expires_at = ?, issued_at = ?, status = 'issued', error = NULL, source=? WHERE id = ?`,
        )
        .run(certificate, key, expiresAt, nowIso(), source, id);
    } else {
      this.db
        .prepare(
          `UPDATE certificates SET certificate = ?, key = ?, expires_at = ?, issued_at = ?, status = 'issued', error = NULL WHERE id = ?`,
        )
        .run(certificate, key, expiresAt, nowIso(), id);
    }
  }

  deleteCertificate(id: number, tenantId?: number): void {
    if (tenantId) {
      this.db.prepare("DELETE FROM certificates WHERE id = ? AND tenant_id = ?").run(id, tenantId);
      return;
    }
    this.db.prepare("DELETE FROM certificates WHERE id = ?").run(id);
  }

  listExpiringSoon(days: number): CertificateRow[] {
    const cutoff = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    return this.db
      .prepare(
        `SELECT * FROM certificates
         WHERE auto_renew = 1 AND status = 'issued' AND expires_at IS NOT NULL AND expires_at < ?
         ORDER BY expires_at ASC`,
      )
      .all(cutoff) as unknown as CertificateRow[];
  }

  // ── ACME accounts ──────────────────────────────────────────────────────
  getAcmeAccount(directoryUrl: string, email: string): AcmeAccountRow | undefined {
    return this.db
      .prepare("SELECT * FROM acme_accounts WHERE directory_url = ? AND email = ?")
      .get(directoryUrl, email) as AcmeAccountRow | undefined;
  }

  saveAcmeAccount(directoryUrl: string, email: string, key: string): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO acme_accounts (directory_url, email, key, created_at)
         VALUES (?, ?, ?, ?)`,
      )
      .run(directoryUrl, email, key, nowIso());
  }

  listAcmeAccounts(): AcmeAccountRow[] {
    return this.db.prepare("SELECT * FROM acme_accounts").all() as unknown as AcmeAccountRow[];
  }

  // ── Discovered certificates ────────────────────────────────────────────
  upsertDiscoveredCert(
    input: {
      source: string;
      sourceId: string | null;
      name: string;
      domains: string[];
      issuer?: string | null;
      serial?: string | null;
      fingerprint?: string | null;
      certificate?: string | null;
      key?: string | null;
      expiresAt?: string | null;
      issuedAt?: string | null;
    },
    tenantId = DEFAULT_TENANT_ID,
  ): boolean {
    const existing = this.db
      .prepare("SELECT id FROM discovered_certificates WHERE source = ? AND source_id = ?")
      .get(input.source, input.sourceId) as { id: number } | undefined;
    if (existing) {
      this.db
        .prepare(
          `UPDATE discovered_certificates SET
             name = ?, domains_json = ?, issuer = ?, serial = ?, fingerprint = ?,
             certificate = ?, key = ?, expires_at = ?, issued_at = ?, last_seen = ?,
             tenant_id = ?
           WHERE id = ?`,
        )
        .run(
          input.name,
          JSON.stringify(input.domains),
          input.issuer ?? null,
          input.serial ?? null,
          input.fingerprint ?? null,
          input.certificate ?? null,
          input.key ?? null,
          input.expiresAt ?? null,
          input.issuedAt ?? null,
          nowIso(),
          tenantId,
          existing.id,
        );
      return false;
    }
    this.db
      .prepare(
        `INSERT INTO discovered_certificates
           (source, source_id, name, domains_json, issuer, serial, fingerprint,
            certificate, key, expires_at, issued_at, first_seen, last_seen, tenant_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.source,
        input.sourceId,
        input.name,
        JSON.stringify(input.domains),
        input.issuer ?? null,
        input.serial ?? null,
        input.fingerprint ?? null,
        input.certificate ?? null,
        input.key ?? null,
        input.expiresAt ?? null,
        input.issuedAt ?? null,
        nowIso(),
        nowIso(),
        tenantId,
      );
    return true;
  }

  listDiscoveredCerts(tenantId?: number): DiscoveredCertRow[] {
    const rows = tenantId
      ? this.db
          .prepare(
            `SELECT * FROM discovered_certificates
             WHERE tenant_id = ? ORDER BY expires_at IS NULL, expires_at ASC`,
          )
          .all(tenantId)
      : this.db.prepare("SELECT * FROM discovered_certificates ORDER BY expires_at IS NULL, expires_at ASC").all();
    return rows as unknown as DiscoveredCertRow[];
  }

  deleteDiscoveredCert(id: number, tenantId?: number): void {
    if (tenantId) {
      this.db.prepare("DELETE FROM discovered_certificates WHERE id = ? AND tenant_id = ?").run(id, tenantId);
      return;
    }
    this.db.prepare("DELETE FROM discovered_certificates WHERE id = ?").run(id);
  }

  // ── Private CA + client certificates ──────────────────────────────────
  getCa(): CaRow | undefined {
    return this.db.prepare("SELECT * FROM ca WHERE id = 1").get() as CaRow | undefined;
  }

  createCa(input: { commonName: string; certificate: string; key: string }): CaRow {
    this.db
      .prepare(
        `INSERT OR IGNORE INTO ca (id, common_name, certificate, key, serial, created_at)
         VALUES (1, ?, ?, ?, 0, ?)`,
      )
      .run(input.commonName, input.certificate, input.key, nowIso());
    return this.getCa()!;
  }

  nextCaSerial(): number {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const row = this.db.prepare("SELECT serial FROM ca WHERE id = 1").get() as { serial: number } | undefined;
      if (!row) throw new Error("CA is not initialized");
      const next = row.serial + 1;
      this.db.prepare("UPDATE ca SET serial = ? WHERE id = 1").run(next);
      this.db.exec("COMMIT;");
      return next;
    } catch (err) {
      this.db.exec("ROLLBACK;");
      throw err;
    }
  }

  listClientCertificates(tenantId?: number): ClientCertificateRow[] {
    const rows = tenantId
      ? this.db.prepare("SELECT * FROM client_certificates WHERE tenant_id = ? ORDER BY id DESC").all(tenantId)
      : this.db.prepare("SELECT * FROM client_certificates ORDER BY id DESC").all();
    return rows as unknown as ClientCertificateRow[];
  }

  getClientCertificate(id: number, tenantId?: number): ClientCertificateRow | undefined {
    const row = tenantId
      ? this.db.prepare("SELECT * FROM client_certificates WHERE id = ? AND tenant_id = ?").get(id, tenantId)
      : this.db.prepare("SELECT * FROM client_certificates WHERE id = ?").get(id);
    return row as ClientCertificateRow | undefined;
  }

  findActiveClientCertificate(name: string, tenantId?: number): ClientCertificateRow | undefined {
    const row = tenantId
      ? this.db
          .prepare(`SELECT * FROM client_certificates WHERE name = ? AND status = 'issued' AND tenant_id = ?`)
          .get(name, tenantId)
      : this.db.prepare("SELECT * FROM client_certificates WHERE name = ? AND status = 'issued'").get(name);
    return row as ClientCertificateRow | undefined;
  }

  createClientCertificate(input: {
    name: string;
    email?: string;
    serialHex: string;
    certificate: string;
    key: string;
    fingerprint: string;
    expiresAt: string;
    tenantId?: number;
  }): ClientCertificateRow {
    const result = this.db
      .prepare(
        `INSERT INTO client_certificates
           (name, email, serial_hex, status, certificate, key, fingerprint,
            expires_at, issued_at, tenant_id, created_at)
         VALUES (?, ?, ?, 'issued', ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.name,
        input.email?.toLowerCase() || null,
        input.serialHex,
        input.certificate,
        input.key,
        input.fingerprint,
        input.expiresAt,
        nowIso(),
        input.tenantId ?? DEFAULT_TENANT_ID,
        nowIso(),
      );
    return this.getClientCertificate(Number(result.lastInsertRowid))!;
  }

  revokeClientCertificate(id: number): ClientCertificateRow | undefined {
    this.db.prepare(`UPDATE client_certificates SET status = 'revoked', revoked_at = ? WHERE id = ?`).run(nowIso(), id);
    return this.getClientCertificate(id);
  }

  // ── DNS audits ─────────────────────────────────────────────────────────
  saveDnsAudit(domain: string, score: number, checks: unknown[]): void {
    this.db
      .prepare("INSERT INTO dns_audits (domain, run_at, score, checks_json) VALUES (?, ?, ?, ?)")
      .run(domain.toLowerCase(), nowIso(), Math.round(score), JSON.stringify(checks));
  }

  listDnsAudits(limit = 50): DnsAuditRow[] {
    return this.db.prepare("SELECT * FROM dns_audits ORDER BY id DESC LIMIT ?").all(limit) as unknown as DnsAuditRow[];
  }

  latestDnsAudit(domain: string): DnsAuditRow | undefined {
    return this.db
      .prepare("SELECT * FROM dns_audits WHERE domain = ? ORDER BY id DESC LIMIT 1")
      .get(domain.toLowerCase()) as DnsAuditRow | undefined;
  }

  // ── CRS registry + state ───────────────────────────────────────────────
  getCrsEntry(serverId: string): CrsRegistryRow | undefined {
    return this.db.prepare("SELECT * FROM crs_registry WHERE server_id = ?").get(serverId) as CrsRegistryRow | undefined;
  }
  listCrsRegistry(): CrsRegistryRow[] {
    return this.db.prepare("SELECT * FROM crs_registry ORDER BY updated_at DESC").all() as unknown as CrsRegistryRow[];
  }
  upsertCrsEntry(input: { serverId: string; labDomain: string; apex: string; wildcard: string; role: string; source: string; metadata?: Record<string, unknown> | null }): CrsRegistryRow {
    const existing = this.getCrsEntry(input.serverId);
    const meta = input.metadata ? JSON.stringify(input.metadata) : (existing?.metadata_json ?? null);
    if (existing) {
      this.db.prepare(`UPDATE crs_registry SET lab_domain=?, apex=?, wildcard=?, role=?, source=?, metadata_json=?, last_seen=?, updated_at=? WHERE server_id=?`)
        .run(input.labDomain, input.apex, input.wildcard, input.role, input.source, meta, nowIso(), nowIso(), input.serverId);
    } else {
      this.db.prepare(`INSERT INTO crs_registry (server_id, lab_domain, apex, wildcard, role, source, first_seen, last_seen, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(input.serverId, input.labDomain, input.apex, input.wildcard, input.role, input.source, nowIso(), nowIso(), meta, nowIso(), nowIso());
    }
    return this.getCrsEntry(input.serverId)!;
  }
  deleteCrsEntry(serverId: string): void {
    this.db.prepare("DELETE FROM crs_registry WHERE server_id = ?").run(serverId);
  }
  getCrsState(): CrsStateRow | undefined {
    return this.db.prepare("SELECT * FROM crs_state WHERE id = 1").get() as CrsStateRow | undefined;
  }
  upsertCrsState(input: { desiredRole: string; resolvedRole: string; domain: string; homeUrl: string; masterUrl: string; isAirGapped: number; lastSync: string | null; lastSyncStatus: string | null }): CrsStateRow {
    const existing = this.getCrsState();
    if (existing) {
      this.db.prepare(`UPDATE crs_state SET desired_role=?, resolved_role=?, domain=?, home_url=?, master_url=?, is_air_gapped=?, last_sync=?, last_sync_status=?, updated_at=? WHERE id=1`)
        .run(input.desiredRole, input.resolvedRole, input.domain, input.homeUrl, input.masterUrl, input.isAirGapped, input.lastSync, input.lastSyncStatus, nowIso());
    } else {
      this.db.prepare(`INSERT INTO crs_state (id, desired_role, resolved_role, domain, home_url, master_url, is_air_gapped, last_sync, last_sync_status, created_at, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(input.desiredRole, input.resolvedRole, input.domain, input.homeUrl, input.masterUrl, input.isAirGapped, input.lastSync, input.lastSyncStatus, nowIso(), nowIso());
    }
    return this.getCrsState()!;
  }

  // ── Service API keys (cross-stack) ────────────────────────────────────
  listServiceKeys(): ServiceApiKeyRow[] {
    return this.db.prepare("SELECT * FROM service_api_keys ORDER BY created_at DESC").all() as unknown as ServiceApiKeyRow[];
  }
  getServiceKey(id: number): ServiceApiKeyRow | undefined {
    return this.db.prepare("SELECT * FROM service_api_keys WHERE id = ?").get(id) as ServiceApiKeyRow | undefined;
  }
  getServiceKeyByHash(hash: string): ServiceApiKeyRow | undefined {
    return this.db.prepare("SELECT * FROM service_api_keys WHERE hash = ?").get(hash) as ServiceApiKeyRow | undefined;
  }
  getServiceKeyByPrefix(prefix: string): ServiceApiKeyRow[] {
    return this.db.prepare("SELECT * FROM service_api_keys WHERE prefix = ?").all(prefix) as unknown as ServiceApiKeyRow[];
  }
  createServiceKey(input: { name: string; prefix: string; hash: string; scopes: string[]; tenantId?: number | null }): ServiceApiKeyRow {
    const result = this.db.prepare(`INSERT INTO service_api_keys (name, prefix, hash, scopes_json, tenant_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(input.name, input.prefix, input.hash, JSON.stringify(input.scopes), input.tenantId ?? null, nowIso());
    return this.getServiceKey(Number(result.lastInsertRowid))!;
  }
  touchServiceKey(id: number): void {
    this.db.prepare("UPDATE service_api_keys SET last_used_at = ? WHERE id = ?").run(nowIso(), id);
  }
  revokeServiceKey(id: number): void {
    this.db.prepare("UPDATE service_api_keys SET revoked_at = ? WHERE id = ?").run(nowIso(), id);
  }
  deleteServiceKey(id: number): void {
    this.db.prepare("DELETE FROM service_api_keys WHERE id = ?").run(id);
  }

  // ── Activities ─────────────────────────────────────────────────────────
  addActivity(kind: string, message: string, detail?: string): void {
    this.db.prepare("INSERT INTO activities (ts, kind, message, detail) VALUES (?, ?, ?, ?)").run(nowIso(), kind, message, detail ?? null);
  }

  listActivities(limit = 100): ActivityRow[] {
    return this.db.prepare("SELECT * FROM activities ORDER BY id DESC LIMIT ?").all(limit) as unknown as ActivityRow[];
  }
}

export const db = new Database();
