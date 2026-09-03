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

/** Slug of the built-in tenant that pre-tenant data belongs to. */
export const DEFAULT_TENANT_ID = 1;

export interface DomainRow {
  id: number;
  name: string;
  strategy: "bind";
  tenant_id: number;
  created_at: string;
}

export interface CertificateRow {
  id: number;
  name: string;
  domain: string;
  wildcard: number;
  strategy: "bind";
  status: string; // issuing | issued | error
  error: string | null;
  domains_json: string;
  certificate: string | null;
  key: string | null;
  expires_at: string | null;
  issued_at: string | null;
  auto_renew: number;
  tenant_id: number;
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
  key: string; // client private key (PKCS#8 PEM; "" when CSR-enrolled — the device holds the key)
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
      -- Organizations/tenants (Authentik group slug ↔ tenant slug). Rows in
      -- the tables below carry tenant_id; the default tenant (id 1) owns all
      -- pre-tenant data and is the home of local/admin sessions.
      CREATE TABLE IF NOT EXISTS tenants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        strategy TEXT NOT NULL DEFAULT 'bind',
        tenant_id INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        domain TEXT NOT NULL,
        wildcard INTEGER NOT NULL DEFAULT 0,
        strategy TEXT NOT NULL DEFAULT 'bind',
        status TEXT NOT NULL DEFAULT 'issuing',
        error TEXT,
        domains_json TEXT NOT NULL DEFAULT '[]',
        certificate TEXT,
        key TEXT,
        expires_at TEXT,
        issued_at TEXT,
        auto_renew INTEGER NOT NULL DEFAULT 1,
        tenant_id INTEGER NOT NULL DEFAULT 1,
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

      -- Internal private CA (singleton row) issuing TLS client certificates.
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
    `);

    // Seed the default tenant (owns all pre-tenant data + local sessions).
    this.db
      .prepare(
        `INSERT OR IGNORE INTO tenants (id, slug, name, created_at)
         VALUES (1, 'default', 'Default', ?)`,
      )
      .run(nowIso());

    // Existing databases predate tenants: add tenant_id to every owned table
    // and back-fill it to the default tenant, then index the column.
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
    // Uniqueness of active certificate names is now per tenant (each tenant
    // has its own device inventory). Replace the old global partial index.
    this.db.exec(`
      DROP INDEX IF EXISTS idx_client_certs_active_name;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_client_certs_active_name
        ON client_certificates (tenant_id, name) WHERE status = 'issued';
    `);
  }

  /** Add a column to an existing table when it is missing (idempotent). */
  private ensureColumn(table: string, column: string, ddl: string): void {
    const cols = this.db
      .prepare(`PRAGMA table_info(${table})`)
      .all() as { name: string }[];
    if (!cols.some((c) => c.name === column)) {
      this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl};`);
    }
  }

  // ── Tenants ────────────────────────────────────────────────────────────
  listTenants(): TenantRow[] {
    return this.db
      .prepare("SELECT * FROM tenants ORDER BY id")
      .all() as unknown as TenantRow[];
  }

  getTenant(id: number): TenantRow | undefined {
    return this.db
      .prepare("SELECT * FROM tenants WHERE id = ?")
      .get(id) as TenantRow | undefined;
  }

  getTenantBySlug(slug: string): TenantRow | undefined {
    return this.db
      .prepare("SELECT * FROM tenants WHERE slug = ?")
      .get(slug) as TenantRow | undefined;
  }

  createTenant(input: { slug: string; name: string }): TenantRow {
    const result = this.db
      .prepare(
        `INSERT INTO tenants (slug, name, created_at) VALUES (?, ?, ?)`,
      )
      .run(input.slug, input.name, nowIso());
    return this.getTenant(Number(result.lastInsertRowid))!;
  }

  // ── Domains ────────────────────────────────────────────────────────────
  listDomains(tenantId?: number): DomainRow[] {
    const rows = tenantId
      ? this.db
          .prepare("SELECT * FROM domains WHERE tenant_id = ? ORDER BY name")
          .all(tenantId)
      : this.db.prepare("SELECT * FROM domains ORDER BY name").all();
    return rows as unknown as DomainRow[];
  }

  getDomain(id: number, tenantId?: number): DomainRow | undefined {
    const row = tenantId
      ? this.db
          .prepare("SELECT * FROM domains WHERE id = ? AND tenant_id = ?")
          .get(id, tenantId)
      : this.db.prepare("SELECT * FROM domains WHERE id = ?").get(id);
    return row as DomainRow | undefined;
  }

  getDomainByName(name: string, tenantId?: number): DomainRow | undefined {
    const row = tenantId
      ? this.db
          .prepare(
            "SELECT * FROM domains WHERE name = ? AND tenant_id = ?",
          )
          .get(name.toLowerCase().replace(/\.$/, ""), tenantId)
      : this.db
          .prepare("SELECT * FROM domains WHERE name = ?")
          .get(name.toLowerCase().replace(/\.$/, ""));
    return row as DomainRow | undefined;
  }

  createDomain(input: { name: string; tenantId?: number }): DomainRow {
    const result = this.db
      .prepare(
        `INSERT INTO domains (name, strategy, tenant_id, created_at)
         VALUES (?, 'bind', ?, ?)`,
      )
      .run(
        input.name.toLowerCase().replace(/\.$/, ""),
        input.tenantId ?? DEFAULT_TENANT_ID,
        nowIso(),
      );
    return this.getDomain(Number(result.lastInsertRowid))!;
  }

  deleteDomain(id: number, tenantId?: number): void {
    if (tenantId) {
      this.db
        .prepare("DELETE FROM domains WHERE id = ? AND tenant_id = ?")
        .run(id, tenantId);
      return;
    }
    this.db.prepare("DELETE FROM domains WHERE id = ?").run(id);
  }

  // ── Certificates ───────────────────────────────────────────────────────
  listCertificates(tenantId?: number): CertificateRow[] {
    const rows = tenantId
      ? this.db
          .prepare(
            "SELECT * FROM certificates WHERE tenant_id = ? ORDER BY id DESC",
          )
          .all(tenantId)
      : this.db.prepare("SELECT * FROM certificates ORDER BY id DESC").all();
    return rows as unknown as CertificateRow[];
  }

  getCertificate(id: number, tenantId?: number): CertificateRow | undefined {
    const row = tenantId
      ? this.db
          .prepare(
            "SELECT * FROM certificates WHERE id = ? AND tenant_id = ?",
          )
          .get(id, tenantId)
      : this.db.prepare("SELECT * FROM certificates WHERE id = ?").get(id);
    return row as CertificateRow | undefined;
  }

  createCertificate(input: {
    name: string;
    domain: string;
    wildcard: boolean;
    autoRenew?: boolean;
    tenantId?: number;
  }): CertificateRow {
    const result = this.db
      .prepare(
        `INSERT INTO certificates (name, domain, wildcard, strategy, domains_json, auto_renew, tenant_id, created_at)
         VALUES (?, ?, ?, 'bind', ?, ?, ?, ?)`,
      )
      .run(
        input.name,
        input.domain.toLowerCase().replace(/\.$/, ""),
        input.wildcard ? 1 : 0,
        JSON.stringify(
          input.wildcard
            ? [input.domain, `*.${input.domain}`]
            : [input.domain],
        ),
        input.autoRenew === false ? 0 : 1,
        input.tenantId ?? DEFAULT_TENANT_ID,
        nowIso(),
      );
    return this.getCertificate(Number(result.lastInsertRowid))!;
  }

  updateCertificateStatus(id: number, status: string, error?: string): void {
    this.db
      .prepare("UPDATE certificates SET status = ?, error = ? WHERE id = ?")
      .run(status, error ?? null, id);
  }

  saveCertificateMaterial(
    id: number,
    certificate: string,
    key: string,
    expiresAt: string,
  ): void {
    this.db
      .prepare(
        `UPDATE certificates SET certificate = ?, key = ?, expires_at = ?, issued_at = ?, status = 'issued', error = NULL WHERE id = ?`,
      )
      .run(certificate, key, expiresAt, nowIso(), id);
  }

  deleteCertificate(id: number, tenantId?: number): void {
    if (tenantId) {
      this.db
        .prepare("DELETE FROM certificates WHERE id = ? AND tenant_id = ?")
        .run(id, tenantId);
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
      .prepare(
        "SELECT * FROM acme_accounts WHERE directory_url = ? AND email = ?",
      )
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
    return this.db
      .prepare("SELECT * FROM acme_accounts")
      .all() as unknown as AcmeAccountRow[];
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
      .prepare(
        "SELECT id FROM discovered_certificates WHERE source = ? AND source_id = ?",
      )
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
      : this.db
          .prepare(
            "SELECT * FROM discovered_certificates ORDER BY expires_at IS NULL, expires_at ASC",
          )
          .all();
    return rows as unknown as DiscoveredCertRow[];
  }

  deleteDiscoveredCert(id: number, tenantId?: number): void {
    if (tenantId) {
      this.db
        .prepare(
          "DELETE FROM discovered_certificates WHERE id = ? AND tenant_id = ?",
        )
        .run(id, tenantId);
      return;
    }
    this.db.prepare("DELETE FROM discovered_certificates WHERE id = ?").run(id);
  }

  // ── Private CA + client certificates ──────────────────────────────────
  getCa(): CaRow | undefined {
    return this.db.prepare("SELECT * FROM ca WHERE id = 1").get() as
      | CaRow
      | undefined;
  }

  /** Insert the root CA singleton (no-op if it already exists). */
  createCa(input: {
    commonName: string;
    certificate: string;
    key: string;
  }): CaRow {
    this.db
      .prepare(
        `INSERT OR IGNORE INTO ca (id, common_name, certificate, key, serial, created_at)
         VALUES (1, ?, ?, ?, 0, ?)`,
      )
      .run(input.commonName, input.certificate, input.key, nowIso());
    return this.getCa()!;
  }

  /** Atomically claim the next serial number for a certificate issuance. */
  nextCaSerial(): number {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const row = this.db
        .prepare("SELECT serial FROM ca WHERE id = 1")
        .get() as { serial: number } | undefined;
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
      ? this.db
          .prepare(
            "SELECT * FROM client_certificates WHERE tenant_id = ? ORDER BY id DESC",
          )
          .all(tenantId)
      : this.db
          .prepare("SELECT * FROM client_certificates ORDER BY id DESC")
          .all();
    return rows as unknown as ClientCertificateRow[];
  }

  getClientCertificate(
    id: number,
    tenantId?: number,
  ): ClientCertificateRow | undefined {
    const row = tenantId
      ? this.db
          .prepare(
            "SELECT * FROM client_certificates WHERE id = ? AND tenant_id = ?",
          )
          .get(id, tenantId)
      : this.db.prepare("SELECT * FROM client_certificates WHERE id = ?").get(id);
    return row as ClientCertificateRow | undefined;
  }

  /** Active (non-revoked) certificate whose CN/name matches `name`. */
  findActiveClientCertificate(
    name: string,
    tenantId?: number,
  ): ClientCertificateRow | undefined {
    const row = tenantId
      ? this.db
          .prepare(
            `SELECT * FROM client_certificates
             WHERE name = ? AND status = 'issued' AND tenant_id = ?`,
          )
          .get(name, tenantId)
      : this.db
          .prepare(
            "SELECT * FROM client_certificates WHERE name = ? AND status = 'issued'",
          )
          .get(name);
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
        nowIso(), // issued_at
        input.tenantId ?? DEFAULT_TENANT_ID,
        nowIso(), // created_at
      );
    return this.getClientCertificate(Number(result.lastInsertRowid))!;
  }

  revokeClientCertificate(id: number): ClientCertificateRow | undefined {
    this.db
      .prepare(
        `UPDATE client_certificates SET status = 'revoked', revoked_at = ? WHERE id = ?`,
      )
      .run(nowIso(), id);
    return this.getClientCertificate(id);
  }

  // ── DNS audits ─────────────────────────────────────────────────────────
  saveDnsAudit(domain: string, score: number, checks: unknown[]): void {
    this.db
      .prepare("INSERT INTO dns_audits (domain, run_at, score, checks_json) VALUES (?, ?, ?, ?)")
      .run(domain.toLowerCase(), nowIso(), Math.round(score), JSON.stringify(checks));
  }

  listDnsAudits(limit = 50): DnsAuditRow[] {
    return this.db
      .prepare("SELECT * FROM dns_audits ORDER BY id DESC LIMIT ?")
      .all(limit) as unknown as DnsAuditRow[];
  }

  latestDnsAudit(domain: string): DnsAuditRow | undefined {
    return this.db
      .prepare(
        "SELECT * FROM dns_audits WHERE domain = ? ORDER BY id DESC LIMIT 1",
      )
      .get(domain.toLowerCase()) as DnsAuditRow | undefined;
  }

  // ── Activities ─────────────────────────────────────────────────────────
  addActivity(kind: string, message: string, detail?: string): void {
    this.db
      .prepare("INSERT INTO activities (ts, kind, message, detail) VALUES (?, ?, ?, ?)")
      .run(nowIso(), kind, message, detail ?? null);
  }

  listActivities(limit = 100): ActivityRow[] {
    return this.db
      .prepare("SELECT * FROM activities ORDER BY id DESC LIMIT ?")
      .all(limit) as unknown as ActivityRow[];
  }
}

export const db = new Database();
