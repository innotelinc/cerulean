import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { config } from "./config";

export interface DomainRow {
  id: number;
  name: string;
  strategy: "bind";
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
      CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        strategy TEXT NOT NULL DEFAULT 'bind',
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
    `);
  }

  // ── Domains ────────────────────────────────────────────────────────────
  listDomains(): DomainRow[] {
    return this.db
      .prepare("SELECT * FROM domains ORDER BY name")
      .all() as unknown as DomainRow[];
  }

  getDomain(id: number): DomainRow | undefined {
    return this.db
      .prepare("SELECT * FROM domains WHERE id = ?")
      .get(id) as DomainRow | undefined;
  }

  getDomainByName(name: string): DomainRow | undefined {
    return this.db
      .prepare("SELECT * FROM domains WHERE name = ?")
      .get(name) as DomainRow | undefined;
  }

  createDomain(input: { name: string }): DomainRow {
    const result = this.db
      .prepare(
        `INSERT INTO domains (name, strategy, created_at)
         VALUES (?, 'bind', ?)`,
      )
      .run(input.name.toLowerCase().replace(/\.$/, ""), nowIso());
    return this.getDomain(Number(result.lastInsertRowid))!;
  }

  deleteDomain(id: number): void {
    this.db.prepare("DELETE FROM domains WHERE id = ?").run(id);
  }

  // ── Certificates ───────────────────────────────────────────────────────
  listCertificates(): CertificateRow[] {
    return this.db
      .prepare("SELECT * FROM certificates ORDER BY id DESC")
      .all() as unknown as CertificateRow[];
  }

  getCertificate(id: number): CertificateRow | undefined {
    return this.db
      .prepare("SELECT * FROM certificates WHERE id = ?")
      .get(id) as CertificateRow | undefined;
  }

  createCertificate(input: {
    name: string;
    domain: string;
    wildcard: boolean;
    autoRenew?: boolean;
  }): CertificateRow {
    const result = this.db
      .prepare(
        `INSERT INTO certificates (name, domain, wildcard, strategy, domains_json, auto_renew, created_at)
         VALUES (?, ?, ?, 'bind', ?, ?, ?)`,
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

  deleteCertificate(id: number): void {
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
  upsertDiscoveredCert(input: {
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
  }): boolean {
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
             certificate = ?, key = ?, expires_at = ?, issued_at = ?, last_seen = ?
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
          existing.id,
        );
      return false;
    }
    this.db
      .prepare(
        `INSERT INTO discovered_certificates
           (source, source_id, name, domains_json, issuer, serial, fingerprint,
            certificate, key, expires_at, issued_at, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
      );
    return true;
  }

  listDiscoveredCerts(): DiscoveredCertRow[] {
    return this.db
      .prepare("SELECT * FROM discovered_certificates ORDER BY expires_at IS NULL, expires_at ASC")
      .all() as unknown as DiscoveredCertRow[];
  }

  deleteDiscoveredCert(id: number): void {
    this.db.prepare("DELETE FROM discovered_certificates WHERE id = ?").run(id);
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
