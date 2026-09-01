import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { config } from "./config";

export interface DomainRow {
  id: number;
  name: string;
  strategy: "acme-dns" | "bind";
  acmedns_subdomain: string | null;
  acmedns_username: string | null;
  acmedns_password: string | null;
  acmedns_fulldomain: string | null;
  created_at: string;
}

export interface CertificateRow {
  id: number;
  name: string;
  domain: string;
  wildcard: number;
  strategy: "acme-dns" | "bind";
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
        strategy TEXT NOT NULL DEFAULT 'acme-dns',
        acmedns_subdomain TEXT,
        acmedns_username TEXT,
        acmedns_password TEXT,
        acmedns_fulldomain TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        domain TEXT NOT NULL,
        wildcard INTEGER NOT NULL DEFAULT 0,
        strategy TEXT NOT NULL DEFAULT 'acme-dns',
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

  createDomain(input: {
    name: string;
    strategy: "acme-dns" | "bind";
    acmedns?: {
      subdomain: string;
      username: string;
      password: string;
      fulldomain: string;
    };
  }): DomainRow {
    const result = this.db
      .prepare(
        `INSERT INTO domains (name, strategy, acmedns_subdomain, acmedns_username, acmedns_password, acmedns_fulldomain, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.name.toLowerCase().replace(/\.$/, ""),
        input.strategy,
        input.acmedns?.subdomain ?? null,
        input.acmedns?.username ?? null,
        input.acmedns?.password ?? null,
        input.acmedns?.fulldomain ?? null,
        nowIso(),
      );
    return this.getDomain(Number(result.lastInsertRowid))!;
  }

  setAcmeDnsCreds(
    id: number,
    creds: {
      subdomain: string;
      username: string;
      password: string;
      fulldomain: string;
    },
  ): void {
    this.db
      .prepare(
        `UPDATE domains SET acmedns_subdomain = ?, acmedns_username = ?, acmedns_password = ?, acmedns_fulldomain = ? WHERE id = ?`,
      )
      .run(creds.subdomain, creds.username, creds.password, creds.fulldomain, id);
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
    strategy: "acme-dns" | "bind";
    autoRenew?: boolean;
  }): CertificateRow {
    const result = this.db
      .prepare(
        `INSERT INTO certificates (name, domain, wildcard, strategy, domains_json, auto_renew, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.name,
        input.domain.toLowerCase().replace(/\.$/, ""),
        input.wildcard ? 1 : 0,
        input.strategy,
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
