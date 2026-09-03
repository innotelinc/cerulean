import fs from "node:fs";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import { config } from "../config";
import { db, DEFAULT_TENANT_ID } from "../db";
import { npm } from "./npm";
import { firstPem } from "./health";

export interface DiscoveryResult {
  added: number;
  updated: number;
  sources: { npm: number; file: number };
}

interface ParsedCert {
  name: string;
  domains: string[];
  issuer: string | null;
  serial: string | null;
  fingerprint: string | null;
  expiresAt: string | null;
  issuedAt: string | null;
}

function cnFromSubject(subject: string): string {
  const match = subject.match(/CN=([^,]+)/);
  return match ? match[1].trim() : "";
}

function parseSubjectAltName(subjectAltName?: string): string[] {
  if (!subjectAltName) return [];
  return subjectAltName
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.startsWith("DNS:"))
    .map((s) => s.slice(4));
}

/** Parse a PEM certificate chain into its leaf identity. */
export function parseCertPem(pem: string): ParsedCert | undefined {
  try {
    const leaf = new X509Certificate(firstPem(pem));
    const legacy = leaf.toLegacyObject() as { subjectAltName?: string };
    const altNames = parseSubjectAltName(legacy.subjectAltName);
    const subjectCn = cnFromSubject(leaf.subject);
    const domains = altNames.length ? altNames : subjectCn ? [subjectCn] : [];
    return {
      name: subjectCn || domains[0] || "unknown",
      domains,
      issuer: leaf.issuer,
      serial: leaf.serialNumber,
      fingerprint: leaf.fingerprint256,
      expiresAt: leaf.validTo,
      issuedAt: leaf.validFrom,
    };
  } catch {
    return undefined;
  }
}

const CERT_EXTS = [".pem", ".crt", ".cert"];

function* walkFiles(dir: string): Generator<string> {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkFiles(full);
    } else if (entry.isFile() && CERT_EXTS.some((e) => entry.name.toLowerCase().endsWith(e))) {
      yield full;
    }
  }
}

/** Scan nginx proxy manager for certificates (including ones not issued here). */
async function scanNpm(
  tenantId: number,
): Promise<{ found: number; added: number }> {
  if (!config.npm.apiUrl || !config.npm.email || !config.npm.password) {
    return { found: 0, added: 0 };
  }
  const certs = await npm.listCertificates();
  let found = 0;
  let added = 0;
  for (const c of certs) {
    try {
      let certificate: string | null = null;
      let key: string | null = null;
      let parsed: ParsedCert | undefined;
      try {
        const full = await npm.getCertificate(c.id);
        const meta = (full as { meta?: { certificate?: string; certificate_key?: string } }).meta;
        if (meta?.certificate) {
          certificate = meta.certificate;
          key = meta.certificate_key ?? null;
          parsed = parseCertPem(certificate);
        }
      } catch {
        // NPM may not expose material for LetsEncrypt-managed certs — use
        // the list metadata instead.
      }
      const domains = parsed?.domains.length
        ? parsed.domains
        : (c.domain_names || []);
      if (db.upsertDiscoveredCert({
        source: "npm",
        sourceId: String(c.id),
        name: parsed?.name || c.nice_name || (domains[0] ?? `npm-cert-${c.id}`),
        domains,
        issuer: parsed?.issuer ?? null,
        serial: parsed?.serial ?? null,
        fingerprint: parsed?.fingerprint ?? null,
        certificate,
        key,
        expiresAt: parsed?.expiresAt ?? c.expires_on,
        issuedAt: parsed?.issuedAt ?? null,
      }, tenantId)) {
        added += 1;
      }
      found += 1;
    } catch {
      // Skip certificates that can't be read — the rest still get scanned.
    }
  }
  return { found, added };
}

/** Scan local directories for PEM certificates (e.g. /etc/ssl/certs). */
async function scanFiles(
  tenantId: number,
): Promise<{ found: number; added: number }> {
  let found = 0;
  let added = 0;
  for (const dir of config.discovery.dirs) {
    if (!fs.existsSync(dir)) continue;
    for (const file of walkFiles(dir)) {
      try {
        const pem = fs.readFileSync(file, "utf8");
        const parsed = parseCertPem(pem);
        if (!parsed) continue;
        const base = file.replace(/\.(pem|crt|cert)$/i, "");
        const keyFile = [".key", ".pem", ".key.pem"]
          .map((ext) => `${base}${ext}`)
          .find((p) => fs.existsSync(p) && p !== file);
        const key = keyFile ? fs.readFileSync(keyFile, "utf8") : null;
        if (db.upsertDiscoveredCert({
          source: "file",
          sourceId: file,
          name: parsed.name,
          domains: parsed.domains,
          issuer: parsed.issuer,
          serial: parsed.serial,
          fingerprint: parsed.fingerprint,
          certificate: pem,
          key,
          expiresAt: parsed.expiresAt,
          issuedAt: parsed.issuedAt,
        }, tenantId)) {
          added += 1;
        }
        found += 1;
      } catch {
        // unreadable / unparseable file — skip
      }
    }
  }
  return { found, added };
}

/**
 * Run a discovery sweep across all sources. Idempotent — existing entries are
 * refreshed in place (last_seen + material) and never duplicated.
 */
export async function runDiscovery(
  tenantId: number = DEFAULT_TENANT_ID,
): Promise<DiscoveryResult> {
  let npmFound = 0;
  let npmAdded = 0;
  let fileFound = 0;
  let fileAdded = 0;

  try {
    ({ found: npmFound, added: npmAdded } = await scanNpm(tenantId));
  } catch (err) {
    db.addActivity(
      "discovery-error",
      "Certificate discovery from nginx proxy manager failed",
      err instanceof Error ? err.message : String(err),
    );
  }
  try {
    ({ found: fileFound, added: fileAdded } = await scanFiles(tenantId));
  } catch (err) {
    db.addActivity(
      "discovery-error",
      "Certificate discovery from local directories failed",
      err instanceof Error ? err.message : String(err),
    );
  }

  db.addActivity(
    "discovery",
    `Certificate discovery complete: ${npmFound} from nginx proxy manager, ${fileFound} from local files`,
  );
  return {
    added: npmAdded + fileAdded,
    updated: npmFound + fileFound - (npmAdded + fileAdded),
    sources: { npm: npmFound, file: fileFound },
  };
}
