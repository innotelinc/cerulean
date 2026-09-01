import { db } from "./db";
import { issueCertificate, renewCertificate } from "./services/acme";
import { npm } from "./services/npm";
import { runDiscovery } from "./services/discovery";
import { auditDomain } from "./services/audit";
import { vault } from "./services/vault";

/**
 * Best-effort: attach an issued/renewed certificate to every NPM proxy host
 * that matches its domains. Failures are logged as activities, never thrown.
 */
async function syncCertToNpmQuietly(certId: number, domain: string): Promise<void> {
  try {
    const result = await npm.syncCertificateToNpm(certId);
    if (result.attached.length) {
      db.addActivity(
        "npm-cert-attach",
        `Attached certificate for ${domain} to NPM proxy host(s): ${result.attached.join(", ")}`,
      );
    }
  } catch (err) {
    db.addActivity(
      "npm-sync-error",
      `Could not sync certificate for ${domain} to nginx proxy manager`,
      err instanceof Error ? err.message : String(err),
    );
  }
}

/** Run a single issue job, persisting status transitions to the DB. */
export async function runIssueJob(certId: number): Promise<void> {
  const cert = db.getCertificate(certId);
  if (!cert) return;
  try {
    const result = await issueCertificate({
      certId,
      domain: cert.domain,
      wildcard: cert.wildcard === 1,
      strategy: cert.strategy,
    });
    db.saveCertificateMaterial(
      certId,
      result.certificate,
      result.key,
      result.expiresAt,
    );
    db.addActivity(
      "acme-issued",
      `Certificate issued for ${cert.domain}${cert.wildcard ? " (+ wildcard)" : ""}`,
      `strategy=${cert.strategy}, expires=${result.expiresAt}`,
    );
    await syncCertToNpmQuietly(certId, cert.domain);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    db.updateCertificateStatus(certId, "error", message);
    db.addActivity("acme-error", `Certificate issuance failed for ${cert.domain}`, message);
  }
}

/**
 * Sweep issued certificates expiring within N days and renew them.
 * Runs sequentially to be kind to Let's Encrypt rate limits.
 */
export async function renewalSweep(days = 30): Promise<void> {
  const expiring = db.listExpiringSoon(days);
  for (const cert of expiring) {
    try {
      await renewCertificate(cert.id);
      await syncCertToNpmQuietly(cert.id, cert.domain);
    } catch (err) {
      db.updateCertificateStatus(
        cert.id,
        "error",
        err instanceof Error ? err.message : String(err),
      );
      db.addActivity(
        "acme-error",
        `Auto-renewal failed for ${cert.domain}`,
        err instanceof Error ? err.message : String(err),
      );
    }
  }
}

/** Scan for externally-managed certificates (NPM + local dirs). */
async function discoverySweep(): Promise<void> {
  try {
    await runDiscovery();
  } catch (err) {
    db.addActivity(
      "discovery-error",
      "Certificate discovery sweep failed",
      err instanceof Error ? err.message : String(err),
    );
  }
}

/** Audit DNS health for every registered domain. */
async function auditSweep(): Promise<void> {
  const domains = db.listDomains();
  for (const domain of domains) {
    try {
      const audit = await auditDomain(domain.name);
      db.saveDnsAudit(audit.domain, audit.score, audit.checks);
      if (audit.score < 60) {
        db.addActivity(
          "dns-audit",
          `DNS audit for ${audit.domain}: ${audit.grade} (${audit.score}/100) — ${audit.checks.filter((c) => c.status !== "ok").map((c) => c.name).join(", ") || "all ok"}`,
        );
      }
    } catch (err) {
      db.addActivity(
        "dns-audit-error",
        `DNS audit failed for ${domain.name}`,
        err instanceof Error ? err.message : String(err),
      );
    }
  }
}

/** Mirror sensitive material into the secret vault (if configured). */
async function vaultSyncSweep(): Promise<void> {
  if (!vault.isEnabled()) return;
  try {
    const { written } = await vault.sync();
    if (written.length) {
      db.addActivity(
        "vault-sync",
        `Synced ${written.length} secret(s) to the vault`,
        written.join(", "),
      );
    }
  } catch (err) {
    db.addActivity(
      "vault-error",
      "Vault sync failed",
      err instanceof Error ? err.message : String(err),
    );
  }
}

export function startScheduler(): void {
  // Renewal sweep: once at startup, then every 12 hours.
  renewalSweep().catch(() => undefined);
  setInterval(() => {
    renewalSweep().catch(() => undefined);
  }, 12 * 60 * 60 * 1000);

  // Certificate discovery: at startup, then daily.
  discoverySweep().catch(() => undefined);
  setInterval(() => {
    discoverySweep().catch(() => undefined);
  }, 24 * 60 * 60 * 1000);

  // DNS health audit: at startup, then every 6 hours.
  auditSweep().catch(() => undefined);
  setInterval(() => {
    auditSweep().catch(() => undefined);
  }, 6 * 60 * 60 * 1000);

  // Vault sync: at startup, then daily.
  vaultSyncSweep().catch(() => undefined);
  setInterval(() => {
    vaultSyncSweep().catch(() => undefined);
  }, 24 * 60 * 60 * 1000);
}
