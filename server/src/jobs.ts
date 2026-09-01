import { db } from "./db";
import { issueCertificate, renewCertificate } from "./services/acme";

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

export function startScheduler(): void {
  // Sweep once at startup, then every 12 hours.
  renewalSweep().catch(() => undefined);
  setInterval(() => {
    renewalSweep().catch(() => undefined);
  }, 12 * 60 * 60 * 1000);
}
