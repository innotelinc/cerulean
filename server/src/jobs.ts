import { db } from "./db";
import { issueCertificate, renewCertificate } from "./services/acme";
import { npm } from "./services/npm";
import { runDiscovery } from "./services/discovery";
import { auditDomain } from "./services/audit";
import { vault } from "./services/vault";

async function syncCertToNpmQuietly(certId: number, domain: string): Promise<void> {
  try {
    const result = await npm.syncCertificateToNpm(certId);
    if (result.attached.length) {
      db.addActivity("npm-cert-attach", `Attached certificate for ${domain} to NPM proxy host(s): ${result.attached.join(", ")}`);
    }
  } catch (err) {
    db.addActivity("npm-sync-error", `Could not sync certificate for ${domain} to nginx proxy manager`, err instanceof Error ? err.message : String(err));
  }
}

export async function runIssueJob(certId: number): Promise<void> {
  const cert = db.getCertificate(certId);
  if (!cert) return;
  try {
    const result = await issueCertificate({ certId, domain: cert.domain, wildcard: cert.wildcard === 1 });
    db.saveCertificateMaterial(certId, result.certificate, result.key, result.expiresAt, "acme");
    db.addActivity("acme-issued", `Certificate issued for ${cert.domain}${cert.wildcard ? " (+ wildcard)" : ""} via Technitium DNS-01`, `expires=${result.expiresAt}`);
    await syncCertToNpmQuietly(certId, cert.domain);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    db.updateCertificateStatus(certId, "error", message);
    db.addActivity("acme-error", `Certificate issuance failed for ${cert.domain}`, message);
  }
}

export async function renewalSweep(days = 30): Promise<void> {
  const expiring = db.listExpiringSoon(days);
  for (const cert of expiring) {
    // 30-day PKI wildcards renew via PKI rotation, not ACME (offline-safe)
    if (cert.source === "pki") {
      try {
        const { ensureWildcardPki } = await import("./services/serverIdentity");
        await ensureWildcardPki();
        await syncCertToNpmQuietly(cert.id, cert.domain);
      } catch (err) {
        db.addActivity("pki-renew-error", `PKI wildcard renewal failed for ${cert.domain}`, err instanceof Error ? err.message : String(err));
      }
      continue;
    }
    try {
      await renewCertificate(cert.id);
      await syncCertToNpmQuietly(cert.id, cert.domain);
    } catch (err) {
      db.updateCertificateStatus(cert.id, "error", err instanceof Error ? err.message : String(err));
      db.addActivity("acme-error", `Auto-renewal failed for ${cert.domain}`, err instanceof Error ? err.message : String(err));
    }
  }
}

async function discoverySweep(): Promise<void> {
  try { await runDiscovery(); } catch (err) {
    db.addActivity("discovery-error", "Certificate discovery sweep failed", err instanceof Error ? err.message : String(err));
  }
}

async function auditSweep(): Promise<void> {
  const domains = db.listDomains();
  for (const domain of domains) {
    try {
      const audit = await auditDomain(domain.name);
      db.saveDnsAudit(audit.domain, audit.score, audit.checks);
      if (audit.score < 60) db.addActivity("dns-audit", `DNS audit for ${audit.domain}: ${audit.grade} (${audit.score}/100) — ${audit.checks.filter((c) => c.status !== "ok").map((c) => c.name).join(", ") || "all ok"}`);
    } catch (err) {
      db.addActivity("dns-audit-error", `DNS audit failed for ${domain.name}`, err instanceof Error ? err.message : String(err));
    }
  }
}

async function vaultSyncSweep(): Promise<void> {
  if (!vault.isEnabled()) return;
  try {
    const { written } = await vault.sync();
    if (written.length) db.addActivity("vault-sync", `Synced ${written.length} secret(s) to the vault`, written.join(", "));
  } catch (err) {
    db.addActivity("vault-error", "Vault sync failed", err instanceof Error ? err.message : String(err));
  }
}

async function orchestratorSweep(): Promise<void> {
  try {
    const { ensureIdentity, registerServer, ensureWildcardPki, tryUpgradeWildcardToAcme } = await import("./services/serverIdentity");
    ensureIdentity();
    // Best-effort central registration (offline-tolerant)
    await registerServer().catch(() => undefined);
    // Ensure a 30-day wildcard exists via PKI first (offline), then try ACME upgrade
    await ensureWildcardPki().catch(() => undefined);
    await tryUpgradeWildcardToAcme().catch(() => undefined);
  } catch (err) {
    db.addActivity("orchestrator-error", "Orchestrator sweep failed", err instanceof Error ? err.message : String(err));
  }
}

export function startScheduler(): void {
  // One-shot orchestrator bootstrap (registration + PKI wildcard)
  orchestratorSweep().catch(() => undefined);

  renewalSweep().catch(() => undefined);
  setInterval(() => { renewalSweep().catch(() => undefined); }, 12 * 60 * 60 * 1000);

  // Wildcard rotation check every 6 hours (covers the 30-day short cert)
  setInterval(() => { orchestratorSweep().catch(() => undefined); }, 6 * 60 * 60 * 1000);

  discoverySweep().catch(() => undefined);
  setInterval(() => { discoverySweep().catch(() => undefined); }, 24 * 60 * 60 * 1000);

  auditSweep().catch(() => undefined);
  setInterval(() => { auditSweep().catch(() => undefined); }, 6 * 60 * 60 * 1000);

  vaultSyncSweep().catch(() => undefined);
  setInterval(() => { vaultSyncSweep().catch(() => undefined); }, 24 * 60 * 60 * 1000);
}
