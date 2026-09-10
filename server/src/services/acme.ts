import { X509Certificate } from "node:crypto";
import * as acme from "acme-client";
import { config } from "../config";
import { db } from "../db";
import * as technitium from "./technitium";
import { dnsResolveTxt } from "./dns";
import { dns01Record } from "./dns01";
import { providerConnectionForTenant } from "./providers";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function stripDot(name: string): string {
  return name.replace(/\.$/, "");
}

async function getAccountKey(): Promise<string> {
  const existing = db.getAcmeAccount(config.acmeDirectoryUrl, config.acmeEmail);
  if (existing) return existing.key;
  const key = await acme.crypto.createPrivateKey();
  db.saveAcmeAccount(config.acmeDirectoryUrl, config.acmeEmail, key.toString());
  return key.toString();
}

interface DnsChallengeState {
  zone: string;
  records: { name: string; value: string }[];
}

/**
 * Resolve the authoritative nameserver to poll for TXT propagation.
 * Prefer TECHNITIUM_URL host (Docker service name → resolved to bridge IP)
 * and fall back to 127.0.0.1:5353 only on the host. Inside Cerulean,
 * cerulean-technitium resolves via Docker DNS to 172.22.0.2:53.
 */
function technitiumNameserver(): string {
  // If TECHNITIUM_URL host resolves, dns.ts will resolve it — keep original
  // hostname and let dnsResolveTxt do the lookup. Returning the hostname is
  // intentional so Docker DNS (127.0.0.11) can return the bridge IP.
  try {
    const u = new URL(config.technitium.url);
    const host = u.hostname;
    if (host) return host;
  } catch { /* fallback */ }
  return "127.0.0.1";
}

async function setChallengeRecord(
  state: DnsChallengeState,
  name: string,
  value: string,
  conn?: Record<string, unknown>,
): Promise<void> {
  await technitium.setTxtRecord(state.zone, name, value, 60, conn as never);
  await waitForTxt(technitiumNameserver(), name, value);
}

async function removeChallengeRecord(
  state: DnsChallengeState,
  name: string,
  value: string,
  conn?: Record<string, unknown>,
): Promise<void> {
  await technitium.clearTxtRecord(state.zone, name, value, conn as never);
}

async function waitForTxt(
  serverIp: string,
  name: string,
  value: string,
  timeoutMs = 60_000,
  intervalMs = 2_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const records = await dnsResolveTxt(serverIp, name);
      if (records.some((r) => r.includes(value))) {
        await sleep(config.propagationBufferSeconds * 1000);
        return;
      }
    } catch { /* not yet */ }
    await sleep(intervalMs);
  }
  throw new Error(`Timed out waiting for TXT record ${name} to appear on ${serverIp} (is Technitium DNS reachable from Cerulean? check TECHNITIUM_URL=${config.technitium.url})`);
}

/**
 * Issue (or renew) a certificate for a domain using DNS-01 via Technitium.
 * RFC2136/nsupdate has been fully replaced by Technitium's HTTP API.
 */
export async function issueCertificate(input: {
  certId: number;
  domain: string;
  wildcard: boolean;
}): Promise<{ certificate: string; key: string; expiresAt: string }> {
  const { certId, domain, wildcard } = input;

  const certRow = db.getCertificate(certId);
  const conn =
    (certRow ? (providerConnectionForTenant(certRow.tenant_id) as unknown as Record<string, unknown>) : null) ?? undefined;

  // Probe Technitium reachability early (offline-friendly error)
  const probe = await technitium.testConnection(conn as never);
  if (!probe.ok) {
    throw new Error(
      `Technitium DNS is unreachable: ${probe.detail} — check TECHNITIUM_URL / TECHNITIUM_TOKEN in .env (offline mode: the PKI wildcard is still served)`,
    );
  }

  const accountKey = await getAccountKey();
  const client = new acme.Client({ directoryUrl: config.acmeDirectoryUrl, accountKey });
  const privateKey = await acme.crypto.createPrivateKey();
  const commonName = domain;
  const altNames = wildcard ? [domain, `*.${domain}`] : [domain];
  const [, csr] = await acme.crypto.createCsr({ commonName, altNames }, privateKey);

  const zone = technitium.resolveZone(domain, [...db.listDomains().map((d) => d.name), config.zone]);
  const state: DnsChallengeState = { zone, records: [] };

  db.updateCertificateStatus(certId, "issuing");
  db.addActivity("acme-issue", `Issuing ${wildcard ? "wildcard " : ""}certificate for ${domain} via Technitium DNS-01`);

  try {
    const certificate = await client.auto({
      csr,
      email: config.acmeEmail,
      termsOfServiceAgreed: true,
      challengePriority: ["dns-01"],
      challengeCreateFn: async (authz: acme.Authorization, _challenge: unknown, keyAuthorization: string) => {
        const record = dns01Record(authz, keyAuthorization);
        const name = stripDot(record.key);
        const value = record.value;
        state.records.push({ name, value });
        await setChallengeRecord(state, name, value, conn ?? undefined);
      },
      challengeRemoveFn: async (authz: acme.Authorization, _challenge: unknown, keyAuthorization: string) => {
        const record = dns01Record(authz, keyAuthorization);
        await removeChallengeRecord(state, stripDot(record.key), record.value, conn ?? undefined);
      },
    });
    const expiresAt = new X509Certificate(certificate).validTo;
    return { certificate, key: privateKey.toString(), expiresAt };
  } catch (err) {
    for (const rec of state.records) {
      try { await removeChallengeRecord(state, rec.name, rec.value, conn ?? undefined); } catch { /* ignore */ }
    }
    throw err;
  }
}

export async function renewCertificate(certId: number): Promise<void> {
  const cert = db.getCertificate(certId);
  if (!cert) throw new Error("Certificate not found");
  const result = await issueCertificate({ certId, domain: cert.domain, wildcard: cert.wildcard === 1 });
  db.saveCertificateMaterial(certId, result.certificate, result.key, result.expiresAt, "acme");
  db.addActivity("acme-renew", `Renewed certificate for ${cert.domain}`);
}
