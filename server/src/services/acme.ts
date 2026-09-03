import { X509Certificate } from "node:crypto";
import * as acme from "acme-client";
import { config } from "../config";
import { db } from "../db";
import * as bind from "./bind";
import { dnsResolveTxt } from "./dns";
import { dns01Record } from "./dns01";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function stripDot(name: string): string {
  return name.replace(/\.$/, "");
}

/** Get-or-create the ACME account key for this directory + email. */
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

async function setChallengeRecord(
  state: DnsChallengeState,
  name: string,
  value: string,
): Promise<void> {
  await bind.setTxtRecord(state.zone, name, value, 60);
  // Poll the authoritative BIND server until the TXT is served.
  await waitForTxt(config.bind.host, name, value);
}

async function removeChallengeRecord(
  state: DnsChallengeState,
  name: string,
  value: string,
): Promise<void> {
  await bind.clearTxtRecord(state.zone, name, value);
}

/** Poll an authoritative nameserver for a TXT record until it appears. */
async function waitForTxt(
  serverIp: string,
  name: string,
  value: string,
  timeoutMs = 60_000,
  intervalMs = 3_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const records = await dnsResolveTxt(serverIp, name);
      if (records.some((r) => r.includes(value))) {
        await sleep(config.propagationBufferSeconds * 1000);
        return;
      }
    } catch {
      // record not present yet — keep polling
    }
    await sleep(intervalMs);
  }
  throw new Error(
    `Timed out waiting for TXT record ${name} to appear on ${serverIp}`,
  );
}

/**
 * Issue (or renew) a certificate for a domain using DNS-01 validation
 * against the configured BIND server (nsupdate + TSIG).
 */
export async function issueCertificate(input: {
  certId: number;
  domain: string;
  wildcard: boolean;
}): Promise<{
  certificate: string;
  key: string;
  expiresAt: string;
}> {
  const { certId, domain, wildcard } = input;

  if (!config.bind.tsigSecret) {
    throw new Error("BIND TSIG key is not configured (see .env)");
  }

  const accountKey = await getAccountKey();
  const client = new acme.Client({
    directoryUrl: config.acmeDirectoryUrl,
    accountKey,
  });

  // Key pair for the certificate itself (kept for renewals). createCsr with a
  // supplied key returns [key, csr].
  const privateKey = await acme.crypto.createPrivateKey();
  const commonName = domain;
  const altNames = wildcard ? [domain, `*.${domain}`] : [domain];
  const [, csr] = await acme.crypto.createCsr(
    { commonName, altNames },
    privateKey,
  );

  // The zone that manages this domain: the longest registered domain suffix,
  // falling back to CERULEAN_ZONE. Challenge TXT records must be written to
  // the zone BIND actually serves — using the issued domain itself (e.g.
  // "monarch.innotel.us") makes nsupdate fail with NOTAUTH.
  const zone = bind.resolveZone(domain, [
    ...db.listDomains().map((d) => d.name),
    config.zone,
  ]);

  const state: DnsChallengeState = {
    zone,
    records: [],
  };

  db.updateCertificateStatus(certId, "issuing");
  db.addActivity(
    "acme-issue",
    `Issuing ${wildcard ? "wildcard " : ""}certificate for ${domain}`,
  );

  try {
    const certificate = await client.auto({
      csr,
      email: config.acmeEmail,
      termsOfServiceAgreed: true,
      challengePriority: ["dns-01"],
      challengeCreateFn: async (
        authz: acme.Authorization,
        _challenge: unknown,
        keyAuthorization: string,
      ) => {
        const record = dns01Record(authz, keyAuthorization);
        const name = stripDot(record.key);
        const value = record.value;
        state.records.push({ name, value });
        await setChallengeRecord(state, name, value);
      },
      challengeRemoveFn: async (
        authz: acme.Authorization,
        _challenge: unknown,
        keyAuthorization: string,
      ) => {
        const record = dns01Record(authz, keyAuthorization);
        await removeChallengeRecord(state, stripDot(record.key), record.value);
      },
    });

    const expiresAt = new X509Certificate(certificate).validTo;
    return { certificate, key: privateKey.toString(), expiresAt };
  } catch (err) {
    // Best-effort cleanup of any challenge records that were set.
    for (const rec of state.records) {
      try {
        await removeChallengeRecord(state, rec.name, rec.value);
      } catch {
        // ignore cleanup errors
      }
    }
    throw err;
  }
}

/** Renew a certificate: re-issue with the same material. */
export async function renewCertificate(certId: number): Promise<void> {
  const cert = db.getCertificate(certId);
  if (!cert) throw new Error("Certificate not found");
  const result = await issueCertificate({
    certId,
    domain: cert.domain,
    wildcard: cert.wildcard === 1,
  });
  db.saveCertificateMaterial(certId, result.certificate, result.key, result.expiresAt);
  db.addActivity("acme-renew", `Renewed certificate for ${cert.domain}`);
}
