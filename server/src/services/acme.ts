import { X509Certificate } from "node:crypto";
import * as acme from "acme-client";
import { config } from "../config";
import { db, type DomainRow } from "../db";
import { acmedns } from "./acmedns";
import * as bind from "./bind";
import { dnsResolveTxt } from "./dns";
import { dns01Record } from "./dns01";

export type ChallengeStrategy = "acme-dns" | "bind";

export interface IssueInput {
  certId: number;
  domain: string;
  wildcard: boolean;
  strategy: ChallengeStrategy;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function stripDot(name: string): string {
  return name.replace(/\.$/, "");
}

/**
 * Ensure a domain has acme-dns credentials registered, registering one if
 * needed, and store them on the domain row.
 */
export async function ensureAcmeDnsCreds(
  domainRow: DomainRow,
): Promise<DomainRow> {
  if (
    domainRow.acmedns_username &&
    domainRow.acmedns_subdomain &&
    domainRow.acmedns_password
  ) {
    return domainRow;
  }
  const creds = await acmedns.register(config.acmedns.allowFrom);
  db.setAcmeDnsCreds(domainRow.id, {
    subdomain: creds.subdomain,
    username: creds.username,
    password: creds.password,
    fulldomain: creds.fulldomain,
  });
  db.addActivity(
    "acmedns-register",
    `Registered acme-dns subdomain for ${domainRow.name}`,
    creds.fulldomain,
  );
  return db.getDomain(domainRow.id)!;
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
  strategy: ChallengeStrategy;
  domainRow?: DomainRow;
  records: { name: string; value: string }[];
  cnameEnsured: Set<string>;
}

async function setChallengeRecord(
  state: DnsChallengeState,
  name: string,
  value: string,
): Promise<void> {
  const zone = config.zone;
  if (state.strategy === "acme-dns") {
    if (!state.domainRow) {
      throw new Error("Missing domain row for acme-dns strategy");
    }
    const fulldomain = state.domainRow.acmedns_fulldomain!;
    // One-time CNAME delegation: _acme-challenge.<domain> → <sub>.auth.<domain>
    const owner = stripDot(name);
    if (!state.cnameEnsured.has(owner)) {
      await bind.ensureCname(zone, owner, fulldomain);
      state.cnameEnsured.add(owner);
    }
    await acmedns.updateTxt(
      state.domainRow.acmedns_subdomain!,
      state.domainRow.acmedns_username!,
      state.domainRow.acmedns_password!,
      value,
    );
    // acme-dns serves TXT from its own DB as the authoritative server, so the
    // record is live immediately. A short buffer avoids TOCTOU races at LE.
    await sleep(Math.min(config.propagationBufferSeconds, 5) * 1000);
  } else {
    await bind.setTxtRecord(zone, name, value, 60);
    // Poll the authoritative BIND server until the TXT is served.
    await waitForTxt(config.bind.host, name, value);
  }
}

async function removeChallengeRecord(
  state: DnsChallengeState,
  name: string,
  value: string,
): Promise<void> {
  if (state.strategy === "acme-dns") {
    if (!state.domainRow) return;
    await acmedns.updateTxt(
      state.domainRow.acmedns_subdomain!,
      state.domainRow.acmedns_username!,
      state.domainRow.acmedns_password!,
      "",
    );
  } else {
    await bind.clearTxtRecord(config.zone, name, value);
  }
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
 * Issue (or renew) a certificate for a domain using DNS-01 validation.
 * Returns { certificate, key } where certificate is the full chain PEM.
 */
export async function issueCertificate(input: IssueInput): Promise<{
  certificate: string;
  key: string;
  expiresAt: string;
}> {
  const { certId, domain, wildcard, strategy } = input;

  let domainRow: DomainRow | undefined;
  if (strategy === "acme-dns") {
    const existing = db.getDomainByName(domain);
    if (!existing) {
      throw new Error(
        `Domain "${domain}" is not registered in Cerulean. Add it on the Domains page first.`,
      );
    }
    domainRow = await ensureAcmeDnsCreds(existing);
  } else if (!config.bind.tsigSecret) {
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

  const state: DnsChallengeState = {
    strategy,
    domainRow,
    records: [],
    cnameEnsured: new Set(),
  };

  db.updateCertificateStatus(certId, "issuing");
  db.addActivity(
    "acme-issue",
    `Issuing ${wildcard ? "wildcard " : ""}certificate for ${domain} (${strategy})`,
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

/** Renew a certificate: re-issue with the same material + strategy. */
export async function renewCertificate(certId: number): Promise<void> {
  const cert = db.getCertificate(certId);
  if (!cert) throw new Error("Certificate not found");
  const result = await issueCertificate({
    certId,
    domain: cert.domain,
    wildcard: cert.wildcard === 1,
    strategy: cert.strategy,
  });
  db.saveCertificateMaterial(certId, result.certificate, result.key, result.expiresAt);
  db.addActivity("acme-renew", `Renewed certificate for ${cert.domain}`);
}
