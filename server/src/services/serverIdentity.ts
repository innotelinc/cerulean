/**
 * Master-orchestrator server identity.
 *
 * On every install <serverId> is registered (if SERVER_REGISTER_URL is set)
 * and this host deterministically serves:
 *   - apex:    <serverId>.lab.innotel.us
 *   - wildcard: *.<serverId>.lab.innotel.us
 *
 * Default zone when the operator provides no domain is
 *   <serverId>.lab.innotel.us (and the wildcard cert for that scope).
 *
 * Offline-first: if the platform is running, it can DHCP/DNS/block/certs
 * without internet. 30-day wildcard is dual-issued:
 *   1. Immediately via internal PKI (offline, self-sufficient), stored as a
 *      certificate row with source="pki" and pushed to NPM.
 *   2. Best-effort ACME DNS-01 via Technitium when online; on success it
 *      replaces the PKI material (source="acme").
 */

import { config, sanitizeServerId, generateServerId } from "../config";
import { db } from "../db";
import * as pki from "./pki";

export interface ServerIdentity {
  serverId: string;
  labDomain: string;
  apex: string; // <id>.lab.innotel.us
  wildcard: string; // *.<id>.lab.innotel.us
  registered: boolean;
  wildcardCertId: number | null;
}

export function currentIdentity(): ServerIdentity {
  const row = db.getServerIdentity();
  if (!row) {
    const apex = `${config.server.id}.${config.server.labDomain}`;
    return { serverId: config.server.id, labDomain: config.server.labDomain, apex, wildcard: `*.${apex}`, registered: false, wildcardCertId: null };
  }
  return {
    serverId: row.server_id,
    labDomain: row.lab_domain,
    apex: row.wildcard_domain,
    wildcard: row.base_domain,
    registered: row.registered === 1,
    wildcardCertId: row.wildcard_cert_id,
  };
}

/** Parse a certificate's SAN list stored as JSON; never throws. */
function parseDomains(raw: string | null | undefined): string[] {
  try {
    const parsed = JSON.parse(raw || "[]") as unknown;
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

export function ensureIdentity(): ServerIdentity {
  const row = db.getServerIdentity();
  let sid = row?.server_id || config.server.id;
  let lab = row?.lab_domain || config.server.labDomain;
  const clean = sanitizeServerId(sid);
  if (!clean) {
    sid = generateServerId();
    db.upsertServerIdentity({ serverId: sid, labDomain: lab, centralUrl: config.server.registerUrl || null });
  } else if (!row) {
    db.upsertServerIdentity({ serverId: sid, labDomain: lab, centralUrl: config.server.registerUrl || null });
  }
  return currentIdentity();
}

/**
 * Register this installation with the central platform (best-effort, offline-tolerant).
 * POSTs { serverId, apex, wildcard, labDomain } to SERVER_REGISTER_URL.
 * Never throws for network errors when we have a PKI fallback.
 */
export async function registerServer(): Promise<{ registered: boolean; detail: string }> {
  const id = ensureIdentity();
  const url = config.server.registerUrl?.trim();
  if (!url) {
    return { registered: false, detail: "SERVER_REGISTER_URL not configured — running offline (standalone)" };
  }
  const payload = {
    serverId: id.serverId,
    server_id: id.serverId,
    apex: id.apex,
    wildcard: id.wildcard,
    wildcard_domain: id.apex,
    labDomain: id.labDomain,
  };
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(config.server.registerToken ? { Authorization: `Bearer ${config.server.registerToken}` } : {}),
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10_000),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 400)}`);
    db.setServerRegistered(true, url);
    db.addActivity("server-register", `Registered ${id.serverId} (${id.apex}) with central`, url);
    return { registered: true, detail: "registered" };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    db.addActivity("server-register-error", `Registration failed for ${id.serverId}`, msg);
    // Offline-safe: still considered “locally registered”
    return { registered: false, detail: msg };
  }
}

/**
 * Issue or renew the host's own 30-day wildcard (*.<id>.lab.innotel.us) via the
 * internal PKI so offline operation still has a valid cert. The cert row is
 * tagged source="pki" and expiresAt reflects the 30-day validity.
 */
export async function ensureWildcardPki(): Promise<{ certId: number; domain: string } | null> {
  if (!config.server.autoWildcard) return null;
  const id = ensureIdentity();
  const apex = id.apex; // e.g. srv-abc1234.lab.innotel.us
  const wildcardName = `*.${apex}`;
  // Reuse existing pki wildcard if still valid > 7 days AND its SANs cover
  // the current apex — the identity can change after a cert was minted (e.g.
  // lab_domain edits), and a stale wildcard must be re-issued rather than kept.
  const existing = id.wildcardCertId ? db.getCertificate(id.wildcardCertId) : undefined;
  if (existing && existing.certificate && existing.expires_at) {
    const daysLeft = (new Date(existing.expires_at).getTime() - Date.now()) / 86400000;
    const coversApex = parseDomains(existing.domains_json).some(
      (d) => d === apex || d === `*.${apex}`,
    );
    if (daysLeft > 7 && coversApex) return { certId: existing.id, domain: apex };
  }

  // Issue a 30-day wildcard from internal PKI. We issue it as a client-style cert
  // but with serverAuth EKU and SANs apex, *.<apex>. Reuse PKI machinery via pki.
  // Fallback: generate a TLS server cert signed by the internal root CA.
  const validity = config.server.wildcardValidityDays;
  // Use the PKI CA directly to mint a server certificate
  const certMaterial = await issueWildcardServerCert(id.serverId, apex, validity);
  if (!certMaterial) return null;

  // Persist as a CertificateRow so NPM sync and /certificates listing see it
  let certRow: { id: number } | undefined;
  if (existing) {
    db.saveCertificateMaterial(existing.id, certMaterial.certificate, certMaterial.key, certMaterial.expiresAt, "pki");
    certRow = existing;
  } else {
    const created = db.createCertificate({
      name: wildcardName,
      domain: apex,
      wildcard: true,
      tenantId: 1,
      source: "pki",
    });
    db.saveCertificateMaterial(created.id, certMaterial.certificate, certMaterial.key, certMaterial.expiresAt, "pki");
    db.updateCertificateStatus(created.id, "issued");
    db.setServerWildcardCert(created.id);
    certRow = created;
    db.addActivity("wildcard-pki", `Issued 30-day PKI wildcard for ${wildcardName}`, `certId=${created.id} expires=${certMaterial.expiresAt}`);
  }

  // Ensure Technitium zone exists for apex (offline-first)
  try {
    const { ensureZone } = await import("./technitium");
    await ensureZone(apex);
    // Auto-add apex A record pointing at NPM/this host if NPM_FORWARD_HOST set (best-effort)
    const fwd = process.env.NPM_FORWARD_HOST?.trim() || process.env.TECHNITIUM_FORWARD_HOST?.trim();
    if (fwd) {
      const { addRecord } = await import("./technitium");
      try { await addRecord({ zone: apex, type: "A", name: "@", value: fwd, ttl: 300 }); } catch { /* already exists */ }
    }
  } catch { /* technitium not yet reachable — cert still usable for NPM */ }

  // Push to NPM (best-effort, never throws)
  try {
    const { npm } = await import("./npm");
    const cid = certRow?.id ?? existing?.id;
    if (cid) await npm.syncCertificateToNpm(cid);
  } catch { /* ignore */ }

  return { certId: certRow!.id, domain: apex };
}

async function issueWildcardServerCert(
  serverId: string,
  apex: string,
  validityDays: number,
): Promise<{ certificate: string; key: string; expiresAt: string } | null> {
  // Mint a proper TLS server certificate (serverAuth EKU, SANs apex + *.<apex>)
  // signed by the internal root CA. Works offline.
  try {
    const ca = await pki.ensureCa();
    const { createPrivateKey, webcrypto, X509Certificate } = await import("node:crypto");
    const x509 = await import("@peculiar/x509");

    const serverKeys = await webcrypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const caKeyObject = createPrivateKey(ca.key);
    const caCert = new x509.X509Certificate(ca.certificate);
    const caSigningKey = await webcrypto.subtle.importKey(
      "pkcs8",
      caKeyObject.export({ type: "pkcs8", format: "der" }) as unknown as ArrayBuffer,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );

    // Claim a serial from the CA counter
    const serialNum = db.nextCaSerial();
    let hex = serialNum.toString(16).toUpperCase();
    if (hex.length % 2 === 1) hex = `0${hex}`;
    if (/^[89A-F]/.test(hex)) hex = `00${hex}`;

    const now = new Date();
    const notAfter = new Date(now.getTime() + validityDays * 86400000);

    // Build SAN: apex + wildcard
    const sans: Array<{ type: "dns"; value: string }> = [
      { type: "dns", value: apex },
      { type: "dns", value: `*.${apex}` },
    ];

    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: hex,
      subject: `CN=*.${apex}`,
      issuer: caCert.subject,
      notBefore: now,
      notAfter,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      publicKey: serverKeys.publicKey,
      signingKey: caSigningKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment, true),
        new x509.ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.1"], false), // serverAuth
        await x509.SubjectKeyIdentifierExtension.create(serverKeys.publicKey, false),
        await x509.AuthorityKeyIdentifierExtension.create(caCert.publicKey, false),
        new x509.SubjectAlternativeNameExtension(sans),
      ],
    });

    const derToPem = (der: Uint8Array, label: string) => {
      const b64 = Buffer.from(der).toString("base64");
      const lines = b64.match(/.{1,64}/g)?.join("\n") ?? "";
      return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
    };
    const keyDer = await webcrypto.subtle.exportKey("pkcs8", serverKeys.privateKey);
    const keyPem = derToPem(new Uint8Array(keyDer as ArrayBuffer), "PRIVATE KEY");
    const certPem = cert.toString();
    const expiresAt = new X509Certificate(certPem).validTo;
    return { certificate: certPem, key: keyPem, expiresAt };
  } catch (err) {
    db.addActivity("wildcard-pki-error", `PKI wildcard issuance failed for ${apex}`, err instanceof Error ? err.message : String(err));
    return null;
  }
}

/**
 * Best-effort ACME upgrade: if online, try to replace the PKI wildcard with
 * a public Let's Encrypt cert (same *.<id>.lab.innotel.us via Technitium DNS-01).
 * Never deletes the PKI cert on failure.
 */
export async function tryUpgradeWildcardToAcme(): Promise<{ upgraded: boolean; detail: string }> {
  if (!config.server.autoWildcard) return { upgraded: false, detail: "autoWildcard disabled" };
  const id = ensureIdentity();
  const row = id.wildcardCertId ? db.getCertificate(id.wildcardCertId) : undefined;
  const shouldTry = !row || row.source !== "acme" || (() => {
    if (!row?.expires_at) return true;
    const days = (new Date(row.expires_at).getTime() - Date.now()) / 86400000;
    return days < 14; // renew window for 30-day cert
  })();
  if (!shouldTry) return { upgraded: false, detail: "acme wildcard still fresh" };

  // Quick offline probe: if Technitium is unreachable, don't attempt ACME
  try {
    const { testConnection } = await import("./technitium");
    const probe = await testConnection();
    if (!probe.ok) return { upgraded: false, detail: `offline: technitium unreachable (${probe.detail.slice(0, 80)})` };
  } catch { return { upgraded: false, detail: "offline" }; }

  try {
    const { issueCertificate } = await import("./acme");
    // Ensure a cert row exists for the ACME attempt
    let certId = row?.id;
    if (!certId) {
      const created = db.createCertificate({ name: `*.${id.apex}`, domain: id.apex, wildcard: true, tenantId: 1 });
      certId = created.id;
      db.setServerWildcardCert(certId);
    }
    const result = await issueCertificate({ certId, domain: id.apex, wildcard: true });
    db.saveCertificateMaterial(certId, result.certificate, result.key, result.expiresAt, "acme");
    db.addActivity("wildcard-acme", `Upgraded ${id.apex} wildcard to ACME (Let's Encrypt)`, `certId=${certId} expires=${result.expiresAt}`);
    try {
      const { npm } = await import("./npm");
      await npm.syncCertificateToNpm(certId);
    } catch { /* ignore */ }
    return { upgraded: true, detail: "issued via acme" };
  } catch (err) {
    return { upgraded: false, detail: err instanceof Error ? err.message : String(err) };
  }
}
