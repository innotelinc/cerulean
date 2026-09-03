import {
  createPrivateKey,
  webcrypto,
  X509Certificate,
} from "node:crypto";
import * as x509 from "@peculiar/x509";
import { config } from "../config";
import { db, type CaRow, type ClientCertificateRow } from "../db";

/**
 * Internal private PKI for TLS client certificates.
 *
 * Cerulean generates a self-signed root CA (lazily, on first use) and issues
 * device/identity certificates from it — the building block for mTLS at the
 * reverse proxy ("auto-allow this device, it holds a cert from our CA"),
 * MDM/SCEP enrollment, and anything else that needs to prove a device or
 * user to nginx. Client certificates are ECDSA P-256 with the clientAuth
 * extended key usage, signed by the root CA whose private key lives in the
 * portal database (and mirrors to the vault when configured).
 *
 * Nothing here touches a public CA: private PKI, trusted only by the
 * endpoints you choose to trust it on.
 */

const CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Error with an HTTP status, so routes can respond precisely. */
export class PkiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "PkiError";
  }
}

const CURVES: Record<string, string> = {
  prime256v1: "P-256",
  secp384r1: "P-384",
  secp521r1: "P-521",
};

function curveName(keyObject: ReturnType<typeof createPrivateKey>): string {
  const curve = keyObject.asymmetricKeyDetails?.namedCurve;
  return CURVES[curve || ""] || "P-256";
}

function derToPem(der: Uint8Array, label: string): string {
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

async function exportKey(
  key: webcrypto.CryptoKey,
  format: "pkcs8" | "spki",
  label: string,
): Promise<string> {
  const der = await webcrypto.subtle.exportKey(format, key);
  return derToPem(new Uint8Array(der), label);
}

/** Serial counter → hex string acceptable as an X.509 serial number. */
function serialToHex(serial: number): string {
  let hex = serial.toString(16).toUpperCase();
  if (hex.length % 2 === 1) hex = `0${hex}`; // byte-align
  if (/^[89A-F]/.test(hex)) hex = `00${hex}`; // keep the integer positive
  return hex;
}

// ── CA lifecycle ──────────────────────────────────────────────────────────

export interface PkiStatus {
  initialized: boolean;
  commonName: string | null;
  caFingerprint: string | null;
  caExpiresAt: string | null;
  createdAt: string | null;
  issued: number;
  revoked: number;
}

export function pkiStatus(): PkiStatus {
  const ca = db.getCa();
  const certs = db.listClientCertificates();
  const issued = certs.filter((c) => c.status === "issued").length;
  const revoked = certs.filter((c) => c.status === "revoked").length;
  if (!ca) {
    return {
      initialized: false,
      commonName: null,
      caFingerprint: null,
      caExpiresAt: null,
      createdAt: null,
      issued,
      revoked,
    };
  }
  const parsed = new X509Certificate(ca.certificate);
  return {
    initialized: true,
    commonName: ca.common_name,
    caFingerprint: parsed.fingerprint256,
    caExpiresAt: parsed.validTo,
    createdAt: ca.created_at,
    issued,
    revoked,
  };
}

/** PEM of the root CA certificate (empty string until initialized). */
export function caCertificatePem(): string {
  return db.getCa()?.certificate ?? "";
}

async function generateCa(commonName: string): Promise<{ cert: string; key: string }> {
  const curve = "P-256";
  const keys = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: curve },
    true,
    ["sign", "verify"],
  );
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${commonName}`,
    notBefore: now,
    notAfter: new Date(now.getTime() + config.pki.caValidityDays * 86400_000),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 2, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, true),
    ],
  });
  return {
    cert: cert.toString(),
    key: await exportKey(keys.privateKey, "pkcs8", "PRIVATE KEY"),
  };
}

/**
 * Ensure the root CA exists (idempotent). Pass an explicit `commonName` only
 * when initializing; subsequent calls ignore it.
 */
export async function ensureCa(commonName?: string): Promise<CaRow> {
  const existing = db.getCa();
  if (existing) return existing;
  const name = (commonName || config.pki.caCommonName).trim();
  const ca = await generateCa(name);
  db.createCa({ commonName: name, certificate: ca.cert, key: ca.key });
  db.addActivity("pki-ca", `Created internal root CA "${name}"`);
  return db.getCa()!;
}

// ── Client certificates ───────────────────────────────────────────────────

export interface IssueClientCertificateInput {
  /** Subject CN + stable identity (device name, owner, ...). Unique among
   * active certificates; revoke the old one before re-issuing. */
  name: string;
  email?: string;
  validityDays?: number;
}

/**
 * Issue a TLS client certificate signed by the internal CA. The root CA is
 * created on first use, so the first issuance "just works".
 */
export async function issueClientCertificate(
  input: IssueClientCertificateInput,
): Promise<ClientCertificateRow> {
  const name = input.name.trim();
  if (!NAME_RE.test(name)) {
    throw new PkiError(
      400,
      `Invalid name "${name}" — use letters, digits, '.', '_' or '-', 1-64 chars, no spaces`,
    );
  }
  const email = input.email?.trim() || "";
  if (email && !EMAIL_RE.test(email)) {
    throw new PkiError(400, `Invalid email address: ${email}`);
  }
  const validityDays = Math.min(
    Math.max(Math.floor(input.validityDays || config.pki.certValidityDays), 1),
    config.pki.caValidityDays,
  );

  if (db.findActiveClientCertificate(name)) {
    throw new PkiError(
      409,
      `A certificate for "${name}" is already active — revoke it before re-issuing`,
    );
  }

  const ca = await ensureCa();
  const caKeyObject = createPrivateKey(ca.key);
  const curve = curveName(caKeyObject);
  const caCert = new x509.X509Certificate(ca.certificate);
  const caSigningKey = await webcrypto.subtle.importKey(
    "pkcs8",
    caKeyObject.export({ type: "pkcs8", format: "der" }),
    { name: "ECDSA", namedCurve: curve },
    false,
    ["sign"],
  );

  const serial = db.nextCaSerial();
  const clientKeys = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: curve },
    true,
    ["sign", "verify"],
  );

  const now = new Date();
  const notAfter = new Date(now.getTime() + validityDays * 86400_000);
  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    new x509.ExtendedKeyUsageExtension([CLIENT_AUTH_OID], true),
    await x509.SubjectKeyIdentifierExtension.create(clientKeys.publicKey, true),
    await x509.AuthorityKeyIdentifierExtension.create(caCert.publicKey, false),
  ];
  if (email) {
    extensions.push(
      new x509.SubjectAlternativeNameExtension([{ type: "email", value: email }]),
    );
  }

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serialToHex(serial),
    subject: `CN=${name}`,
    issuer: caCert.subject,
    notBefore: now,
    notAfter,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    publicKey: clientKeys.publicKey,
    signingKey: caSigningKey,
    extensions,
  });
  const certificatePem = cert.toString();
  const keyPem = await exportKey(clientKeys.privateKey, "pkcs8", "PRIVATE KEY");
  const fingerprint = new X509Certificate(certificatePem).fingerprint256;

  const row = db.createClientCertificate({
    name,
    email: email || undefined,
    serialHex: serialToHex(serial),
    certificate: certificatePem,
    key: keyPem,
    fingerprint,
    expiresAt: notAfter.toISOString(),
  });
  db.addActivity(
    "pki-issue",
    `Issued client certificate for "${name}" (serial ${row.serial_hex})`,
    `expires=${row.expires_at}`,
  );
  return row;
}

export function listClientCertificates(): ClientCertificateRow[] {
  return db.listClientCertificates();
}

export function getClientCertificate(id: number): ClientCertificateRow | undefined {
  return db.getClientCertificate(id);
}

/**
 * Material of an issued certificate: the leaf PEM, its private key, and the
 * root CA PEM (so a client can install the whole trust chain).
 */
export function clientCertificateMaterial(
  row: ClientCertificateRow,
): { certificate: string; key: string; ca: string } {
  const ca = db.getCa();
  return {
    certificate: row.certificate,
    key: row.key,
    ca: ca?.certificate ?? "",
  };
}

export function revokeClientCertificate(id: number): ClientCertificateRow {
  const row = db.getClientCertificate(id);
  if (!row) {
    throw new PkiError(404, "Client certificate not found");
  }
  if (row.status === "revoked") {
    throw new PkiError(409, `Certificate "${row.name}" is already revoked`);
  }
  const updated = db.revokeClientCertificate(id);
  db.addActivity(
    "pki-revoke",
    `Revoked client certificate for "${row.name}" (serial ${row.serial_hex})`,
  );
  return updated!;
}
