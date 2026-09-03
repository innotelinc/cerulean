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

/** Allowed device/identity names (subject CN, 1-64 chars). */
export const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
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

export function pkiStatus(tenantId?: number): PkiStatus {
  const ca = db.getCa();
  const certs = db.listClientCertificates(tenantId);
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

export interface EnrollCsrInput {
  validityDays?: number;
}

interface ValidatedIssueInput {
  name: string;
  email: string;
  validityDays: number;
}

function validateIssueInput(
  nameRaw: string,
  emailRaw?: string,
  validityDaysRaw?: number,
): ValidatedIssueInput {
  const name = nameRaw.trim();
  if (!NAME_RE.test(name)) {
    throw new PkiError(
      400,
      `Invalid name "${name}" — use letters, digits, '.', '_' or '-', 1-64 chars, no spaces`,
    );
  }
  const email = (emailRaw ?? "").trim();
  if (email && !EMAIL_RE.test(email)) {
    throw new PkiError(400, `Invalid email address: ${email}`);
  }
  const validityDays = Math.min(
    Math.max(Math.floor(validityDaysRaw || config.pki.certValidityDays), 1),
    config.pki.caValidityDays,
  );
  return { name, email, validityDays };
}

function assertNameFree(name: string, tenantId?: number): void {
  if (db.findActiveClientCertificate(name, tenantId)) {
    throw new PkiError(
      409,
      `A certificate for "${name}" is already active — revoke it before re-issuing`,
    );
  }
}

interface SignRequest {
  name: string;
  email: string;
  validityDays: number;
  tenantId?: number;
  publicKey: webcrypto.CryptoKey | x509.PublicKey;
  /** PKCS#8 PEM of a server-generated key, or null when the private key stays
   * on the enrollee's side (CSR enrollment). */
  keyPem: string | null;
  activityKind: string;
}

/**
 * Sign a public key into a TLS client certificate with the internal CA and
 * persist it. Shared by portal-side issuance (server holds the key) and CSR
 * enrollment (the device holds the key).
 */
async function signAndStore(req: SignRequest): Promise<ClientCertificateRow> {
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
  const now = new Date();
  const notAfter = new Date(now.getTime() + req.validityDays * 86400_000);
  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    new x509.ExtendedKeyUsageExtension([CLIENT_AUTH_OID], true),
    await x509.SubjectKeyIdentifierExtension.create(req.publicKey, true),
    await x509.AuthorityKeyIdentifierExtension.create(caCert.publicKey, false),
  ];
  if (req.email) {
    extensions.push(
      new x509.SubjectAlternativeNameExtension([{ type: "email", value: req.email }]),
    );
  }

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serialToHex(serial),
    subject: `CN=${req.name}`,
    issuer: caCert.subject,
    notBefore: now,
    notAfter,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    publicKey: req.publicKey,
    signingKey: caSigningKey,
    extensions,
  });
  const certificatePem = cert.toString();
  const fingerprint = new X509Certificate(certificatePem).fingerprint256;

  const row = db.createClientCertificate({
    name: req.name,
    email: req.email || undefined,
    serialHex: serialToHex(serial),
    certificate: certificatePem,
    key: req.keyPem ?? "",
    fingerprint,
    expiresAt: notAfter.toISOString(),
    tenantId: req.tenantId,
  });
  db.addActivity(
    req.activityKind,
    `Issued client certificate for "${req.name}" (serial ${row.serial_hex})`,
    `expires=${row.expires_at}`,
  );
  return row;
}

/**
 * Issue a TLS client certificate signed by the internal CA. The root CA is
 * created on first use, so the first issuance "just works".
 */
export async function issueClientCertificate(
  input: IssueClientCertificateInput,
  tenantId?: number,
): Promise<ClientCertificateRow> {
  const { name, email, validityDays } = validateIssueInput(
    input.name,
    input.email,
    input.validityDays,
  );
  assertNameFree(name, tenantId);

  const ca = await ensureCa();
  const curve = curveName(createPrivateKey(ca.key));
  const clientKeys = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: curve },
    true,
    ["sign", "verify"],
  );
  return signAndStore({
    name,
    email,
    validityDays,
    tenantId,
    publicKey: clientKeys.publicKey,
    keyPem: await exportKey(clientKeys.privateKey, "pkcs8", "PRIVATE KEY"),
    activityKind: "pki-issue",
  });
}

/**
 * Sign a device-generated PKCS#10 CSR with the internal CA and record the
 * certificate. The device keeps its private key — Cerulean stores no key for
 * it — and the result is revoked/re-issued exactly like a portal-issued one.
 * This is the CA operation a SCEP/EST/MDM enrollment front ultimately
 * performs, exposed directly so devices, MDMs and scripts can enroll now.
 */
export async function enrollCsr(
  csrPem: string,
  input: EnrollCsrInput = {},
  tenantId?: number,
): Promise<ClientCertificateRow> {
  const pem = String(csrPem ?? "").trim();
  if (!pem) {
    throw new PkiError(400, "Missing CSR — send a PKCS#10 request in PEM form");
  }
  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(pem);
  } catch {
    throw new PkiError(
      400,
      "Unparseable CSR — expected -----BEGIN CERTIFICATE REQUEST----- PEM",
    );
  }
  if (!(await csr.verify(webcrypto))) {
    throw new PkiError(
      400,
      "CSR signature does not match the enclosed public key",
    );
  }

  const alg = csr.publicKey.algorithm as {
    name?: string;
    namedCurve?: string;
    modulusLength?: number;
  };
  const supported =
    alg?.name === "ECDSA"
      ? ["P-256", "P-384", "P-521"].includes(alg.namedCurve ?? "")
      : alg?.name === "RSASSA-PKCS1-v1_5"
        ? (alg.modulusLength ?? 0) >= 2048
        : false;
  if (!supported) {
    throw new PkiError(
      400,
      "CSR key must be ECDSA (P-256/P-384/P-521) or RSA ≥ 2048 bits",
    );
  }

  const cn = csr.subjectName.getField("CN");
  if (!cn.length) {
    throw new PkiError(
      400,
      "CSR subject must include a CN — that is the device/identity name in Cerulean",
    );
  }
  const { name, validityDays } = validateIssueInput(
    cn[0],
    undefined,
    input.validityDays,
  );
  assertNameFree(name, tenantId);

  return signAndStore({
    name,
    email: "",
    validityDays,
    tenantId,
    publicKey: csr.publicKey,
    keyPem: null,
    activityKind: "pki-enroll",
  });
}

export function listClientCertificates(tenantId?: number): ClientCertificateRow[] {
  return db.listClientCertificates(tenantId);
}

export function getClientCertificate(
  id: number,
  tenantId?: number,
): ClientCertificateRow | undefined {
  return db.getClientCertificate(id, tenantId);
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

export function revokeClientCertificate(
  id: number,
  tenantId?: number,
): ClientCertificateRow {
  const row = db.getClientCertificate(id, tenantId);
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
