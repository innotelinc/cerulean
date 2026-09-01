import { X509Certificate, createPrivateKey } from "node:crypto";

export interface HealthCheck {
  name: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

export interface CertHealth {
  score: number;
  grade: string;
  checks: HealthCheck[];
}

export interface HealthInput {
  expiresAt?: string | null;
  issuedAt?: string | null;
  domains?: string[];
  hasMaterial?: boolean;
  certificate?: string | null;
  key?: string | null;
  issuer?: string | null;
}

/** Grade a 0–100 score. */
export function gradeFor(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

const DAY_MS = 24 * 60 * 60 * 1000;

function daysUntil(iso?: string | null): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return (t - Date.now()) / DAY_MS;
}

/** Extract key strength details from a PEM private key. */
function keyStrength(pem?: string | null): {
  bits?: number;
  curve?: string;
  type: string;
} | null {
  if (!pem) return null;
  try {
    const key = createPrivateKey(pem);
    const details = key.asymmetricKeyDetails as {
      modulusLength?: number;
      namedCurve?: string;
    };
    const type = key.asymmetricKeyType || "unknown";
    return {
      bits: details?.modulusLength,
      curve: details?.namedCurve,
      type,
    };
  } catch {
    return null;
  }
}

/**
 * Score the health of a certificate (0–100) from its metadata and material.
 * Pure and synchronous — no network calls — so it can run on every listing.
 *
 * Checks:
 *  - remaining validity (fail < 7 days, warn < 30 days)
 *  - issue date present and not in the future
 *  - material (fullchain + key) stored
 *  - key strength (RSA ≥ 2048 or modern EC curve)
 *  - signature algorithm (SHA-1 fails)
 *  - SAN coverage (at least one name; wildcards also cover the apex)
 *  - self-signed certificates are flagged for review
 */
export function scoreCertificate(input: HealthInput): CertHealth {
  const checks: HealthCheck[] = [];
  const domains = input.domains || [];

  // 1. Remaining validity
  const days = daysUntil(input.expiresAt);
  if (days === null) {
    checks.push({ name: "validity", status: "warn", detail: "No expiry date recorded" });
  } else if (days < 0) {
    checks.push({ name: "validity", status: "fail", detail: `Expired ${Math.abs(Math.round(days))} days ago` });
  } else if (days < 7) {
    checks.push({ name: "validity", status: "fail", detail: `Expires in ${Math.round(days)} day(s)` });
  } else if (days < 30) {
    checks.push({ name: "validity", status: "warn", detail: `Expires in ${Math.round(days)} day(s)` });
  } else {
    checks.push({ name: "validity", status: "ok", detail: `Expires in ${Math.round(days)} day(s)` });
  }

  // 2. Issue date
  const issuedDays = daysUntil(input.issuedAt);
  if (!input.issuedAt) {
    checks.push({ name: "issued", status: "warn", detail: "No issue date recorded" });
  } else if (issuedDays !== null && issuedDays > 1) {
    checks.push({ name: "issued", status: "warn", detail: "Issue date is in the future" });
  } else {
    checks.push({ name: "issued", status: "ok", detail: "Issue date recorded" });
  }

  // 3. Material
  if (input.hasMaterial || (input.certificate && input.key)) {
    checks.push({ name: "material", status: "ok", detail: "Fullchain and private key stored" });
  } else {
    checks.push({ name: "material", status: "warn", detail: "Private key not stored with certificate" });
  }

  // 4. Key strength
  const strength = keyStrength(input.key);
  if (strength === null) {
    checks.push({ name: "key", status: "warn", detail: "Private key unavailable — cannot verify strength" });
  } else if (strength.type === "rsa" && strength.bits && strength.bits >= 2048) {
    checks.push({ name: "key", status: "ok", detail: `RSA-${strength.bits} key` });
  } else if (strength.type === "rsa") {
    checks.push({ name: "key", status: "fail", detail: `RSA-${strength.bits} is too weak — use ≥ 2048` });
  } else if (strength.type === "ec") {
    const modern = ["prime256v1", "secp256r1", "P-256", "secp384r1", "P-384", "secp521r1", "P-521"];
    if (strength.curve && modern.includes(strength.curve)) {
      checks.push({ name: "key", status: "ok", detail: `EC key (${strength.curve})` });
    } else {
      checks.push({ name: "key", status: "fail", detail: `EC key on weak curve: ${strength.curve || "unknown"}` });
    }
  } else {
    checks.push({ name: "key", status: "warn", detail: `Uncommon key type: ${strength.type}` });
  }

  // 5. Signature algorithm (from the leaf certificate PEM)
  if (input.certificate) {
    try {
      const leaf = new X509Certificate(firstPem(input.certificate));
      const legacy = leaf.toLegacyObject() as { signature?: { algorithm?: string } };
      const algo = (legacy.signature?.algorithm || "").toLowerCase();
      if (algo.includes("sha1")) {
        checks.push({ name: "signature", status: "fail", detail: `Weak signature algorithm: ${algo}` });
      } else {
        checks.push({ name: "signature", status: "ok", detail: algo ? `Signature: ${algo}` : "Signature verified" });
      }
      if (leaf.issuer && leaf.subject && leaf.issuer === leaf.subject) {
        checks.push({ name: "chain", status: "warn", detail: "Self-signed certificate — verify this is intended" });
      } else {
        checks.push({ name: "chain", status: "ok", detail: `Issued by ${leaf.issuer}` });
      }
    } catch {
      checks.push({ name: "signature", status: "warn", detail: "Could not parse certificate PEM" });
    }
  } else {
    checks.push({ name: "signature", status: "warn", detail: "Certificate PEM not available" });
  }

  // 6. SAN coverage
  if (domains.length === 0) {
    checks.push({ name: "coverage", status: "fail", detail: "No subject names recorded" });
  } else {
    const apex = domains.filter((d) => !d.startsWith("*."));
    const wildcards = domains.filter((d) => d.startsWith("*."));
    if (wildcards.length > 0 && apex.length === 0) {
      checks.push({ name: "coverage", status: "warn", detail: "Wildcard-only certificate — apex is not covered" });
    } else {
      checks.push({ name: "coverage", status: "ok", detail: `${domains.length} subject name(s)` });
    }
  }

  let score = 100;
  for (const c of checks) {
    if (c.status === "fail") score -= 25;
    else if (c.status === "warn") score -= 10;
  }
  score = Math.max(0, Math.min(100, score));

  return { score, grade: gradeFor(score), checks };
}

/** Extract the first PEM block (the leaf) from a possibly multi-cert chain. */
export function firstPem(pem: string): string {
  const match = pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/);
  return match ? match[0] : pem;
}
