import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPublicKey, webcrypto, X509Certificate } from "node:crypto";
import * as x509 from "@peculiar/x509";

// The enrollment profile embeds the configured SCEP URL; set it before the
// config singleton loads (first dynamic import below).
process.env.PKI_SCEP_URL = "https://scep.example.test/scep";

/**
 * The pki service talks to the sqlite-backed `db` singleton. Vitest cannot
 * load `node:sqlite` (it is not in Vite 5's builtin list), so like the rest
 * of the suite we exercise the service against an in-memory fake store — the
 * X.509 issuance, chain validation and lifecycle rules are all real.
 */

type CertRow = {
  id: number;
  name: string;
  email: string | null;
  serial_hex: string;
  status: string;
  certificate: string;
  key: string;
  fingerprint: string | null;
  expires_at: string | null;
  issued_at: string | null;
  revoked_at: string | null;
  tenant_id: number;
  created_at: string;
};
type CaRow = {
  id: number;
  common_name: string;
  certificate: string;
  key: string;
  serial: number;
  created_at: string;
};

const h = vi.hoisted(() => {
  const state: { ca: CaRow | undefined; certs: CertRow[]; serial: number } = {
    ca: undefined,
    certs: [],
    serial: 0,
  };
  const nowIso = () => new Date().toISOString();
  const db = {
    getCa: () => state.ca,
    createCa: (input: {
      commonName: string;
      certificate: string;
      key: string;
    }) => {
      state.ca = {
        id: 1,
        common_name: input.commonName,
        certificate: input.certificate,
        key: input.key,
        serial: 0,
        created_at: nowIso(),
      };
      return state.ca;
    },
    nextCaSerial: () => {
      state.serial += 1;
      return state.serial;
    },
    listClientCertificates: (tenantId?: number) =>
      tenantId
        ? state.certs.filter((c) => c.tenant_id === tenantId)
        : state.certs,
    getClientCertificate: (id: number, tenantId?: number) =>
      state.certs.find(
        (c) => c.id === id && (tenantId === undefined || c.tenant_id === tenantId),
      ),
    findActiveClientCertificate: (name: string, tenantId?: number) =>
      state.certs.find(
        (c) =>
          c.name === name &&
          c.status === "issued" &&
          (tenantId === undefined || c.tenant_id === tenantId),
      ),
    createClientCertificate: (input: {
      name: string;
      email?: string;
      serialHex: string;
      certificate: string;
      key: string;
      fingerprint: string;
      expiresAt: string;
      tenantId?: number;
    }) => {
      const row: CertRow = {
        id: state.certs.length + 1,
        name: input.name,
        email: input.email?.toLowerCase() ?? null,
        serial_hex: input.serialHex,
        status: "issued",
        certificate: input.certificate,
        key: input.key,
        fingerprint: input.fingerprint,
        expires_at: input.expiresAt,
        issued_at: nowIso(),
        revoked_at: null,
        tenant_id: input.tenantId ?? 1,
        created_at: nowIso(),
      };
      state.certs.push(row);
      return row;
    },
    revokeClientCertificate: (id: number) => {
      const row = state.certs.find((c) => c.id === id);
      if (row) {
        row.status = "revoked";
        row.revoked_at = nowIso();
      }
      return row;
    },
    addActivity: () => {},
  };
  return {
    db,
    reset: () => {
      state.ca = undefined;
      state.certs = [];
      state.serial = 0;
    },
  };
});

vi.mock("../src/db", () => ({ db: h.db }));

const {
  caCertificatePem,
  clientCertificateMaterial,
  enrollCsr,
  ensureCa,
  getClientCertificate,
  issueClientCertificate,
  listClientCertificates,
  pkiStatus,
  revokeClientCertificate,
} = await import("../src/services/pki");
const { buildEnrollmentProfile } = await import("../src/services/enrollment");

const CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";

/** Unique CN so tests never collide with leftovers in the shared test DB. */
const uniq = (prefix = "t") =>
  `${prefix}-${process.pid.toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

beforeEach(() => {
  h.reset();
});

describe("pki CA", () => {
  it("ensureCa is idempotent and returns a self-signed root CA", async () => {
    expect(pkiStatus().initialized).toBe(false);

    await ensureCa();
    const status = pkiStatus();
    expect(status.initialized).toBe(true);
    expect(status.commonName).toBe("Cerulean Root CA");
    expect(status.caFingerprint).toBeTruthy();
    expect(status.caExpiresAt).toBeTruthy();

    const caPem = caCertificatePem();
    expect(caPem).toContain("BEGIN CERTIFICATE");
    const cert = new X509Certificate(caPem);
    expect(cert.subject).toBe(cert.issuer); // self-signed

    // Basic constraints: it really is a CA.
    const parsed = new x509.X509Certificate(caPem);
    const bc = parsed.extensions.find(
      (e) => e instanceof x509.BasicConstraintsExtension,
    ) as x509.BasicConstraintsExtension;
    expect(bc).toBeTruthy();
    expect(bc.ca).toBe(true);

    // Re-running must not rotate the CA.
    const fingerprint = status.caFingerprint;
    await ensureCa();
    expect(pkiStatus().caFingerprint).toBe(fingerprint);
  });
});

describe("issueClientCertificate", () => {
  it("issues a clientAuth certificate signed by the root CA", async () => {
    const name = uniq();
    const row = await issueClientCertificate({
      name,
      email: "dev@example.com",
      validityDays: 30,
    });

    expect(row.name).toBe(name);
    expect(row.email).toBe("dev@example.com");
    expect(row.status).toBe("issued");
    expect(row.serial_hex).toMatch(/^[0-9A-F]+$/);

    const leaf = new X509Certificate(row.certificate);
    expect(leaf.subject).toBe(`CN=${name}`);
    expect(leaf.issuer).toBe(new X509Certificate(caCertificatePem()).subject);
    expect(leaf.verify(createPublicKey(caCertificatePem()))).toBe(true);
    expect(row.fingerprint).toBe(leaf.fingerprint256);
    expect(row.key).toContain("BEGIN PRIVATE KEY");
    expect(new Date(row.expires_at!).getTime()).toBeGreaterThan(
      Date.now() + 29 * 86_400_000,
    );

    // Extended key usage: clientAuth only, and the leaf is not a CA.
    const parsed = new x509.X509Certificate(row.certificate);
    const eku = parsed.extensions.find(
      (e) => e instanceof x509.ExtendedKeyUsageExtension,
    ) as x509.ExtendedKeyUsageExtension;
    expect(eku.usages.map(String)).toContain(CLIENT_AUTH_OID);
    const bc = parsed.extensions.find(
      (e) => e instanceof x509.BasicConstraintsExtension,
    ) as x509.BasicConstraintsExtension;
    expect(bc.ca).toBe(false);

    // Listed + retrievable by id.
    expect(listClientCertificates().find((c) => c.id === row.id)?.name).toBe(
      name,
    );
    expect(getClientCertificate(row.id)?.name).toBe(name);
  });

  it("auto-initializes the CA on first use and assigns distinct serials", async () => {
    const first = await issueClientCertificate({ name: uniq("s1") });
    const second = await issueClientCertificate({ name: uniq("s2") });
    expect(pkiStatus().initialized).toBe(true);
    expect(first.serial_hex).not.toBe(second.serial_hex);
  });

  it("rejects an invalid name and email", async () => {
    await expect(issueClientCertificate({ name: "has spaces!" })).rejects.toThrow(
      /Invalid name/,
    );
    await expect(
      issueClientCertificate({ name: uniq(), email: "not-an-email" }),
    ).rejects.toThrow(/Invalid email/);
    await expect(issueClientCertificate({ name: "" })).rejects.toThrow(
      /Invalid name/,
    );
  });

  it("allows only one active certificate per name, and re-issue after revoke", async () => {
    const name = uniq();
    const row = await issueClientCertificate({ name });
    await expect(issueClientCertificate({ name })).rejects.toMatchObject({
      status: 409,
      message: expect.stringContaining("already active"),
    });

    revokeClientCertificate(row.id);
    const reissued = await issueClientCertificate({ name });
    expect(reissued.id).not.toBe(row.id);
    expect(reissued.status).toBe("issued");
  });
});

describe("revokeClientCertificate", () => {
  it("revokes a certificate and refuses to double-revoke or revoke ghosts", async () => {
    const row = await issueClientCertificate({ name: uniq() });
    const updated = revokeClientCertificate(row.id);
    expect(updated.status).toBe("revoked");
    expect(updated.revoked_at).toBeTruthy();

    expect(() => revokeClientCertificate(row.id)).toThrow(/already revoked/);
    expect(() => revokeClientCertificate(999_999)).toThrow(/not found/);
  });

  it("counts issued/revoked in pkiStatus", async () => {
    const row = await issueClientCertificate({ name: uniq() });
    expect(pkiStatus().issued).toBe(1);
    revokeClientCertificate(row.id);
    const after = pkiStatus();
    expect(after.issued).toBe(0);
    expect(after.revoked).toBe(1);
  });
});

describe("clientCertificateMaterial", () => {
  it("returns leaf, private key and the root CA for trust installation", async () => {
    const row = await issueClientCertificate({ name: uniq() });
    const material = clientCertificateMaterial(row);
    expect(material.certificate).toContain("BEGIN CERTIFICATE");
    expect(material.key).toContain("BEGIN PRIVATE KEY");
    expect(material.ca).toContain("BEGIN CERTIFICATE");
    // The CA PEM matches the actual root (so clients can build the chain).
    expect(material.ca).toBe(caCertificatePem());
  });
});

async function makeCsr(
  cn: string,
  alg: { name: "ECDSA"; namedCurve: string } | { name: "RSASSA-PKCS1-v1_5"; modulusLength: number } = {
    name: "ECDSA",
    namedCurve: "P-256",
  },
): Promise<string> {
  const keys =
    alg.name === "ECDSA"
      ? await webcrypto.subtle.generateKey(
          { name: "ECDSA", namedCurve: alg.namedCurve },
          true,
          ["sign", "verify"],
        )
      : await webcrypto.subtle.generateKey(
          {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: alg.modulusLength,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
          },
          true,
          ["sign", "verify"],
        );
  const signingAlgorithm =
    alg.name === "ECDSA"
      ? { name: "ECDSA", hash: "SHA-256" }
      : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${cn}`,
    signingAlgorithm,
    keys,
  });
  return csr.toString();
}

describe("enrollCsr", () => {
  it("signs a device-generated CSR — the device keeps the private key", async () => {
    const name = uniq("csr");
    const row = await enrollCsr(await makeCsr(name), { validityDays: 30 });

    expect(row.name).toBe(name);
    expect(row.status).toBe("issued");
    expect(row.key).toBe(""); // Cerulean never sees the private key
    expect(row.serial_hex).toMatch(/^[0-9A-F]+$/);

    const leaf = new X509Certificate(row.certificate);
    expect(leaf.subject).toBe(`CN=${name}`);
    expect(leaf.verify(createPublicKey(caCertificatePem()))).toBe(true);

    // The server-side template still applies: clientAuth EKU, not a CA.
    const parsed = new x509.X509Certificate(row.certificate);
    const eku = parsed.extensions.find(
      (e) => e instanceof x509.ExtendedKeyUsageExtension,
    ) as x509.ExtendedKeyUsageExtension;
    expect(eku.usages.map(String)).toContain(CLIENT_AUTH_OID);
    const bc = parsed.extensions.find(
      (e) => e instanceof x509.BasicConstraintsExtension,
    ) as x509.BasicConstraintsExtension;
    expect(bc.ca).toBe(false);

    // Revoke frees the CN so the same device can re-enroll.
    revokeClientCertificate(row.id);
    const again = await enrollCsr(await makeCsr(name));
    expect(again.id).not.toBe(row.id);
    expect(again.status).toBe("issued");
  });

  it("accepts RSA ≥ 2048 CSRs too", async () => {
    const name = uniq("rsa");
    const row = await enrollCsr(
      await makeCsr(name, { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048 }),
    );
    expect(row.name).toBe(name);
    expect(row.key).toBe("");
    expect(new X509Certificate(row.certificate).verify(createPublicKey(caCertificatePem()))).toBe(
      true,
    );
  });

  it("rejects garbage, unsigned-looking and weak-key CSRs", async () => {
    await expect(enrollCsr("not a csr")).rejects.toMatchObject({
      status: 400,
      message: expect.stringContaining("Unparseable"),
    });
    await expect(enrollCsr("")).rejects.toMatchObject({ status: 400 });

    // An EC P-521 key is fine, but a 1024-bit RSA CSR must be refused.
    const weak = await makeCsr(uniq("weak"), {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 1024,
    });
    await expect(enrollCsr(weak)).rejects.toMatchObject({
      status: 400,
      message: expect.stringContaining("RSA ≥ 2048"),
    });
  });

  it("requires a CN and enforces the one-active-per-name rule across paths", async () => {
    const name = uniq("both");
    await issueClientCertificate({ name }); // portal-issued first
    await expect(enrollCsr(await makeCsr(name))).rejects.toMatchObject({ status: 409 });

    // A CSR with no CN is refused.
    const keys = await webcrypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "O=No CN Here",
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      keys,
    });
    await expect(enrollCsr(csr.toString())).rejects.toMatchObject({
      status: 400,
      message: expect.stringContaining("CN"),
    });
  });
});

describe("tenant isolation (client certificates)", () => {
  it("scopes issuance, listing, status and revocation to the tenant", async () => {
    // Two tenants (ids 2 and 3) each issue their own device certificate.
    const rowA = await issueClientCertificate({ name: uniq("ta") }, 2);
    const rowB = await issueClientCertificate({ name: uniq("tb") }, 3);

    // Tenant-wide views never leak across tenants.
    expect(listClientCertificates(2).map((c) => c.id)).toEqual([rowA.id]);
    expect(listClientCertificates(3).map((c) => c.id)).toEqual([rowB.id]);
    expect(pkiStatus(2).issued).toBe(1);
    expect(pkiStatus(3).issued).toBe(1);

    // Cross-tenant reads and revokes are invisible (404 semantics).
    expect(getClientCertificate(rowA.id, 3)).toBeUndefined();
    expect(() => revokeClientCertificate(rowA.id, 3)).toThrow(/not found/);
    expect(revokeClientCertificate(rowB.id, 3).status).toBe("revoked");
  });

  it("allows the same device name in different tenants", async () => {
    const name = uniq("shared");
    const a = await issueClientCertificate({ name }, 2);
    const b = await issueClientCertificate({ name }, 3); // no 409 across tenants
    expect(a.id).not.toBe(b.id);
    // …but a duplicate inside one tenant is still refused.
    await expect(issueClientCertificate({ name }, 2)).rejects.toMatchObject({
      status: 409,
    });
  });

  it("scopes CSR enrollment to the tenant too", async () => {
    const name = uniq("csr-t");
    const row = await enrollCsr(await makeCsr(name), {}, 2);
    expect(row.key).toBe("");
    expect(getClientCertificate(row.id, 2)?.id).toBe(row.id);
    expect(getClientCertificate(row.id, 3)).toBeUndefined();
  });
});

describe("enrollment profile (.mobileconfig)", () => {
  it("embeds the root CA trust anchor and an SCEP payload for the device CN", async () => {
    await ensureCa();
    const profile = buildEnrollmentProfile({ name: "mbp-admin" });
    expect(profile.filename).toBe("cerulean-mbp-admin.mobileconfig");
    expect(profile.xml).toContain("com.apple.security.root");
    expect(profile.xml).toContain("com.apple.security.scep");
    expect(profile.xml).toContain("https://scep.example.test/scep");
    expect(profile.xml).toContain("<string>CN</string>");
    expect(profile.xml).toContain("<string>mbp-admin</string>");
    // The profile literally carries the CA cert so the device can trust us.
    const derB64 = new X509Certificate(caCertificatePem()).raw.toString("base64");
    expect(profile.xml).toContain(derB64);
  });

  it("refuses to build before the CA exists or with an invalid name", async () => {
    expect(() => buildEnrollmentProfile({ name: "no-ca-yet" })).toThrow(
      /not initialized/,
    );
    expect(() => buildEnrollmentProfile({ name: "bad name!" })).toThrow(
      /Invalid device name/,
    );
  });
});
