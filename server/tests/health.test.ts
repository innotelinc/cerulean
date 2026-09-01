import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { firstPem, gradeFor, scoreCertificate } from "../src/services/health";

const DAY = 24 * 60 * 60 * 1000;
const inDays = (n: number) => new Date(Date.now() + n * DAY).toISOString();

function rsaKey(bits: number): string {
  return generateKeyPairSync("rsa", { modulusLength: bits }).privateKey.export({
    type: "pkcs8",
    format: "pem",
  }) as string;
}

describe("gradeFor", () => {
  it("maps scores to A–F grades", () => {
    expect(gradeFor(100)).toBe("A");
    expect(gradeFor(90)).toBe("A");
    expect(gradeFor(89)).toBe("B");
    expect(gradeFor(75)).toBe("B");
    expect(gradeFor(74)).toBe("C");
    expect(gradeFor(60)).toBe("C");
    expect(gradeFor(59)).toBe("D");
    expect(gradeFor(40)).toBe("D");
    expect(gradeFor(39)).toBe("F");
  });
});

describe("scoreCertificate", () => {
  it("gives a healthy long-lived certificate a top score", () => {
    const health = scoreCertificate({
      expiresAt: inDays(300),
      issuedAt: inDays(-10),
      domains: ["innotel.us", "*.innotel.us"],
      hasMaterial: true,
      certificate:
        "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
      key: rsaKey(2048),
    });
    expect(health.score).toBeGreaterThanOrEqual(80);
    expect(health.grade).toBe("A");
    const names = health.checks.map((c) => c.name);
    expect(names).toContain("validity");
    expect(names).toContain("key");
    expect(names).toContain("signature");
  });

  it("fails an expired certificate", () => {
    const health = scoreCertificate({
      expiresAt: inDays(-5),
      domains: ["innotel.us"],
    });
    expect(health.score).toBeLessThan(60);
    const validity = health.checks.find((c) => c.name === "validity");
    expect(validity?.status).toBe("fail");
  });

  it("warns for a certificate expiring within 30 days", () => {
    const health = scoreCertificate({
      expiresAt: inDays(15),
      domains: ["innotel.us"],
    });
    const validity = health.checks.find((c) => c.name === "validity");
    expect(validity?.status).toBe("warn");
  });

  it("flags a weak RSA-1024 key", () => {
    const health = scoreCertificate({
      expiresAt: inDays(300),
      domains: ["innotel.us"],
      key: rsaKey(1024),
    });
    const key = health.checks.find((c) => c.name === "key");
    expect(key?.status).toBe("fail");
  });

  it("accepts an RSA-2048 key", () => {
    const health = scoreCertificate({
      expiresAt: inDays(300),
      domains: ["innotel.us"],
      key: rsaKey(2048),
    });
    const key = health.checks.find((c) => c.name === "key");
    expect(key?.status).toBe("ok");
  });

  it("fails when no subject names are recorded", () => {
    const health = scoreCertificate({ expiresAt: inDays(300) });
    const coverage = health.checks.find((c) => c.name === "coverage");
    expect(coverage?.status).toBe("fail");
  });

  it("warns when a wildcard certificate does not cover the apex", () => {
    const health = scoreCertificate({
      expiresAt: inDays(300),
      domains: ["*.innotel.us"],
    });
    const coverage = health.checks.find((c) => c.name === "coverage");
    expect(coverage?.status).toBe("warn");
  });

  it("clamps the score to 0–100", () => {
    const health = scoreCertificate({
      expiresAt: inDays(-1),
      domains: [],
    });
    expect(health.score).toBeGreaterThanOrEqual(0);
    expect(health.score).toBeLessThanOrEqual(100);
  });
});

describe("firstPem", () => {
  it("extracts the leaf from a multi-cert chain", () => {
    const leaf = "-----BEGIN CERTIFICATE-----\nQUFB\n-----END CERTIFICATE-----";
    const chain = `${leaf}\n-----BEGIN CERTIFICATE-----\nQkJC\n-----END CERTIFICATE-----`;
    expect(firstPem(chain)).toBe(leaf);
  });

  it("returns the input unchanged when it is a single PEM", () => {
    const pem = "-----BEGIN CERTIFICATE-----\nQUFB\n-----END CERTIFICATE-----";
    expect(firstPem(pem)).toBe(pem);
  });
});
