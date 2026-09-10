import { describe, expect, it } from "vitest";
import { loadConfig, sanitizeServerId } from "../src/config";

const baseEnv = {
  CERULEAN_ADMIN_PASSWORD: "test-password",
  CERULEAN_SERVER_ID: "srv-abc1234",
  NPM_MODE: "remote",
  NPM_API_URL: "http://external-npm:81",
  TECHNITIUM_URL: "http://technitium.test:5380",
};

describe("loadConfig — Technitium + server identity", () => {
  it("defaults zone to <serverId>.lab.innotel.us", () => {
    const cfg = loadConfig({ ...baseEnv, CERULEAN_ZONE: "" });
    // loadConfig requires CERULEAN_ZONE falsy to default; pass unset
    const cfg2 = loadConfig({ CERULEAN_ADMIN_PASSWORD: "pw", CERULEAN_SERVER_ID: "srv-xyz1000", CERULEAN_LAB_DOMAIN: "lab.example" });
    expect(cfg2.zone).toBe("srv-xyz1000.lab.example");
  });

  it("respects explicit CERULEAN_ZONE", () => {
    const cfg = loadConfig({ ...baseEnv, CERULEAN_ZONE: "custom.example" });
    expect(cfg.zone).toBe("custom.example");
  });

  it("uses Technitium URL from env, defaults to the host gateway when missing", () => {
    const cfg = loadConfig(baseEnv);
    expect(cfg.technitium.url).toBe("http://technitium.test:5380");
    // Technitium is host-networked, so the app reaches it through the host
    // gateway (host.docker.internal), never 127.0.0.1/container name.
    const cfg2 = loadConfig({ CERULEAN_ADMIN_PASSWORD: "pw", CERULEAN_SERVER_ID: "srv-abc1234" });
    expect(cfg2.technitium.url).toBe("http://host.docker.internal:5380");
  });

  it("caps wildcard validity to 1..90", () => {
    const cfg = loadConfig({ ...baseEnv, SERVER_WILDCARD_VALIDITY_DAYS: "200" });
    expect(cfg.server.wildcardValidityDays).toBe(90);
    const cfg2 = loadConfig({ ...baseEnv, SERVER_WILDCARD_VALIDITY_DAYS: "0" });
    expect(cfg2.server.wildcardValidityDays).toBe(1);
  });

  it("defaults labDomain to lab.innotel.us", () => {
    const cfg = loadConfig(baseEnv);
    expect(cfg.server.labDomain).toBe("lab.innotel.us");
    expect(cfg.server.id).toBe("srv-abc1234");
  });
});

describe("sanitizeServerId", () => {
  it("accepts DNS-safe slugs", () => {
    expect(sanitizeServerId("srv-abc1234")).toBe("srv-abc1234");
    expect(sanitizeServerId("alpha")).toBe("alpha");
  });
  it("rejects bad slugs", () => {
    expect(sanitizeServerId("-bad")).toBe("");
    expect(sanitizeServerId("bad-")).toBe("");
    expect(sanitizeServerId("Has Spaces")).toBe("");
  });
});

describe("NPM mode (Technitium only — BIND no longer exists)", () => {
  it("uses the bundled NPM address when NPM_MODE=local", () => {
    const cfg = loadConfig({ ...baseEnv, NPM_MODE: "local" });
    expect(cfg.npm.apiUrl).toBe("http://cerulean-npm:81");
  });

  it("uses external NPM when remote", () => {
    const cfg = loadConfig(baseEnv);
    expect(cfg.npm.apiUrl).toBe("http://external-npm:81");
  });
});
