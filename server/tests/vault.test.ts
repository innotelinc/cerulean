import { describe, expect, it } from "vitest";
import { parseInfisicalRef, parseVaultRef } from "../src/services/vault";

describe("parseVaultRef", () => {
  it("parses vault://path#key", () => {
    expect(parseVaultRef("vault://cerulean/npm#password")).toEqual({
      path: "cerulean/npm",
      key: "password",
    });
  });

  it("parses a path without a key", () => {
    expect(parseVaultRef("vault://cerulean/npm")).toEqual({
      path: "cerulean/npm",
      key: undefined,
    });
  });

  it("returns undefined for plain values", () => {
    expect(parseVaultRef("change-me")).toBeUndefined();
    expect(parseVaultRef("")).toBeUndefined();
    expect(parseVaultRef("https://vault.example.com")).toBeUndefined();
  });
});

describe("parseInfisicalRef", () => {
  it("parses infisical://<name>", () => {
    expect(parseInfisicalRef("infisical://NPM_PASSWORD")).toBe("NPM_PASSWORD");
    expect(parseInfisicalRef("infisical://certs.default.1.key")).toBe("certs.default.1.key");
  });

  it("trims whitespace", () => {
    expect(parseInfisicalRef("infisical://  NPM_PASSWORD  ")).toBe("NPM_PASSWORD");
  });

  it("returns undefined for plain or vault values", () => {
    expect(parseInfisicalRef("change-me")).toBeUndefined();
    expect(parseInfisicalRef("")).toBeUndefined();
    expect(parseInfisicalRef("vault://cerulean/npm#password")).toBeUndefined();
  });
});
