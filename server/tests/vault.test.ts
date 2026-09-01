import { describe, expect, it } from "vitest";
import { parseVaultRef } from "../src/services/vault";

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
