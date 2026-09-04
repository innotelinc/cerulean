import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config";

const baseEnv = {
  CERULEAN_ADMIN_PASSWORD: "test-password",
  BIND_MODE: "remote",
  NPM_MODE: "remote",
  NPM_API_URL: "http://external-npm:81",
};

describe("local NPM deployment policy", () => {
  it("rejects local NPM when BIND is remote", () => {
    expect(() =>
      loadConfig({ ...baseEnv, NPM_MODE: "local" }),
    ).toThrow(/NPM_MODE=local requires BIND_MODE=local/);
  });

  it("uses the bundled NPM address for local BIND", () => {
    const cfg = loadConfig({
      ...baseEnv,
      BIND_MODE: "local",
      NPM_MODE: "local",
      NPM_API_URL: "http://stale-external-npm:81",
    });
    expect(cfg.bind.host).toBe("cerulean-bind");
    expect(cfg.npm.apiUrl).toBe("http://cerulean-npm:81");
  });

  it("uses the external NPM address for remote BIND", () => {
    const cfg = loadConfig(baseEnv);
    expect(cfg.npm.apiUrl).toBe("http://external-npm:81");
  });
});
