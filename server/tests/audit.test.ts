import { describe, expect, it } from "vitest";
import { scoreChecks } from "../src/services/audit";
import type { HealthCheck } from "../src/services/health";

function check(status: HealthCheck["status"]): HealthCheck {
  return { name: "x", status, detail: "" };
}

describe("scoreChecks", () => {
  it("scores a clean audit at 100", () => {
    expect(scoreChecks([check("ok"), check("ok")])).toBe(100);
  });

  it("deducts 10 per warning", () => {
    expect(scoreChecks([check("ok"), check("warn")])).toBe(90);
    expect(scoreChecks([check("warn"), check("warn")])).toBe(80);
  });

  it("deducts 25 per failure", () => {
    expect(scoreChecks([check("fail")])).toBe(75);
    expect(scoreChecks([check("fail"), check("fail")])).toBe(50);
  });

  it("clamps at zero", () => {
    expect(scoreChecks([check("fail"), check("fail"), check("fail"), check("fail"), check("fail")])).toBe(0);
  });

  it("never exceeds 100", () => {
    expect(scoreChecks([])).toBe(100);
  });
});
