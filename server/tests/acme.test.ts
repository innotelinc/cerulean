import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { dns01Record } from "../src/services/dns01";

describe("dns-01 challenge record construction", () => {
  const authz = { identifier: { type: "dns", value: "innotel.us" } };

  it("uses _acme-challenge.<domain> as the record name", () => {
    const record = dns01Record(authz, "fake-key-authorization");
    expect(record.key).toBe("_acme-challenge.innotel.us");
  });

  it("computes base64url(sha256(keyAuthorization)) as the TXT value", () => {
    const record = dns01Record(authz, "fake-key-authorization");
    const expected = createHash("sha256")
      .update("fake-key-authorization")
      .digest("base64url");
    expect(record.value).toBe(expected);
    // ACME DNS-01 TXT values are exactly 43 chars of URL-safe base64
    expect(record.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("strips the wildcard label — validation happens at the base domain", () => {
    const wildcardAuthz = {
      identifier: { type: "dns", value: "*.innotel.us" },
    };
    const record = dns01Record(wildcardAuthz, "x");
    expect(record.key).toBe("_acme-challenge.innotel.us");
  });
});
