import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { dns01Record } from "../src/services/dns01";

describe("dns-01 challenge record construction", () => {
  const authz = { identifier: { type: "dns", value: "innotel.us" } };

  it("uses _acme-challenge.<domain> as the record name", () => {
    const record = dns01Record(authz, "fake-key-authorization");
    expect(record.key).toBe("_acme-challenge.innotel.us");
  });

  it("publishes the key authorization verbatim (RFC 8555 §8.4)", () => {
    // acme-client passes the already-digested value (base64url SHA-256 of
    // token.thumbprint); it must NOT be hashed again.
    const record = dns01Record(authz, "fake-key-authorization");
    expect(record.value).toBe("fake-key-authorization");
  });

  it("strips the wildcard label — validation happens at the base domain", () => {
    const wildcardAuthz = {
      identifier: { type: "dns", value: "*.innotel.us" },
    };
    const record = dns01Record(wildcardAuthz, "x");
    expect(record.key).toBe("_acme-challenge.innotel.us");
  });
});
