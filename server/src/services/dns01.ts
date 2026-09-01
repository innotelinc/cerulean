import { createHash } from "node:crypto";

/**
 * DNS-01 challenge record for an ACME authorization. The TXT value is the
 * base64url-encoded SHA-256 digest of the key authorization (RFC 8555 §8.4),
 * published at _acme-challenge.<domain>. Wildcard identifiers
 * (`*.example.com`) are validated via the base domain's challenge record.
 */
export function dns01Record(
  authz: { identifier: { value: string } },
  keyAuthorization: string,
): { key: string; value: string } {
  const identifier = authz.identifier.value.startsWith("*.")
    ? authz.identifier.value.slice(2)
    : authz.identifier.value;
  return {
    key: `_acme-challenge.${identifier}`,
    value: createHash("sha256").update(keyAuthorization).digest("base64url"),
  };
}
