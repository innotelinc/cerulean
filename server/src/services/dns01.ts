/**
 * DNS-01 challenge record for an ACME authorization, published at
 * _acme-challenge.<domain>. Wildcard identifiers (`*.example.com`) are
 * validated via the base domain's challenge record.
 *
 * The `keyAuthorization` passed in by acme-client for dns-01 challenges is
 * ALREADY the RFC 8555 §8.4 TXT value (base64url(SHA256(token.thumbprint)))
 * — it must be published verbatim. Hashing it again would produce a value
 * neither acme-client's verifier nor Let's Encrypt accepts.
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
    value: keyAuthorization,
  };
}
