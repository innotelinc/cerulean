# 🔵 Cerulean — Platform Stack Role

**Classification: TrustOps**

Certificate lifecycle, DNS automation, and device trust — ACME, PKI, discovery, deployment, and trust scoring for the whole ecosystem.

This page declares Cerulean's role in the
[**Innotel Platform Stack**](https://github.com/innotelinc/innotel-platform-stack) —
the canonical single-responsibility architecture. The stack is defined in exactly one
place; this page links each product to it and states what this platform owns, consumes,
provides, and explicitly does not own.

## Owns

- Certificate lifecycle
- ACME automation
- PKI (internal CA, device mTLS)
- DNS automation
- Certificate discovery
- Certificate deployment
- Trust monitoring
- DNS health
- Compliance reporting
- Trust scoring

## Provides

- Trust services (certificates, DNS, PKI) to Monarch, Zeus, Oasis, Signara, ONYX, Magnate, Capstone, and NPM Edge

## Consumes

- Authentik — identity, SSO, organizations
- Infisical — secrets, TLS private keys, CA keys

## Explicitly does NOT own

- Users and passwords (Authentik)
- Payment processing (Magnate)
- Storage (ONYX)


> **Current state:** Cerulean resolves `infisical://` secret references alongside the legacy `vault://` backend.

## Secrets (Infisical)

Secrets for this platform live in **Infisical** (SecretOps): credentials are imported
into an Infisical workspace and the stack's `.env` is derived from it. Enable it with:

```bash
# generate the required keys and add them to .env
openssl rand -base64 32   # INFISICAL_ENCRYPTION_KEY
openssl rand -hex 16      # INFISICAL_AUTH_SECRET
openssl rand -hex 16      # INFISICAL_DB_PASSWORD

# start the profile and provision the workspace + import .env secrets
docker compose -f docker-compose.yml -f compose.infisical.yml --profile infisical up -d
bash scripts/infisical-setup.sh
```

See [compose.infisical.yml](../compose.infisical.yml) and
[scripts/infisical-setup.py](../scripts/infisical-setup.py) for details.

## Golden rules

- **Authentik = Identity** · **Infisical = Secrets** · **Cerulean = Trust** ·
  **ONYX = Storage** · **Magnate = Revenue** — everything else is a business function.
- No platform duplicates another's responsibility.
- No credit in commits, footers, or headers to anyone but the project owner.

---

*Cerulean · TrustOps · [Innotel Platform Stack](https://github.com/innotelinc/innotel-platform-stack)*
