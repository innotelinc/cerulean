# 🔵 Cerulean — Platform Stack Role

**Classification: TrustOps — Master Orchestrator (Technitium)**

Certificate lifecycle, DNS automation, DHCP, ad-blocking, and device trust — ACME, PKI, discovery, deployment, and trust scoring for the whole ecosystem. When running, Cerulean is **self-sufficient**: Technitium DNS + DHCP + blocking + 30-day wildcard (`*.<serverId>.lab.innotel.us`) without internet; upgraded to ACME when online.

This page declares Cerulean's role in the
[**Innotel Platform Stack**](https://github.com/innotelinc/innotel-platform-stack) —
the canonical single-responsibility architecture.

## Owns

- Certificate lifecycle (ACME DNS-01 via Technitium HTTP API; default 30-day wildcard PKI offline → ACME when online)
- DNS automation (Technitium authoritative zones via `/api/zones/*`)
- DHCP (Technitium scopes/leases via `/api/dhcp/*`)
- Ad-blocking (Technitium block lists + per-domain block/allow)
- Master orchestrator / server identity (`<serverId>.lab.innotel.us` + `*.<serverId>.lab.innotel.us`, central registration)
- PKI (internal CA, device mTLS, plus server wildcard)
- Certificate discovery & deployment
- Trust monitoring, DNS health, compliance reporting, trust scoring

## Provides

- Trust + network services (certificates, DNS, DHCP, blocking, PKI) to Monarch, Zeus, Oasis, Signara, ONYX, Magnate, Capstone, and NPM Edge
- Plug-anywhere LAN operation (DHCP/DNS/blocking/certs) without internet

## Consumes

- Authentik — identity, SSO, organizations
- Infisical — secrets, TLS private keys, CA keys
- Technitium DNS Server — DNS, DHCP, blocking backend (bundled via `technitium/dns-server`, or remote via `TECHNITIUM_URL`)
- Optional central registration endpoint (`SERVER_REGISTER_URL`) for `<serverId>` inventory

## Explicitly does NOT own

- Users and passwords (Authentik)
- Payment processing (Magnate)
- Storage (ONYX)

> **Current state:** Technitium HTTP API replaces RFC2136/nsupdate/SSH+BIND entirely. Cerulean resolves `infisical://` and `vault://` secret references. Default wildcard is 30-day, offline-first.

## Deployment — Technitium

Bundled (recommended, offline-ready):

```bash
docker compose --profile technitium up -d   # Technitium DNS+DHCP+blocking at http://<host>:5380 (port 53 for DNS, 67/udp for DHCP)
```

Or point `TECHNITIUM_URL`/`TECHNITIUM_TOKEN` (or `TECHNITIUM_USER`/`TECHNITIUM_PASSWORD`) at a remote Technitium.

Server identity: `CERULEAN_SERVER_ID` (stable `<serverId>`, auto-generated if empty) + `CERULEAN_LAB_DOMAIN` (default `lab.innotel.us`) → zone `<serverId>.lab.innotel.us`.

## Secrets (Infisical)

```bash
openssl rand -base64 32   # INFISICAL_ENCRYPTION_KEY
openssl rand -hex 16      # INFISICAL_AUTH_SECRET
openssl rand -hex 16      # INFISICAL_DB_PASSWORD
docker compose -f docker-compose.yml -f compose.infisical.yml --profile infisical up -d
bash scripts/infisical-setup.sh
```

See [compose.infisical.yml](../compose.infisical.yml) and [scripts/infisical-setup.py](../scripts/infisical-setup.py).

## Golden rules

- **Authentik = Identity** · **Infisical = Secrets** · **Cerulean = Trust + Network** · **ONYX = Storage** · **Magnate = Revenue** · **NPM Edge = Edge** — everything else is a business function.
- No platform duplicates another's responsibility.
- No credit in commits, footers, or headers to anyone but the project owner.

---

*Cerulean · TrustOps (Technitium master orchestrator) · [Innotel Platform Stack](https://github.com/innotelinc/innotel-platform-stack)*
