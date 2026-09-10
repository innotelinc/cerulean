# 🔵 Cerulean — Platform Stack Role

**Classification: TrustOps — Master Orchestrator (Technitium)**

Certificate lifecycle, DNS automation, DHCP, ad-blocking, and device trust — ACME, PKI, discovery, deployment, and trust scoring for the whole ecosystem. When running, Cerulean is **self-sufficient**: Technitium DNS + DHCP + blocking + 90-day wildcard (`*.<serverId>.lab.innotel.us`) without internet; upgraded to ACME when online.

This page declares Cerulean's role in the
[**Innotel Platform Stack**](https://github.com/innotelinc/innotel-platform-stack) —
the canonical single-responsibility architecture.

## Owns

- Certificate lifecycle (ACME DNS-01 via Technitium HTTP API; default 90-day wildcard PKI offline → ACME when online)
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
- HashiCorp Vault — secrets, TLS private keys, CA keys
- Technitium DNS Server — DNS, DHCP, blocking backend (bundled via `technitium/dns-server`, or remote via `TECHNITIUM_URL`)
- CRS home `https://lab.innotel.us` + regional masters (slaves register & pull replica when online; offline → `isolated-master` self-sufficient; legacy `SERVER_REGISTER_URL` still honored)

## Explicitly does NOT own

- Users and passwords (Authentik)
- Payment processing (Magnate)
- Storage (ONYX)

> **Current state:** Technitium HTTP API replaces RFC2136/nsupdate/SSH+BIND. CRS master/slave to `lab.innotel.us` + service-key bridge for other stacks. Service API mirrors domains/certs/DNS/DHCP/blocking/PKI. Default wildcard 90-day, offline-first.

## Deployment — Technitium

Bundled (recommended, offline-ready):

```bash
docker compose --profile technitium up -d   # Technitium DNS+DHCP+blocking at http://<host>:5380 (host networking: binds :53 DNS + :67/udp DHCP directly; setup.sh frees :53 by disabling systemd-resolved)
```

Or point `TECHNITIUM_URL`/`TECHNITIUM_TOKEN` (or `TECHNITIUM_USER`/`TECHNITIUM_PASSWORD`) at a remote Technitium.

Server identity: `CERULEAN_SERVER_ID` (stable `<serverId>`, auto-generated if empty) + `CERULEAN_LAB_DOMAIN` (default `lab.innotel.us`) → zone `<serverId>.lab.innotel.us`.

## CRS — master / slave

Every Cerulean is a **CRS node** (`CRS_ROLE=auto|master|slave`). Home is `https://lab.innotel.us`.

- **auto** (default): try to be a slave to `CRS_MASTER_URL` (= `CRS_HOME_URL`); if unreachable → `isolated-master` (self-sufficient, acts as master locally, still a logical slave to home; re-syncs when online).
- **master**: must set `CRS_DOMAIN` (e.g. `lab.innotel.us`) — holds all records, assigns serverIds, rejects slaves when not authoritative. Still registers as slave to home best-effort.
- **slave**: registers to `CRS_MASTER_URL` when online, holds a full replica of every serverId.
- Air-gapped: no extra flag needed — `auto` → `isolated-master` automatically; optionally set `CRS_AIR_GAPPED=1`.

Public probe: `GET /api/crs/status` (unauthenticated). Register: `POST /api/crs/register` (Bearer `CRS_TOKEN` or `ceru_…` with `crs:register`). Replica: `GET /api/crs/registry`.

## Service API — other stacks → Cerulean

Create a service key as platform admin: `POST /api/service/keys { name, scopes, tenantId }` → `ceru_<prefix>_<secret>` (shown once). Scopes: `*`, `crs:*`, `dns:*`, `certs:*`, `domains:*`, `dhcp:read`, `blocking:read`, `pki:*`, `status`.

Bridge (Bearer `ceru_…`):

- `GET /api/service/status` · `GET /api/service/crs/*` · `POST /api/service/crs/register`
- `GET|POST /api/service/domains` · `GET|POST|DELETE /api/service/dns/records?zone=`
- `GET|POST /api/service/certificates` · `GET /api/service/certificates/:id/material`
- `GET /api/service/dhcp/*` · `GET /api/service/blocking/status` · `GET|POST /api/service/pki/*`

See Orchestrator page → *CRS* and *Service API keys* panels for live state, sync, and key management.

## Secrets (HashiCorp Vault)

```bash
docker compose --profile vault up -d   # bundled dev-mode Vault (VAULT_ADDR=http://localhost:8200, VAULT_TOKEN=cerulean-root)
```

See [vault-setup.md](vault-setup.md).

## Golden rules

- **Authentik = Identity** · **HashiCorp Vault = Secrets** · **Cerulean = Trust + Network** · **ONYX = Storage** · **Magnate = Revenue** · **NPM Edge = Edge** — everything else is a business function.
- No platform duplicates another's responsibility.
- No credit in commits, footers, or headers to anyone but the project owner.

---

*Cerulean · TrustOps (Technitium master orchestrator) · [Innotel Platform Stack](https://github.com/innotelinc/innotel-platform-stack)*
