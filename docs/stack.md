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
- Technitium DNS Server — DNS, DHCP, blocking backend (bundled via `technitium/dns-server`, or remote via `TECHNITIUM_URL`). Its console signs in through Authentik itself (`scripts/technitium-sso.py`) behind the `cerulean-technitium-sso` gateway: the gateway keeps the console off the LAN, the console's own OIDC says *who* is on it.
- CRS home `https://lab.innotel.us` + regional masters (slaves register & pull replica when online; offline → `isolated-master` self-sufficient; legacy `SERVER_REGISTER_URL` still honored)

## Explicitly does NOT own

- Users and passwords (Authentik)
- Payment processing (Magnate)
- Storage (ONYX)

> **Current state:** Technitium HTTP API replaces RFC2136/nsupdate/SSH+BIND. CRS master/slave to `lab.innotel.us` + service-key bridge for other stacks. Service API mirrors domains/certs/DNS/DHCP/blocking/PKI. Default wildcard 90-day, offline-first.

## Roadmap — where Cerulean stands (17 September 2026)

**Live and verified on the deployment:**

- [x] **Trust plane is the estate's front door** — Authentik (SSO), the NPM edge,
      Technitium DNS, and Vault are the four containers that stayed up through the
      17 Sep capacity pass on `.46`; every public host in the estate resolves and
      terminates here.
- [x] **The Technitium console signs in through Authentik** — `scripts/technitium-sso.py`
      configures the console's own OIDC client (`authentik-setup.py technitium` creates
      it); `verify-sso.py` proves the whole posture end to end. The DNS/DHCP admin
      plane has no password of its own left.
- [x] **Estate hostnames provisioned through Cerulean** — `admin.distro.innotel.us`
      DNS + NPM host added (idempotent), joining `distro.` and `cp.distro.` on the
      wildcard; Olympus preview names (`*-preview.studio.olympus.innotel.us`) register
      through the service API.
- [x] **OIDC callback lists** — the estate's multi-origin apps (Distro, Zeus) now
      register every origin they answer on; Cerulean's `AUTHENTIK_*_REDIRECT_URI`
      takes the comma-separated list and provisioning is idempotent.
- [x] **Nightly disk hygiene** — `scripts/docker-cleanup.sh` (canonical here in ips,
      mirrored into every member repo) runs at 04:17 on all four docker hosts.

**Open, in priority order:**

1. **Per-tenant Technitium drift check** — a tenant-registered provider is used
      for record operations but nothing compares its zones to Cerulean's own view.
      A scheduled audit would catch a tenant whose Technitium silently diverges.
2. **Vault-first everywhere** — Monarch and Capstone still carry resolved values
      in host `.env` files (no runtime resolver yet). Cerulean could offer a
      `vault://`-resolving env-file sidecar so consumers stop storing plaintext.
3. **www aliases beyond the big three** — `WWW_ALIASES` covers capstone/olympus/
      monarch; distro and zeus apexes deserve the same 301 treatment.
4. **Renewal sweep evidence in the dashboard** — the sweep runs; its last-run
      result should be visible per certificate, not only in logs.


## Deployment — Technitium

Bundled (recommended, offline-ready):

```bash
docker compose --profile technitium up -d   # Technitium DNS+DHCP+blocking — host networking: binds :53 DNS + :67/udp DHCP directly, and its console (:5380) on loopback + the docker0 gateway only (setup.sh frees :53 by disabling systemd-resolved and re-applies TECHNITIUM_WEB_SERVICE_LOCAL_ADDRESSES; containers dial http://172.17.0.1:5380)
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
docker compose --profile vault up -d   # durable file-backed Vault: self-initialising, auto-unsealing, scoped token
```

See [vault-setup.md](vault-setup.md).

## Golden rules

- **Authentik = Identity** · **HashiCorp Vault = Secrets** · **Cerulean = Trust + Network** · **ONYX = Storage** · **Magnate = Revenue** · **NPM Edge = Edge** — everything else is a business function.
- No platform duplicates another's responsibility.
- No credit in commits, footers, or headers to anyone but the project owner.

---

*Cerulean · TrustOps (Technitium master orchestrator) · [Innotel Platform Stack](https://github.com/innotelinc/innotel-platform-stack)*

### Paid-tier groups (2026-09-18)

`scripts/authentik-setup.py` now creates **paid-tier Authentik groups**
(`PAID_GROUPS`, default `paid_users paid_pro`) at bootstrap. Magnate's Stripe
webhook is the member manager — checkout grants, cancellation/past-due
revokes, return-to-active re-grants — so every consumer that reads the
`groups` claim (Distro entitlements, Olympus quotas, Jellyfin's LDAP filter)
follows revenue without per-service wiring.

Magnate's Stripe keys now live in this Vault (`cerulean/magnate/stripe`),
resolved at container start through the Zeus-style standalone resolver; the
stack's `.env` carries only `vault://` refs. `magnate` was added to
`VAULT_PRODUCT_TOKENS`, so the platform mints and renews its path-scoped
token like every other product.
