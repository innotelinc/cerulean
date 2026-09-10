<div align="center">

# 🔵 Cerulean

**Authentication, secrets & trust management — self-hosted.**

*One login for the whole platform — DNS, DHCP, certificates, ad-blocking, secrets, and identity in one place.*

[![CI](https://github.com/innotelinc/cerulean/actions/workflows/ci.yml/badge.svg)](https://github.com/innotelinc/cerulean/actions/workflows/ci.yml)
[![Conformity](https://github.com/innotelinc/cerulean/actions/workflows/conform.yml/badge.svg)](https://github.com/innotelinc/cerulean/actions/workflows/conform.yml)
[![Release](https://github.com/innotelinc/cerulean/actions/workflows/release.yml/badge.svg)](https://github.com/innotelinc/cerulean/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/innotelinc/cerulean)](https://innotelinc.github.io/cerulean/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

---

## Why Cerulean

| Problem | Cerulean answer |
| --- | --- |
| Identity, secrets, and trust scattered across platforms | One stack: Authentik SSO + Infisical secrets + Cerulean DNS/TLS/PKI, all in one place |
| Every platform running its own login | Cerulean Authentik is the single identity source; disable a user and they lose every platform |
| Per-platform TLS lifecycle | Cerulean issues ACME certificates + DNS records; NPM Edge fronts public hosts only |
| Secrets committed to .env or repos | Infisical is the only secrets store; .env is derived and gitignored |
| Recovery after a host loss is manual | Cerulean stores DNS + PKI + secrets; re-provision a host and the trust plane is recoverable |
| Box must work offline / anywhere | Master orchestrator: DHCP, DNS, 90-day wildcard (*.<serverId>.lab.innotel.us) and ad-blocking without internet |

> **About Cerulean** — the self-hosted **authentication & trust stack** for the Innotel
> platform: **Authentik** (single sign-on — every platform login goes through Cerulean),
> **Infisical** (secret management), certificate lifecycles and DNS automation written
> straight into **Technitium DNS Server** via HTTP API (regular + wildcard Let's Encrypt via DNS-01),
> an **internal PKI** with mTLS device enrollment, **DHCP** and **ad-blocking** from the same DNS,
> discovery and health scoring, a secret vault,
> and multi-tenant isolation — **self-sufficient** with a 90-day wildcard
> (`*.<serverId>.lab.innotel.us` / `<serverId>.lab.innotel.us`) that works offline and
> is upgraded to ACME when online. nginx proxy manager wired with zero clicks.
> **Landing page:** [innotelinc.github.io/cerulean](https://innotelinc.github.io/cerulean)

---

Cerulean centralizes certificate lifecycles, DNS automation, and device trust in
one self-hosted platform. It issues **Let's Encrypt certificates (regular and
wildcard)** via DNS-01 challenges written straight into **Technitium DNS Server**
over HTTP API (`/api/zones/records/*`), manages **DNS records live on Technitium**,
runs **DHCP scopes** and **ad-blocking** from the same server, and pushes
**certificates to nginx proxy manager** with zero clicks. Without internet it still
serves DNS/DHCP and a **90-day wildcard PKI certificate** for its own
`<serverId>.lab.innotel.us`; when online that wildcard is upgraded to Let's Encrypt
via the same Technitium DNS-01 flow. It runs its own
**internal PKI** for device certificates and mTLS auto-allow, discovers
certificates across your environment, audits DNS health, scores certificate
health, mirrors secrets into a **vault**, signs users in through **Authentik**,
and scopes everything per **organization/tenant**. On a fresh host it even
provisions every nginx proxy host automatically — the stack is wired before you
open a browser.

Each installation gets a stable **`<serverId>`** (e.g. `srv-a3f9-4821`) at first boot.
Its default zone is `<serverId>.lab.innotel.us` with wildcard `*.<serverId>.lab.innotel.us`;
if `SERVER_REGISTER_URL` is set it registers there on boot (best-effort, offline-tolerant).
Set `CERULEAN_SERVER_ID` in `.env` for a pre-assigned ID.

The reference deployment routes `*.cerulean.innotel.us` through nginx proxy
manager to the portal and its services — but every endpoint, credential, and
zone is configurable.

## Capabilities

| | | |
| --- | --- | --- |
| 🪪 **Single sign-on (Authentik)** | One login for every platform — OIDC authorization-code + PKCE, passkeys (WebAuthn), groups/roles; all platform logins route through Cerulean. |
| 🔑 **Secret management (Infisical)** | Central secret store for the whole stack; `.env` values may be `infisical://path#key` references; mirrors into the vault. |
| 🔐 **ACME certificates** | Let's Encrypt, regular + **wildcard**, DNS-01 via Technitium HTTP API. Auto-renewed 30 days before expiry. Default wildcard `*.<serverId>.lab.innotel.us` is 90-day PKI offline, upgraded to ACME when online. | 
| 🌐 **Live DNS management** | Create/list/delete `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `NS`, `SRV`, `CAA`, `PTR` records on zones you control via Technitium API — routed to **the tenant's own Technitium** when one is registered. |
| 📡 **DHCP (Technitium)** | Scopes, leases and reservations on the same Technitium — Cerulean is the LAN's DHCP orchestrator. |
| 🚫 **Ad-blocking (Technitium)** | Global toggle, block-list URLs, and per-domain allow/block — all via Technitium. |
| 🔒 **Plug-anywhere / offline-first** | If the platform is running it can be the master orchestrator — DNS, DHCP, certs, blocking — without internet. Server ID + wildcard cert make it self-sufficient. |
| 🛡 **Internal PKI** | Private root CA issuing **per-device TLS client certificates** (ECDSA P-256, `clientAuth`) — revoke instantly, re-issue freely. Also mints the 90-day server wildcard. |
| 📱 **Device trust** | Devices enroll with keys that never leave them (CSR signing) or via MDM-pushed Apple profiles (root CA + SCEP). nginx **auto-allows** any device holding a Cerulean certificate. |
| 🏢 **Multi-tenant** | Certificates, domains, PKI, and vault secrets scoped per organization. Tenants can bring their **own Technitium servers**; tenant identity rides on Authentik groups; platform admins manage tenants in the dashboard. |
| ⇄ **nginx proxy manager** | One-click cert export, automatic attach on issue/renew, and full proxy-host provisioning on a fresh host. |
| ⌕ **Discovery & audit** | Sweep NPM and local PEM directories into a central inventory; audit NS delegation, SOA, propagation, and CAA per domain. |
| 💯 **Health scoring** | Every issued and discovered certificate gets a 0–100 score and A–F grade across validity, key strength, algorithm, SANs, material. |
| 🔑 **Secret vault** | Private keys mirrored to HashiCorp Vault (KV v2); `.env` values may be `vault://path#key` references. |
| 🪪 **Authentik SSO** | OIDC authorization-code + PKCE sign-in; passkeys (WebAuthn) provisioned by script; users/groups managed in Authentik. |
| ⚙️ **REST API** | Every dashboard action is a JSON endpoint — script issuance, exports, and administration. |

## Quick start

```bash
# One-shot setup: generates the admin password, ensures Technitium, installs
# dependencies, builds, starts the stack, and provisions every nginx proxy
# manager proxy host (if NPM_* is configured in .env).
./scripts/setup.sh

# Bundled Technitium (authoritative DNS + DHCP + blocking) — offline-ready
docker compose --profile technitium up -d
# With the full auth & trust stack provisioned automatically
# (Authentik SSO + Infisical secrets + Vault — set INFISICAL_ADMIN_PASSWORD
# in .env to also import stack secrets into Infisical):
./scripts/setup.sh --with-authentik
```

The portal is then at `http://<host>:3000` (or `https://<serverId>.lab.innotel.us`
once the Technitium zone + wildcard are active and a proxy host is provisioned).
The generated admin password is printed at the end of setup (and stored in
`CERULEAN_ADMIN_PASSWORD` in `.env`). Authentik and Infisical are **the stack's
auth & secrets layer** — every platform login and every secret reference
routes through Cerulean.

Auth & trust compose profiles (each opt-in):

```bash
docker compose --profile authentik up -d                     # Authentik SSO — one login for every platform
docker compose -f docker-compose.yml -f compose.infisical.yml \
             --profile infisical up -d                       # Infisical secret management
docker compose --profile vault up -d                         # dev-mode HashiCorp Vault
# DNS/DHCP/blocking plane:
docker compose --profile technitium up -d                    # Technitium DNS + DHCP + ad-blocking (recommended)
# Edge:
docker compose --profile npm up -d                           # bundled NPM Edge (NPM_MODE=local)
```

## How it works

```
                    ┌─────────────────────────────────────────┐
                    │              Cerulean portal            │
                    │  (dashboard + REST API, Node/TypeScript)│
                    │  master orchestrator: DHCP · DNS · PKI  │
                    └────────────┬──────────────┬─────────────┘
                                 │              │
                 HTTP API (token)│              │ HTTP API (token)
                                 ▼              ▼
                    ┌─────────────────┐    ┌──────────────────────┐
                    │ Technitium DNS  │    │ nginx proxy manager  │
                    │ :53 · :5380     │    │ 192.168.1.71:81      │
                    │ DHCP :67 · block│    └──────────────────────┘
                    └─────────────────┘               ▲
                           ▲                          │
                           └── authoritative for <serverId>.lab.innotel.us ──┘
                    wildcard *.<serverId>.lab.innotel.us (PKI 90d → ACME when online)
```

## Documentation

| Guide | What it covers |
| --- | --- |
| [Device enrollment & mTLS](docs/device-enrollment.md) | Internal CA, CSR + SCEP/MDM enrollment, nginx auto-allow, Authentik passkeys |
| [First-time setup](#first-time-setup) | Technitium, server identity, nginx proxy manager, the proxy-host map |
| [Using Cerulean](#using-cerulean) | Domains, certificates, DHCP, blocking, discovery, PKI — day to day |
| [REST API](#rest-api) | Every endpoint, with examples |
| [Multi-tenant (SSO)](#multi-tenant-sso) | Organizations, Authentik groups, isolation model |
| [Authentik (SSO)](#authentik-sso) | Provisioning the provider + passkeys |
| [Secret vault](#secret-vault) | Mirroring and `vault://` references |

---

## First-time setup

### 1. Technitium DNS Server (HTTP API) — DHCP & ad-blocking included

Cerulean's DNS plane is now **Technitium** over HTTP API — no SSH, no TSIG, no `nsupdate`.

- **Bundled (recommended):** `docker compose --profile technitium up -d` runs
  `technitium/dns-server` as `cerulean-technitium` (ports 53/tcp+udp, 5380 for
  the web console, 67/udp for DHCP). Cerulean reaches it at
  `http://cerulean-technitium:5380`. Set `TECHNITIUM_ADMIN_PASSWORD` in `.env`
  for the web console password; `TECHNITIUM_TOKEN` for an API token
  (or use `TECHNITIUM_USER`/`TECHNITIUM_PASSWORD`). The container stores
  state in `./data/technitium` (`/etc/dns`).
- **Remote:** point `TECHNITIUM_URL` at your Technitium (e.g. `http://10.0.0.5:5380`)
  and set `TECHNITIUM_TOKEN` (create under Settings → API Tokens) or
  `TECHNITIUM_USER`/`TECHNITIUM_PASSWORD`.

DNS-01 for Let's Encrypt is fully automatic: Cerulean writes `_acme-challenge`
TXT records via `/api/zones/records/add`, waits for Technitium to serve them,
then cleans up. Tenants that register their own Technitium under **DNS Providers**
have their zones run against that tenant's server.

**Server identity & offline wildcard.** On first boot Cerulean mints a stable
`<serverId>` (or uses `CERULEAN_SERVER_ID` from `.env`) and owns
`<serverId>.lab.innotel.us` + `*.<serverId>.lab.innotel.us`. A 90-day wildcard
is issued immediately from the **internal PKI** (works offline) and attached to NPM;
when online it is upgraded to a public Let's Encrypt cert via Technitium DNS-01.
Change the lab suffix with `CERULEAN_LAB_DOMAIN`; optionally register with
`SERVER_REGISTER_URL` (POST `{serverId, apex, wildcard}`) for central inventory.

**DHCP & ad-blocking** are toggled in Orchestrator. DHCP scopes live in Technitium
(`Scope name`, range, subnet, router, DNS); ad-blocking uses Technitium's
block lists + per-domain block/allow zones. Both work without internet once
configured.

### 2. nginx proxy manager

- **`NPM_MODE=remote`** (default) — drive an existing external NPM server via its API.
- **`NPM_MODE=local`** — use the bundled NPM Edge from `../npm/compose.cerulean.yml`
  (NPM + MariaDB + backup-ui). Start with `docker compose --profile npm up -d`.
  Cerulean talks to it at `http://cerulean-npm:81`.

Set `NPM_EMAIL` and `NPM_PASSWORD` in `.env`. In remote mode also set
`NPM_API_URL`. Set `NPM_FORWARD_HOST` (portal host's LAN IP, auto-detected if blank).
`./scripts/setup.sh` runs `./scripts/npm-proxy-hosts.py` automatically when NPM is configured.

### 3. nginx proxy manager proxy hosts (the map)

One subdomain per service. `scripts/npm-proxy-hosts.py` creates any missing
host and updates any that drifted (an already-attached certificate is always
preserved):

| Proxy host (subdomain) | Upstream scheme | Upstream host | Upstream port | Purpose |
| --- | --- | --- | --- | --- |
| `cerulean.innotel.us` | `http` | `NPM_FORWARD_HOST` (portal LAN IP) | **3000** | Cerulean dashboard + REST API |
| `app.cerulean.innotel.us` | `http` | `NPM_FORWARD_HOST` | **3000** | Cerulean application |
| `api.cerulean.innotel.us` | `http` | `NPM_FORWARD_HOST` | **3000** | Cerulean REST API |
| `auth.cerulean.innotel.us` | `http` | `NPM_FORWARD_HOST` | **9000** | Authentik (SSO / user management) |
| `dns.cerulean.innotel.us` | `http` | `NPM_FORWARD_HOST` | **3000** | DNS management |
| `certs.cerulean.innotel.us` | `http` | `NPM_FORWARD_HOST` | **3000** | Certificate management |
| `admin.cerulean.innotel.us` | `http` | `NPM_FORWARD_HOST` | **3000** | Administration |

For the subdomains to resolve, add `A` records pointing at the NPM host's IP —
set `NPM_HOST_IP` in `.env` and `npm-proxy-hosts.py` creates them via Technitium API,
or create them in Cerulean under Domains → Records.

By default hosts are created without SSL (`certificate_id: 0`). The moment you
issue a certificate for a provisioned host's domain, Cerulean **automatically imports it into NPM and attaches it**. A
wildcard certificate for `*.innotel.us` (or `*.<serverId>.lab.innotel.us`) is attached to every matching subdomain
host as well, but never replaces a certificate a host already has.

## Using Cerulean

1. **Orchestrator** — check Technitium reachability, server identity (`<serverId>.lab.innotel.us`), wildcard cert (PKI/ACME), DHCP scopes & leases, and ad-blocking in one place; register or rotate the wildcard there.
2. **Domains** — add a zone (auto-created on Technitium). Expand to browse and edit records live via API, or hit *Audit DNS*.
3. **Certificates** — pick a domain or leave empty for the default `*.<serverId>.lab.innotel.us` (90-day PKI, offline), tick *Wildcard*, and hit *Issue*. ACME uses Technitium DNS-01; each cert carries a health score (0–100, A–F).
4. **Discovery & Audit** — scan for certificates that exist on nginx proxy manager or in local PEM directories, review their health, and run DNS audits for every registered domain.
5. **nginx proxy manager** — proxies are provisioned automatically by `setup.sh`; once a certificate is issued for a host's domain it is attached automatically. *Export to NPM* is still there for manual exports.
6. **PKI & Devices** — initialize the root CA, issue a device certificate (or enroll via CSR/MDM), download material or an enrollment profile, and revoke instantly.
7. **Tenants** *(platform admins)* — create/rename organizations and view their members live from Authentik.
8. **Settings** — orchestrator posture, integration health, vault sync, renewal sweep, and configuration summary.

## Multi-tenant (SSO)

Every certificate, domain, and vault secret is scoped to an **organization
(tenant)**. Tenant identity rides on Authentik groups: a tenant's slug is a
group, and group members see only their tenant's data. Send
`X-Cerulean-Tenant: <slug>` to switch among the tenants you belong to. Local
admin sessions (or members of the `TENANT_PLATFORM_GROUP` group) are platform
admins who manage tenants from the **Tenants** page or `GET/POST /api/tenants`.
Existing single-tenant data lives in the built-in `default` tenant — upgrading
requires no migration work.

**Per-tenant DNS providers.** A tenant that runs its own Technitium can register it
under **DNS Providers** (URL + API token or user/password; secrets are
write-only). Record operations on the tenant's zones run against its **default**
provider; tenants with no provider fall back to the platform-level Technitium from
`.env`, so nothing breaks when a provider is removed.

## REST API

All endpoints require `Authorization: Bearer <token>` (obtain a token via
`POST /api/auth/login`). Tenant-owned data (domains, certificates, PKI,
discovery) is scoped to your tenant.

| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/auth/login` | `{ password }` → `{ token }` |
| GET | `/api/auth/config` | Public — auth methods available (local + OIDC) |
| GET | `/api/auth/me` | Current session user + tenant context |
| GET | `/api/auth/oidc/authorize` · `/callback` | Authentik sign-in flow |
| GET | `/api/status` | Integration health + config summary (Technitium, DHCP, blocking, server) |
| GET/POST | `/api/server/identity` | Server identity (GET) / update `serverId`/`labDomain` (POST) |
| POST | `/api/server/register` | Register `<serverId>` with `SERVER_REGISTER_URL` (offline-tolerant) |
| POST | `/api/server/wildcard/renew` | Ensure/rotate wildcard (PKI → ACME upgrade) |
| GET | `/api/orchestrator/status` | Full orchestrator status (DNS, DHCP, blocking) |
| GET | `/api/discovery/certificates` | Discovered certificate inventory |
| POST | `/api/discovery/scan` | Run a discovery sweep |
| GET | `/api/audit/dns` · `/api/audit/dns/history` | DNS health audits |
| GET | `/api/certificates/:id/health` | Certificate health breakdown |
| POST | `/api/vault/sync` | Mirror secrets into the vault |
| GET/POST/DELETE | `/api/domains[/:id]` | Manage registered domains (Technitium zones) |
| GET/POST/PATCH/DELETE | `/api/dns/providers[/:id]` | Per-tenant Technitium providers (secrets write-only) |
| GET | `/api/domains/:id/records` | List zone records (Technitium API) |
| POST/DELETE | `/api/domains/:id/records` | Add / delete a DNS record (Technitium) |
| GET/POST | `/api/dhcp/scopes` | List / create DHCP scopes |
| DELETE/POST | `/api/dhcp/scopes/:name` | Delete / enable / disable a scope |
| GET | `/api/dhcp/leases` | DHCP leases |
| POST/DELETE | `/api/dhcp/scopes/:name/reserved` | Reserved leases |
| GET/POST | `/api/blocking/status` · `/api/blocking` | Blocking status / toggle + block-list URLs |
| GET/POST/DELETE | `/api/blocking/blocked` | Per-domain block list |
| GET/POST/DELETE | `/api/blocking/allowed` | Per-domain allow list (exceptions) |
| POST | `/api/blocking/refresh` | Force refresh block lists |
| GET/POST | `/api/certificates` | List certificates / start issuance (empty `domain` = default `*.<serverId>.lab.innotel.us`) |
| GET | `/api/certificates/:id` | Certificate status |
| GET | `/api/certificates/:id/material` | Fullchain PEM + private key |
| POST | `/api/certificates/:id/renew` | Renew now (Technitium DNS-01) |
| GET | `/api/pki/status` | Internal CA + client-certificate status |
| POST | `/api/pki/init` | Generate the internal root CA (idempotent) |
| GET | `/api/pki/ca` | Root CA certificate (PEM, for trust install) |
| GET/POST | `/api/pki/certificates` | List client certs / issue one |
| GET | `/api/pki/certificates/:id` | Client certificate detail |
| GET | `/api/pki/certificates/:id/material` | Leaf PEM + key + root CA |
| POST | `/api/pki/certificates/:id/revoke` | Revoke a client certificate |
| POST | `/api/pki/enroll/csr` | Sign a device-generated CSR (key stays on device) |
| GET | `/api/pki/enrollment/profile` | Apple `.mobileconfig` (root CA + SCEP payload) |
| POST | `/api/npm/mtls` | Gate a proxy host behind device client certs (auto-allow) |
| GET/POST | `/api/tenants` | List / create tenants (platform admins) |
| PATCH | `/api/tenants/:id` | Rename a tenant (platform admins) |
| GET | `/api/tenants/:slug/members` | Tenant members from Authentik (platform admins) |
| GET | `/api/npm/hosts` · `/api/npm/certificates` | NPM state |
| POST | `/api/npm/export-cert` | `{ certificate_id }` → import into NPM |
| POST | `/api/npm/hosts` | Create a proxy host |
| GET | `/api/activities` | Audit log |

Example — issue a wildcard and export it (Technitium DNS-01):

```bash
TOKEN=$(curl -s -X POST localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"password":"your-admin-password"}' | jq -r .token)

# Default 90-day wildcard for this box (*.<serverId>.lab.innotel.us) — works offline (PKI)
curl -s -X POST localhost:3000/api/certificates \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{}'

# Or an explicit domain's wildcard via Technitium
curl -s -X POST localhost:3000/api/certificates \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","wildcard":true}'

curl -s -X POST localhost:3000/api/npm/export-cert \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"certificate_id":1}'
```

## Project layout

```
server/          Express + TypeScript API (Technitium HTTP API, ACME, DHCP, blocking, PKI)
web/             React + Vite dashboard (Orchestrator, Technitium, DHCP, blocking, certs)
scripts/         setup helpers (Technitium, NPM proxy provisioning)
docs/            deeper setup guides
data/            runtime data (SQLite DB, gitignored) — incl. data/technitium
```

## Authentik (SSO)

Cerulean ships Authentik as an optional compose profile:

```bash
docker compose --profile authentik up -d
./scripts/setup.sh --with-authentik   # generates client secret + provisions the provider
```

The bundled image is `ghcr.io/goauthentik/server:${AUTHENTIK_IMAGE_TAG:-2026.8.1}`
(server + worker share the same tag). Set `AUTHENTIK_IMAGE_TAG` in `.env` to
pin a different release.

The OIDC provider and application are created automatically by
`scripts/authentik-setup.py` (it logs in with `AUTHENTIK_ADMIN_USER` /
`AUTHENTIK_ADMIN_PASSWORD`). On the very first boot, create the Authentik admin
with `docker compose --profile authentik exec authentik-server ak
createsuperuser`, or set `AUTHENTIK_BOOTSTRAP_PASSWORD` before the first start.
The `auth.cerulean.innotel.us` proxy host fronts Authentik on port 9000.

Passkeys (WebAuthn) are enabled with `scripts/authentik-passkeys.py` — it
creates a WebAuthn validation stage and binds it into the default
authentication flow, so enrolled users sign in with a passkey (Community
Edition; users enroll once in their Authentik settings). See
`docs/device-enrollment.md` §5.

## Secrets — Infisical (SecretOps) and legacy Vault

Cerulean follows the [Innotel Platform Stack](https://github.com/innotelinc/innotel-platform-stack):
**Infisical** (SecretOps) is the source of truth for secrets, with the legacy HashiCorp
Vault integration kept for existing deployments.

With `INFISICAL_ADDR` / `INFISICAL_TOKEN` / `INFISICAL_WORKSPACE_ID` set (provisioned by
`scripts/infisical-setup.sh`), `.env` values can reference secrets instead of holding
plaintext:

```
NPM_PASSWORD=infisical://NPM_PASSWORD
TECHNITIUM_TOKEN=infisical://TECHNITIUM_TOKEN
```

The server also mirrors certificate private keys and ACME account keys into Infisical on
a schedule and on demand (`POST /api/vault/sync`), each under its own secret name
(`certs.<tenant>.<id>.*`, `pki.ca.*`, `acme.<email>.key`). Enable the bundled Infisical
profile with:

```bash
docker compose -f docker-compose.yml -f compose.infisical.yml --profile infisical up -d
bash scripts/infisical-setup.sh
```

Legacy deployments can keep using Vault: with `VAULT_ADDR` and `VAULT_TOKEN` set, the
server mirrors the same material into Vault (KV v2) and resolves `vault://path#key`
references (a dev-mode Vault ships as `docker compose --profile vault up -d`).

## Release pipeline

Every `v*` tag triggers the release workflow: tests + typecheck on every
push/PR (`ci.yml`), a multi-arch Docker image published to GHCR, and a GitHub
release with release artifacts.

## Security notes

- Real credentials live only in `.env`, which is **gitignored** — never commit
  them. `.env.example` holds placeholders. Prefer `vault://`/`infisical://` references.
- `scripts/npm-proxy-hosts.py` reads `NPM_*`/`TECHNITIUM_*` from `.env` and talks to
  NPM/Technitium APIs with short-lived tokens; it never writes credentials anywhere.
- Change the NPM and Technitium passwords if they have ever been shared in chat or logs.

## License

MIT — see [LICENSE](LICENSE).

## 🏛️ Platform stack

Cerulean is the ecosystem's **TrustOps** platform — certificate lifecycle, DNS automation, DHCP, ad-blocking, PKI, and trust scoring in the
[**Innotel Platform Stack**](https://github.com/innotelinc/innotel-platform-stack) —
where Authentik owns identity, Infisical owns secrets, Cerulean owns trust and is the
offline-first **master orchestrator** (Technitium DNS + DHCP + blocking), ONYX owns storage,
Magnate owns revenue, NPM Edge owns the edge. See
[docs/stack.md](docs/stack.md) for this platform's owns/consumes boundaries.
