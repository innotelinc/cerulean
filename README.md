<div align="center">

# 🔵 Cerulean

**Certificate, DNS & trust management — self-hosted.**

*Point DNS at it once — never touch a zone file again.*

[![CI](https://github.com/innotelinc/cerulean/actions/workflows/ci.yml/badge.svg)](https://github.com/innotelinc/cerulean/actions/workflows/ci.yml)
[![Release](https://github.com/innotelinc/cerulean/actions/workflows/release.yml/badge.svg)](https://github.com/innotelinc/cerulean/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/innotelinc/cerulean)](https://innotelinc.github.io/cerulean/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

> **About Cerulean** — the self-hosted control plane for certificate lifecycles, DNS
> automation, and device trust: Let's Encrypt issuance (regular + wildcard) written
> straight into your own BIND server, live DNS record management, an internal PKI with
> mTLS device enrollment, discovery and health scoring, a secret vault, Authentik SSO,
> and multi-tenant isolation — nginx proxy manager wired with zero clicks.
> **Landing page:** [innotelinc.github.io/cerulean](https://innotelinc.github.io/cerulean)

---

Cerulean centralizes certificate lifecycles, DNS automation, and device trust in
one self-hosted platform. It issues **Let's Encrypt certificates (regular and
wildcard)** via DNS-01 challenges written straight into **your own BIND server**
over SSH (nsupdate + TSIG), manages **DNS records live on BIND**, and pushes
**certificates to nginx proxy manager** with zero clicks. It runs its own
**internal PKI** for device certificates and mTLS auto-allow, discovers
certificates across your environment, audits DNS health, scores certificate
health, mirrors secrets into a **vault**, signs users in through **Authentik**,
and scopes everything per **organization/tenant**. On a fresh host it even
provisions every nginx proxy host automatically — the stack is wired before you
open a browser.

The reference deployment routes `*.cerulean.innotel.us` through nginx proxy
manager to the portal and its services — but every endpoint, credential, and
zone is configurable.

## Capabilities

| | | |
| --- | --- | --- |
| 🔐 **ACME certificates** | Let's Encrypt, regular + **wildcard**, DNS-01 via your own BIND over `nsupdate` + TSIG. Auto-renewed 30 days before expiry. | 
| 🌐 **Live DNS management** | Create/list/delete `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `NS`, `SRV` records on zones you control, straight over SSH — routed to **the tenant's own DNS provider** when one is registered. |
| 🛡 **Internal PKI** | Private root CA issuing **per-device TLS client certificates** (ECDSA P-256, `clientAuth`) — revoke instantly, re-issue freely. |
| 📱 **Device trust** | Devices enroll with keys that never leave them (CSR signing) or via MDM-pushed Apple profiles (root CA + SCEP). nginx **auto-allows** any device holding a Cerulean certificate. |
| 🏢 **Multi-tenant** | Certificates, domains, PKI, and vault secrets scoped per organization. Tenants can bring their **own BIND servers**; tenant identity rides on Authentik groups; platform admins manage tenants in the dashboard. |
| ⇄ **nginx proxy manager** | One-click cert export, automatic attach on issue/renew, and full proxy-host provisioning on a fresh host. |
| ⌕ **Discovery & audit** | Sweep NPM and local PEM directories into a central inventory; audit NS delegation, SOA, propagation, and CAA per domain. |
| 💯 **Health scoring** | Every issued and discovered certificate gets a 0–100 score and A–F grade across validity, key strength, algorithm, SANs, material. |
| 🔑 **Secret vault** | Private keys mirrored to HashiCorp Vault (KV v2); `.env` values may be `vault://path#key` references. |
| 🪪 **Authentik SSO** | OIDC authorization-code + PKCE sign-in; passkeys (WebAuthn) provisioned by script; users/groups managed in Authentik. |
| ⚙️ **REST API** | Every dashboard action is a JSON endpoint — script issuance, exports, and administration. |

## Quick start

```bash
# One-shot setup: generates the admin password + TSIG key, configures BIND,
# installs dependencies, builds, starts the stack, and provisions every nginx
# proxy manager proxy host (if NPM_* is configured in .env).
./scripts/setup.sh

# Or with Authentik SSO provisioned automatically:
./scripts/setup.sh --with-authentik
```

The dashboard is then at `http://<host>:3000` (or `https://cerulean.innotel.us`
once the proxy host is provisioned and a certificate is attached). The generated
admin password is printed at the end of setup (and stored in
`CERULEAN_ADMIN_PASSWORD` in `.env`).

Optional compose profiles, each opt-in:

```bash
docker compose --profile bind --profile npm up -d  # local BIND + bundled NPM Edge (BIND_MODE=local, NPM_MODE=local)
docker compose --profile bind up -d                # bundled BIND only (BIND_MODE=local)
docker compose --profile authentik up -d   # Authentik SSO + user management
docker compose --profile vault up -d       # dev-mode HashiCorp Vault
```

## How it works

```
                    ┌─────────────────────────────────────────┐
                    │              Cerulean portal            │
                    │  (dashboard + REST API, Node/TypeScript)│
                    └────────────┬──────────────┬─────────────┘
                                 │              │
                  SSH + nsupdate │              │ HTTP API (token)
                    (TSIG key)   │              │
                                 ▼              ▼
                    ┌─────────────┐        ┌──────────────────────┐
                    │ BIND server │        │ nginx proxy manager  │
                    │ 192.168.1.80│        │ 192.168.1.71:81      │
                    └─────────────┘        └──────────────────────┘
                           ▲
                           └── authoritative for innotel.us ──┘
```

## Documentation

| Guide | What it covers |
| --- | --- |
| [Device enrollment & mTLS](docs/device-enrollment.md) | Internal CA, CSR + SCEP/MDM enrollment, nginx auto-allow, Authentik passkeys |
| [First-time setup](#first-time-setup) | BIND, nginx proxy manager, the proxy-host map |
| [Using Cerulean](#using-cerulean) | Domains, certificates, discovery, PKI — day to day |
| [REST API](#rest-api) | Every endpoint, with examples |
| [Multi-tenant (SSO)](#multi-tenant-sso) | Organizations, Authentik groups, isolation model |
| [Authentik (SSO)](#authentik-sso) | Provisioning the provider + passkeys |
| [Secret vault](#secret-vault) | Mirroring and `vault://` references |

---

## First-time setup

### 1. BIND (SSH + nsupdate)

Two modes, picked with `BIND_MODE` in `.env`:

- **`BIND_MODE=remote`** (default) — point at an existing BIND server. This
  is what the rest of this section describes.
- **`BIND_MODE=local`** — run the **bundled BIND + sshd container** from this
  stack: `docker compose --profile bind up -d`. Cerulean reaches it at the
  compose service name `cerulean-bind` over SSH, exactly like a remote box
  (nsupdate + TSIG, dig AXFR). On first start the container generates its
  TSIG key and root SSH password and prints them to its logs — copy them into
  `BIND_TSIG_SECRET` / `BIND_SSH_PASSWORD` in `.env` (or set them before
  starting). Zones come from `BIND_ZONES` / `CERULEAN_ZONE`.

For `BIND_MODE=remote`, `./scripts/setup.sh` runs `./scripts/setup-bind.sh`
for you. It SSHs to the BIND server and **automatically**: generates a TSIG
key, installs it (`/etc/bind/cerulean.keys` + an `include` in `named.conf`),
and patches each zone in `BIND_ZONES` with `allow-update` and
`allow-transfer` — with a backup of your config before editing and a
`named-checkconf` rollback if anything is invalid, then reloads BIND and
writes the key into `.env`.

What it needs from you: `.env` with `BIND_SSH_HOST`, `BIND_SSH_USER` and
(`BIND_SSH_KEY_PATH` or `BIND_SSH_PASSWORD`), plus the ability for the portal
host to reach BIND over SSH. If you'd rather configure BIND by hand, the
three things it adds are:

```named
key "cerulean" { algorithm hmac-sha256; secret "<generated>"; };
```

```named
allow-update { key "cerulean"; };        /* in each managed zone */
allow-transfer { <portal-ip>; };          /* so Cerulean can list records (AXFR) */
```

### 2. nginx proxy manager

Two modes, picked with `NPM_MODE` in `.env`:

- **`NPM_MODE=remote`** (default) — drive an existing external NPM server via its API. This is the only supported NPM mode when `BIND_MODE=remote`.
- **`NPM_MODE=local`** — available only with `BIND_MODE=local`; it enables the complete NPM Edge component from the sibling `npm/` repository: NPM, MariaDB, and `backup-ui`. Start both opt-in profiles together with `docker compose --profile bind --profile npm up -d`. Cerulean talks to NPM at `http://cerulean-npm:81`; host-side provisioning uses the local admin port.

For local mode, the NPM component is imported from `../npm/compose.cerulean.yml`; it includes MariaDB and `backup-ui`, and persists its state in the NPM repository's `data/`, `mysql/`, `letsencrypt/`, and `backups/` directories. Do not use the local profile with a remote BIND server.

Set `NPM_EMAIL` and `NPM_PASSWORD` in `.env`. In remote mode also set
`NPM_API_URL` to the external NPM API. In local mode, Cerulean uses
`http://cerulean-npm:81` internally and the host-side provisioner uses the
configured local admin port. Set `NPM_FORWARD_HOST` (the portal host's LAN IP,
as seen from NPM — auto-detected if blank). Cerulean authenticates against NPM's
`/api/tokens` endpoint and can then:

- import any Cerulean certificate as a **custom certificate**, and
- create **proxy hosts** that use it.

`./scripts/setup.sh` runs `./scripts/npm-proxy-hosts.py` automatically when
NPM is configured, so a fresh host comes up with every proxy host already
created.

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

For the subdomains to resolve, add an A record per row pointing at the NPM
host's IP — set `NPM_HOST_IP` in `.env` and `npm-proxy-hosts.py` creates them
on BIND automatically (requires `BIND_SSH_*` + `BIND_TSIG_SECRET`), or create
them in Cerulean under Domains → Records.

To add another service, append an entry to `PROXY_HOSTS` in
`scripts/npm-proxy-hosts.py` and re-run it.

By default hosts are created without SSL (`certificate_id: 0`). The moment you
issue a certificate for `cerulean.innotel.us` (or any provisioned host's
domain), Cerulean **automatically imports it into NPM and attaches it to the
matching proxy host** — renewals refresh the same NPM certificate in place. A
wildcard certificate for `*.innotel.us` is attached to every matching subdomain
host (e.g. `cerulean.innotel.us`) as well, but never replaces a certificate a
host already has — set `NPM_WILDCARD_ATTACH=0` in `.env` to restrict attaches
to exact-domain matches. If you'd rather have NPM request its own Let's Encrypt
certificate via HTTP-01, set `NPM_PROXY_SSL=1` instead.

## Using Cerulean

1. **Domains** — add `innotel.us`. Expand a domain to browse and edit its
   records live on BIND, or hit *Audit DNS* to run a health audit (NS
   delegation, SOA consistency, propagation, CAA).
2. **Certificates** — pick a domain, tick *Wildcard* for a
   `*.innotel.us` certificate, and hit *Issue*. Status is
   shown live; expiry is tracked and certificates auto-renew. Each certificate
   carries a **health score** (0–100, A–F) covering validity, key strength,
   signature algorithm, and SAN coverage.
3. **Discovery & Audit** — scan for certificates that exist on nginx proxy
   manager or in local PEM directories, review their health, and run DNS
   audits for every registered domain from one page.
4. **nginx proxy manager** — proxies are provisioned automatically by
   `setup.sh`; once a certificate is issued for a host's domain it is attached
   to the host automatically (wildcards cover matching subdomains). The
   *Export to NPM* button is still there for manual exports.
5. **PKI & Devices** — initialize the root CA, issue a device certificate (or
   enroll one with a CSR so its key never leaves the device), download
   material or an MDM enrollment profile, and revoke instantly — see
   `docs/device-enrollment.md` for the full MDM/SCEP/mTLS runbook.
6. **Tenants** *(platform admins)* — create/rename organizations and view
   their members live from Authentik.
7. **Settings** — integration health, vault sync, renewal sweep, and a
   full configuration summary.

## Multi-tenant (SSO)

Every certificate, domain, and vault secret is scoped to an **organization
(tenant)**. Tenant identity rides on Authentik groups: a tenant's slug is a
group, and group members see only their tenant's data. Send
`X-Cerulean-Tenant: <slug>` to switch among the tenants you belong to. Local
admin sessions (or members of the `TENANT_PLATFORM_GROUP` group) are platform
admins who manage tenants from the **Tenants** page or `GET/POST /api/tenants`.
Existing single-tenant data lives in the built-in `default` tenant — upgrading
requires no migration work.

**Per-tenant DNS providers.** A tenant that runs its own BIND can register it
under **DNS Providers** (SSH endpoint, auth, and TSIG key; secrets are
write-only and never leave the server). Record operations on the tenant's
zones — AXFR listing and nsupdate adds/deletes — run against its **default**
provider; tenants with no provider fall back to the platform-level BIND from
`.env`, so nothing breaks when a provider is removed.

## REST API

All endpoints require `Authorization: Bearer <token>` (obtain a token via
`POST /api/auth/login`). Tenant-owned data (domains, certificates, PKI,
discovery) is scoped to your tenant: members of an Authentik group whose slug
matches a tenant see only that tenant's data, platform admins operate on the
`default` tenant by default and send `X-Cerulean-Tenant: <slug>` to act in
another.

| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/auth/login` | `{ password }` → `{ token }` |
| GET | `/api/auth/config` | Public — auth methods available (local + OIDC) |
| GET | `/api/auth/me` | Current session user + tenant context |
| GET | `/api/auth/oidc/authorize` · `/callback` | Authentik sign-in flow |
| GET | `/api/status` | Integration health + config summary |
| GET | `/api/discovery/certificates` | Discovered certificate inventory |
| POST | `/api/discovery/scan` | Run a discovery sweep |
| GET | `/api/audit/dns` · `/api/audit/dns/history` | DNS health audits |
| GET | `/api/certificates/:id/health` | Certificate health breakdown |
| POST | `/api/vault/sync` | Mirror secrets into the vault |
| GET/POST/DELETE | `/api/domains[/:id]` | Manage registered domains |
| GET/POST/PATCH/DELETE | `/api/dns/providers[/:id]` | Per-tenant BIND providers (secrets write-only) |
| GET | `/api/domains/:id/records` | List zone records (AXFR) |
| POST/DELETE | `/api/domains/:id/records` | Add / delete a DNS record |
| GET/POST | `/api/certificates` | List certificates / start issuance |
| GET | `/api/certificates/:id` | Certificate status |
| GET | `/api/certificates/:id/material` | Fullchain PEM + private key |
| POST | `/api/certificates/:id/renew` | Renew now |
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

Example — issue a wildcard certificate and export it:

```bash
TOKEN=$(curl -s -X POST localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"password":"your-admin-password"}' | jq -r .token)

curl -s -X POST localhost:3000/api/certificates \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"domain":"innotel.us","wildcard":true}'

curl -s -X POST localhost:3000/api/npm/export-cert \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"certificate_id":1}'
```

Example — issue a device TLS client certificate and download its material:

```bash
curl -s -X POST localhost:3000/api/pki/certificates \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"laptop-1","email":"admin@innotel.us"}'

curl -s localhost:3000/api/pki/certificates/1/material \
  -H "Authorization: Bearer $TOKEN"   # → { certificate, key, ca }
```

## Project layout

```
server/          Express + TypeScript API (ACME, BIND/nsupdate, NPM, PKI)
web/             React + Vite dashboard
scripts/         setup helpers (BIND TSIG key generation, NPM proxy provisioning)
docs/            deeper setup guides
data/            runtime data (SQLite DB, gitignored)
```

## Authentik (SSO)

Cerulean ships Authentik as an optional compose profile:

```bash
docker compose --profile authentik up -d
./scripts/setup.sh --with-authentik   # generates client secret + provisions the provider
```

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
BIND_SSH_PASSWORD=infisical://BIND_SSH_PASSWORD
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
references (a dev-mode Vault ships as `docker compose --profile vault up -d`):

```
NPM_PASSWORD=vault://cerulean/npm#password
BIND_SSH_PASSWORD=vault://cerulean/bind#password
```

## Release pipeline

Every `v*` tag triggers the release workflow: tests + typecheck on every
push/PR (`ci.yml`), a multi-arch Docker image published to GHCR, and a GitHub
release with release artifacts — source tarballs (full, server, web), a
software bill of materials (SPDX), and `SHA256SUMS.txt` checksums.

## Security notes

- Real credentials live only in `.env`, which is **gitignored** — never commit
  them. `.env.example` holds placeholders. Prefer `vault://` references for
  anything sensitive.
- `scripts/npm-proxy-hosts.py` reads `NPM_*` from `.env` and talks to NPM's API
  with a short-lived token; it never writes credentials anywhere.
- Change the NPM and BIND passwords if they have ever been shared in chat or
  logs. Prefer SSH keys over passwords for BIND.

## License

MIT — see [LICENSE](LICENSE).

## 🏛️ Platform stack

Cerulean is the ecosystem's **TrustOps** platform — certificate lifecycle, DNS automation, PKI, and trust scoring in the
[**Innotel Platform Stack**](https://github.com/innotelinc/innotel-platform-stack) — the
canonical single-responsibility architecture where Authentik owns identity, Infisical owns
secrets, Cerulean owns trust, ONYX owns storage, Magnate owns revenue, NPM Edge owns the edge, and every other
platform is a business function that consumes them. See
[docs/stack.md](docs/stack.md) for this platform's owns/consumes boundaries and its
Infisical secret setup.
