# Cerulean — Certificate & DNS Management

*Point DNS at it once — never touch a zone file again.*

Cerulean is a self-hosted, centralized certificate and DNS lifecycle
platform. It issues **Let's Encrypt certificates (regular and wildcard)** via
DNS-01 challenges written straight into **your own BIND server** over SSH
(nsupdate + TSIG), manages **DNS records on remote BIND servers**, and
**exports certificates to nginx proxy manager** with one click. It also
**discovers certificates**
in your environment, **audits DNS health**, **scores certificate health**,
stores secrets in a **vault**, and signs users in through **Authentik**. On a
fresh host it even **provisions every nginx proxy host automatically** — the
stack is wired up before you open a browser.

The reference deployment routes `*.cerulean.innotel.us` through nginx proxy
manager to the portal and its services — but every endpoint, credential, and
zone is configurable.

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

## Features

- **Authentik SSO** — sign in with an OIDC authorization-code + PKCE flow
  against Authentik (users/groups managed there). The stack bundles Authentik
  (`docker compose --profile authentik up -d`) and
  `scripts/authentik-setup.py` provisions the OIDC provider automatically.
  The admin password stays available as a bootstrap fallback
  (`AUTH_LOCAL_ENABLED=0` for Authentik-only).
- **Secret vault** — private keys and ACME account keys are mirrored into a
  HashiCorp Vault (KV v2) when `VAULT_ADDR` + `VAULT_TOKEN` are set, and any
  .env value may be a `vault://path#key` reference instead of plaintext.
- **Certificate discovery** — a sweep imports certificates found on nginx
  proxy manager (including ones Cerulean didn't issue) and in local PEM
  directories (`CERT_DISCOVERY_DIRS`) into a central inventory.
- **DNS health auditing** — every registered domain is audited (NS
  delegation, authoritative SOA answers, serial consistency, propagation
  across public resolvers, CAA policy) on a schedule and on demand.
- **Certificate health scoring** — every issued and discovered certificate
  gets a 0–100 score and A–F grade from its validity, key strength,
  signature algorithm, SAN coverage, and material.
- **Let's Encrypt certificates** — regular and **wildcard** (SAN), issued
  in-process with the ACME v2 protocol over DNS-01, stored with their private
  keys, and **auto-renewed** 30 days before expiry.
- **BIND-based DNS-01** — challenge TXT records are written straight to your
  authoritative BIND server via `nsupdate` with a TSIG key (auto-generated
  and installed by `./scripts/setup.sh`). No extra challenge servers needed:
- **BIND record management** — create, list, and delete `A`, `AAAA`, `CNAME`,
  `TXT`, `MX`, `NS`, and `SRV` records on any zone you control, live over SSH.
- **One-click nginx proxy manager export** — import a Cerulean-issued
  certificate into NPM as a custom certificate and/or create a proxy host
  (domain → upstream host:port) with SSL, HTTP/2, and forced SSL.
- **Automatic nginx proxy manager provisioning** — `scripts/npm-proxy-hosts.py`
  (hooked into `setup.sh`) creates or updates every proxy host on your NPM
  instance via its API, so a fresh host comes up fully routed. Idempotent:
  create what's missing, update what drifted, never touch the rest.
- **Automatic certificate attach** — the moment a certificate is issued or
  renewed for a provisioned proxy host's domain, Cerulean imports the fresh
  material into NPM and attaches it to the matching host (SSL + HTTP/2 on),
  refreshing in place on renewal — no clicks, ever. Wildcard certificates
  (`*.innotel.us`) attach to every matching subdomain host
  (`cerulean.innotel.us`) too, unless the host already has its own
  certificate (toggle with `NPM_WILDCARD_ATTACH`).
- **Internal PKI** — Cerulean runs a private root CA and issues **per-device
  TLS client certificates** (ECDSA P-256, `clientAuth` EKU) for mTLS at the
  reverse proxy and MDM-driven enrollment. The CA is created lazily on first
  issuance; certificates can be listed, re-issued after revoke, and exported
  as leaf + key + CA PEM so a device can install the trust chain.
- **Multi-tenant (organizations)** — every certificate, domain and vault
  secret is scoped to a tenant. Tenant identity rides on Authentik groups: a
  tenant's slug is a group, and group members see only their tenant's data
  (`X-Cerulean-Tenant` switches among the caller's tenants). Local admin
  sessions (or `TENANT_PLATFORM_GROUP` members) are platform admins who
  create tenants via `GET/POST /api/tenants`. Existing single-tenant data
  lives in the built-in `default` tenant — no migration work needed.
- **Device enrollment & mTLS auto-allow** — devices enroll with a key that
  never leaves them (CSR signing, `POST /api/pki/enroll/csr`) or through an
  MDM-pushed Apple profile that installs the root CA and points at your SCEP
  endpoint (`PKI_SCEP_URL`, dashboard → PKI & Devices). Flip a proxy host's
  TLS gate on (`POST /api/npm/mtls`) and nginx auto-allows any device holding
  a Cerulean-signed certificate while rejecting everything else — passkeys in
  Authentik are provisioned by `scripts/authentik-passkeys.py`. Runbook:
  `docs/device-enrollment.md`.
- **REST API** — every dashboard action is also available as a JSON endpoint
  (see below), so you can script issuance or exports.
- **Audit log** — every domain, record, issuance, and export is recorded.

## Quick start

```bash
# One-shot setup: generates the admin password + TSIG key, configures BIND,
# installs all dependencies, builds, starts the stack, and provisions every
# nginx proxy manager proxy host (if NPM_* is configured in .env).
./scripts/setup.sh

# Or with Authentik SSO provisioned automatically:
./scripts/setup.sh --with-authentik
```

The dashboard is then at `http://<host>:3000` (or `https://cerulean.innotel.us`
once the proxy host is provisioned and a certificate is attached). The
generated admin password is printed at the end of setup (and stored in
`CERULEAN_ADMIN_PASSWORD` in `.env`).

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

- **`NPM_MODE=remote`** (default) — drive an existing NPM server via its API.
- **`NPM_MODE=local`** — run the **bundled NPM container** from this stack:
  `docker compose --profile npm up -d`. Cerulean talks to it at the compose
  service name `cerulean-npm` (`NPM_INTERNAL_API_URL=http://cerulean-npm:81`
  by default); the host-side provisioning script `npm-proxy-hosts.py` uses
  `NPM_API_URL=http://localhost:81`.

Set `NPM_API_URL`, `NPM_EMAIL`, and `NPM_PASSWORD` in `.env`, plus
`NPM_FORWARD_HOST` (the portal host's LAN IP, as seen from NPM — auto-detected
if blank). Cerulean authenticates against NPM's `/api/tokens` endpoint and can
then:

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
5. **Settings** — integration health, vault sync, renewal sweep, and a
   full configuration summary.
6. **PKI & Devices** — Cerulean generates its own private root CA on first
   use and issues TLS client certificates for devices/identities, all from
   the dashboard: initialize the CA, issue a certificate (or enroll a device
   with a CSR so its key never leaves it), download material or an MDM
   enrollment profile, and revoke instantly. Install the root CA as the
   trust anchor on your endpoints (nginx `ssl_client_certificate`, browsers,
   MDM) and nginx will accept any device presenting a valid certificate —
   see `docs/device-enrollment.md` for the full MDM/SCEP/mTLS runbook.

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
| GET | `/api/auth/me` | Current session user |
| GET | `/api/auth/oidc/authorize` · `/callback` | Authentik sign-in flow |
| GET | `/api/status` | Integration health + config summary |
| GET | `/api/discovery/certificates` | Discovered certificate inventory |
| POST | `/api/discovery/scan` | Run a discovery sweep |
| GET | `/api/audit/dns` · `/api/audit/dns/history` | DNS health audits |
| GET | `/api/certificates/:id/health` | Certificate health breakdown |
| POST | `/api/vault/sync` | Mirror secrets into the vault |
| GET/POST/DELETE | `/api/domains[/:id]` | Manage registered domains |
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
server/          Express + TypeScript API (ACME, BIND/nsupdate, NPM)
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

## Secret vault

With `VAULT_ADDR` and `VAULT_TOKEN` set, the server mirrors certificate
private keys and ACME account keys into Vault (KV v2) on a schedule and on
demand (`POST /api/vault/sync`). `.env` values can also reference vault
secrets instead of holding plaintext:

```
NPM_PASSWORD=vault://cerulean/npm#password
BIND_SSH_PASSWORD=vault://cerulean/bind#password
```

A dev-mode Vault is available via `docker compose --profile vault up -d` for
self-hosted stacks — point `VAULT_ADDR` at a real Vault for production.

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
