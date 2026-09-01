# Cerulean ◆ DNS Management Portal

Cerulean is a self-hosted DNS management dashboard that runs an **acme-dns**
server, issues **Let's Encrypt certificates (regular and wildcard)** via DNS-01
challenges, manages **DNS records on remote BIND servers** through `nsupdate`
over SSH, and **exports certificates to nginx proxy manager** with one click.

It was built for the Innotel stack: BIND on `192.168.1.80`, nginx proxy
manager on `192.168.1.71`, and the `innotel.us` domain — but every endpoint,
credential, and zone is configurable.

```
                    ┌─────────────────────────────────────────┐
                    │              Cerulean portal            │
                    │  (dashboard + REST API, Node/TypeScript)│
                    └──────┬──────────────┬──────────┬────────┘
                           │              │          │
             SSH + nsupdate│              │HTTP API  │HTTP API (token)
               (TSIG key)  │              │          │
                           ▼              ▼          ▼
                    ┌─────────────┐  ┌───────────┐  ┌──────────────────────┐
                    │ BIND server │  │ acme-dns  │  │ nginx proxy manager  │
                    │ 192.168.1.80│  │ (port 53) │  │ 192.168.1.71:81      │
                    └─────────────┘  └───────────┘  └──────────────────────┘
                           ▲              ▲
                           └── authoritative for innotel.us / auth.innotel.us ──┘
```

## Features

- **acme-dns built in** — `docker-compose` runs an acme-dns server; Cerulean
  registers per-domain subdomains and points `_acme-challenge` CNAME records
  at them automatically.
- **Let's Encrypt certificates** — regular and **wildcard** (SAN), issued
  in-process with the ACME v2 protocol, stored with their private keys, and
  **auto-renewed** 30 days before expiry.
- **Two DNS-01 strategies** (pick one at setup time via `./scripts/setup.sh`):
  - `bind` *(default)* — challenge TXT records written straight to BIND via
    `nsupdate` with an auto-generated TSIG key. Requires BIND to be publicly
    reachable on port 53 (which it is, if it serves your zone).
  - `acme-dns` — challenge TXT records served by the acme-dns container
    (`--profile acmedns`), delegated from a subdomain of your zone. Use this
    when your authoritative DNS has no write API or isn't publicly reachable.
- **BIND record management** — create, list, and delete `A`, `AAAA`, `CNAME`,
  `TXT`, `MX`, `NS`, and `SRV` records on any zone you control, live over SSH.
- **One-click nginx proxy manager export** — import a Cerulean-issued
  certificate into NPM as a custom certificate and/or create a proxy host
  (domain → upstream host:port) with SSL, HTTP/2, and forced SSL.
- **REST API** — every dashboard action is also available as a JSON endpoint
  (see below), so you can script issuance or exports.
- **Audit log** — every domain, record, issuance, and export is recorded.

## Quick start

```bash
# One-shot setup: choose your strategy (bind or acmedns), it generates the
# admin password + TSIG key, configures BIND (and optionally acme-dns),
# installs all dependencies, builds, and starts the stack.
./scripts/setup.sh --strategy bind

# Or with acme-dns (delegated DNS-01):
./scripts/setup.sh --strategy acmedns
```

The dashboard is then at `http://<host>:3000`. The generated admin password
is printed at the end of setup (and stored in `CERULEAN_ADMIN_PASSWORD` in
`.env`).

## First-time setup

### 1. BIND (SSH + nsupdate)

`./scripts/setup.sh` runs `./scripts/setup-bind.sh` for you. It SSHs to the
BIND server and **automatically**: generates a TSIG key, installs it
(`/etc/bind/cerulean.keys` + an `include` in `named.conf`), and patches each
zone in `BIND_ZONES` with `allow-update` and `allow-transfer` — with a
backup of your config before editing and a `named-checkconf` rollback if
anything is invalid, then reloads BIND and writes the key into `.env`.

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

### 2. acme-dns (only for the `acme-dns` strategy)

`acme-dns/config.cfg` controls the acme-dns server. Set the `A` record in its
`records` list to your **public IP** — the acme-dns container must be
reachable on **UDP/TCP 53 from the internet** for Let's Encrypt validation.

Add the delegation to your public DNS (i.e. to BIND's `innotel.us` zone, or
anywhere innotel.us is served):

```dns
auth.innotel.us.   IN   NS   auth.innotel.us.
auth.innotel.us.   IN   A    <your public IP>
```

Cerulean creates the per-domain CNAME
(`_acme-challenge.innotel.us. → <uuid>.auth.innotel.us.`) automatically the
first time it issues a certificate for a domain. See
[docs/acme-dns-setup.md](docs/acme-dns-setup.md) for a full walkthrough.

> If you only use the `bind` strategy (direct nsupdate), you can skip acme-dns
> entirely.

### 3. nginx proxy manager

Set `NPM_API_URL`, `NPM_EMAIL`, and `NPM_PASSWORD` in `.env`. Cerulean
authenticates against NPM's `/api/tokens` endpoint and can then:

- import any Cerulean certificate as a **custom certificate**, and
- create **proxy hosts** that use it.

## Using Cerulean

1. **Domains** — add `innotel.us` (choose the challenge strategy). Expand a
   domain to browse and edit its records live on BIND.
2. **Certificates** — pick a domain, tick *Wildcard* for a
   `*.innotel.us` certificate, choose the strategy, and hit *Issue*. Status is
   shown live; expiry is tracked and certificates auto-renew.
3. **nginx proxy manager** — click *Export to NPM* on any issued certificate,
   or create a proxy host and select the certificate (Cerulean auto-exports it).

## REST API

All endpoints require `Authorization: Bearer <token>` (obtain a token via
`POST /api/auth/login`).

| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/auth/login` | `{ password }` → `{ token }` |
| GET | `/api/status` | Integration health + config summary |
| GET/POST/DELETE | `/api/domains[/:id]` | Manage registered domains |
| GET | `/api/domains/:id/records` | List zone records (AXFR) |
| POST/DELETE | `/api/domains/:id/records` | Add / delete a DNS record |
| GET/POST | `/api/certificates` | List certificates / start issuance |
| GET | `/api/certificates/:id` | Certificate status |
| GET | `/api/certificates/:id/material` | Fullchain PEM + private key |
| POST | `/api/certificates/:id/renew` | Renew now |
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
  -d '{"domain":"innotel.us","wildcard":true,"strategy":"acme-dns"}'

curl -s -X POST localhost:3000/api/npm/export-cert \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"certificate_id":1}'
```

## Project layout

```
server/          Express + TypeScript API (ACME, BIND/nsupdate, acme-dns, NPM)
web/             React + Vite dashboard
acme-dns/        acme-dns server configuration
scripts/         setup helpers (BIND TSIG key generation)
docs/            deeper setup guides
data/            runtime data (SQLite DB, gitignored)
```

## Security notes

- Real credentials live only in `.env`, which is **gitignored** — never commit
  them. `.env.example` holds placeholders.
- The acme-dns API port (4443) should be firewalled to your network; only
  UDP/TCP **53** needs to be public.
- Change the NPM and BIND passwords if they have ever been shared in chat or
  logs. Prefer SSH keys over passwords for BIND.

## License

MIT — see [LICENSE](LICENSE).
