# Secret vault (HashiCorp Vault)

Cerulean integrates with **HashiCorp Vault** (KV v2 engine) in two ways:

1. **Secret mirroring** — certificate private keys, ACME account keys and the
   root CA are copied into Vault on a schedule and on demand
   (`POST /api/vault/sync`), so sensitive material exists off-host.
2. **`vault://` references** — any `.env` value may be a
   `vault://<path>#<key>` reference instead of plaintext. The server resolves
   it at use time (NPM password, Technitium token, ...).

## Enabling

The stack ships a **durable, file-backed Vault** that needs no manual setup:

```bash
docker compose --profile vault up -d
```

`scripts/vault-entrypoint.sh` is the vault container's entrypoint and, on every
start:

1. starts Vault on the `file` storage backend — `./data/vault/file`
2. initialises it once (`vault operator init`) — the single unseal key and the
   **root** token are written to `./data/vault/init/init.json` (mode 600)
3. unseals it (Vault re-seals itself on every restart)
4. enables KV v2 at `VAULT_PREFIX` (default `cerulean`)
5. writes the `cerulean` policy and mints a **periodic token scoped to that
   policy** into `./data/vault/token/cerulean.token`, then renews it every 12h
6. does the same for each product named in `VAULT_PRODUCT_TOKENS`, except its
   policy covers only `<prefix>/data/<product>` — see
   [Products must not share that token](#products-must-not-share-that-token)

The app container mounts **only** `./data/vault/token` (read-only) and reads the
token through `VAULT_TOKEN_FILE`, so the root token never reaches it:

```dotenv
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=                          # empty → use the file below
VAULT_TOKEN_FILE=/vault/token/cerulean.token
VAULT_PREFIX=cerulean
# Products that get their own, narrower token — one entry per product path.
VAULT_PRODUCT_TOKENS=                 # e.g. olympus
```

Pointing at an **external** Vault works the same way: set `VAULT_ADDR` and a
scoped `VAULT_TOKEN` and leave `VAULT_TOKEN_FILE` empty (an explicit
`VAULT_TOKEN` always wins over the file).

> **Back up `./data/vault/init/`.** It holds the only unseal key and the root
> token; without it the store can never be unsealed again. The bundled server
> uses a single unseal key (`-key-shares=1`) so it can unseal unattended — for
> production, prefer a real Vault with
> [auto-unseal](https://developer.hashicorp.com/vault/docs/configuration/seal)
> (KMS/Transit) and a shorter-lived token renewed by Vault Agent.

Both mounts live under `data/`, which is **gitignored** — keys and the token are
never committed. The Vault UI/API is published on `:8200` for operators.

### Recovery

| Situation | What happens |
| --- | --- |
| Vault container restarts | Bootstraps unseals it from `init.json`; secrets and the app token survive. |
| `init.json` deleted (store still initialised) | The bootstrap refuses to start and says so, rather than destroying data. Restore the backup, or wipe `./data/vault` to start over. |
| Scoped token revoked/expired | The bootstrap mints a fresh one and logs that a running app container must be restarted (`docker compose --profile vault up -d cerulean`) to pick it up. |

## Mirroring secrets

With Vault enabled, the scheduler syncs on startup and daily, and the
**Settings → Secret vault → Sync secrets** button (or `POST /api/vault/sync`)
runs it on demand. Material is written under the configured prefix:

```
certs/<tenant>/<id>     certificate (fullchain) + private key
acme/<email>            ACME account private key
pki/ca                  private root CA (certificate + key)
pki/certs/<tenant>/<id> issued client certificate + key
```

## Policy

The bootstrap generates the policy and the app's token from it. It is scoped to
the mount prefix — no `secret/` access, and never root:

```hcl
path "cerulean/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "cerulean/metadata/*" {
  capabilities = ["read", "list"]
}
```

(`<prefix>/data/*` is the KV v2 read/write path; `<prefix>/metadata/*` is the
version metadata that listing needs.)

### Products must not share that token

`<prefix>/data/*` reaches **every** product in the mount, and secrets are only
namespaced by path — so a copy of the app's token held by one product can read
and overwrite any other's. List each product in `VAULT_PRODUCT_TOKENS`; the
bootstrap writes a same-shaped policy narrowed to its path and mints
`./data/vault/token/<product>.token` for it, renewed alongside the others:

```hcl
# what <product> gets: the same operations, one path
path "cerulean/data/<product>"       { capabilities = ["create", "read", "update", "delete", "list"] }
path "cerulean/data/<product>/*"     { capabilities = ["create", "read", "update", "delete", "list"] }
path "cerulean/metadata/<product>"   { capabilities = ["read", "list"] }
path "cerulean/metadata/<product>/*" { capabilities = ["read", "list"] }
```

There is deliberately no `list` on the mount root: that would disclose every
sibling secret's name to any product holding a token.

### Consuming it from another product or host

Copy `./data/vault/token/<product>.token` (mode 600) to the consumer and point
it here:

```dotenv
VAULT_ADDR=http://<vault-host>:8200
VAULT_TOKEN_FILE=./data/vault/token/<product>.token
VAULT_PREFIX=cerulean
```

Renewal resets the token's TTL without changing its **value**, so a copy taken
once stays valid for as long as this container runs; re-copy it only when the
bootstrap logs that it re-minted. Never hand a consumer `cerulean.token`.

## vault:// references in .env

```dotenv
NPM_PASSWORD=vault://cerulean/npm#password
TECHNITIUM_TOKEN=vault://cerulean/technitium#token
```

Create the secrets with the Vault CLI:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=$(python3 -c "import json;print(json.load(open('data/vault/init/init.json'))['root_token'])")
vault kv put cerulean/npm password='the-real-password'
vault kv put cerulean/technitium token='the-technitium-api-token'
```

`vault://<path>` without `#key` returns the first value of the secret. The
`/status` endpoint and the Settings page show Vault connectivity; failures to
resolve a reference surface as a clear error when the credential is used.
