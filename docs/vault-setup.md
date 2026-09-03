# Secret vault (HashiCorp Vault)

Cerulean integrates with **HashiCorp Vault** (KV v2 engine) in two ways:

1. **Secret mirroring** — certificate private keys and ACME account keys are
   copied into Vault on a schedule and on demand (`POST /api/vault/sync`), so
   sensitive material exists off-host.
2. **`vault://` references** — any `.env` value may be a
   `vault://<path>#<key>` reference instead of plaintext. The server resolves
   it at use time (NPM password, BIND SSH password, ...).

## Enabling

```dotenv
VAULT_ADDR=http://vault:8200     # or https://vault.example.com
VAULT_TOKEN=<root or policy token>
VAULT_PREFIX=cerulean
```

The compose stack ships a **dev-mode** Vault for self-hosted testing:

```bash
docker compose --profile vault up -d
# VAULT_ADDR=http://localhost:8200, VAULT_TOKEN=cerulean-root (see
# VAULT_DEV_ROOT_TOKEN_ID in .env)
```

> Dev mode is ephemeral and single-node — fine for a homelab, but for
> production point `VAULT_ADDR` at a real, sealed, unsealed-by-operator Vault
> and give Cerulean a token with `read/write` on `secret/data/cerulean/*`.

## Mirroring secrets

With Vault enabled, the scheduler syncs on startup and daily, and the
**Settings → Secret vault → Sync secrets** button (or `POST /api/vault/sync`)
runs it on demand. Material is written under the configured prefix:

```
certs/<id>              certificate (fullchain) + private key
acme/<email>            ACME account private key
```

## vault:// references in .env

```dotenv
NPM_PASSWORD=vault://cerulean/npm#password
BIND_SSH_PASSWORD=vault://cerulean/bind#password
```

Create the secrets with the Vault CLI:

```bash
vault kv put cerulean/npm password='the-real-password'
vault kv put cerulean/bind password='the-ssh-password'
```

`vault://<path>` without `#key` returns the first value of the secret. The
`/status` endpoint and the Settings page show Vault connectivity; failures to
resolve a reference surface as a clear error when the credential is used.

## Policy (production)

```hcl
path "secret/data/cerulean/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/cerulean/*" {
  capabilities = ["read", "list"]
}
```
