#!/bin/sh
# Cerulean — durable HashiCorp Vault bootstrap.
#
# Runs as the vault container's entrypoint (docker compose --profile vault) and
# replaces the old in-memory dev server. On every start it makes the stack's
# secret store usable:
#
#   1. starts Vault on the persistent "file" storage backend (./data/vault/file)
#   2. initialises it once — unseal key + root token land in VAULT_INIT_FILE
#      (./data/vault/init/init.json, mode 600). Vault seals on every restart, so
#      on the next start those keys are used to unseal it.
#   3. enables the KV v2 engine at VAULT_PREFIX
#   4. writes the `cerulean` policy, scoped to <prefix>/data|metadata/*
#   5. mints a token with only that policy and writes it to VAULT_TOKEN_FILE
#      (./data/vault/token/cerulean.token) — the only thing the app container can
#      see; the root token never leaves init.json — then renews it in place.
#   6. does the same for each product named in VAULT_PRODUCT_TOKENS, except its
#      policy covers only <prefix>/data/<product>. The mount-wide grant lets any
#      one product read and overwrite every sibling's secrets; a product that
#      only ever touches its own path should not hold that.
#
# Steps 3-6 are idempotent: they re-run only when the mount, policy or token is
# missing, so restarts are fast and existing secrets are never touched.
set -eu

CONFIG="${VAULT_CONFIG_FILE:-/vault/init/vault.hcl}"
INIT_FILE="${VAULT_INIT_FILE:-/vault/init/init.json}"
TOKEN_FILE="${VAULT_TOKEN_FILE:-/vault/token/cerulean.token}"
FILE_STORAGE="${VAULT_FILE_STORAGE:-/vault/file}"
PREFIX="${VAULT_PREFIX:-cerulean}"
POLICY="${VAULT_POLICY_NAME:-cerulean}"
API_ADDR="${VAULT_API_ADDR:-http://vault:8200}"
# Token lifetime/renewal. A periodic token renews back to the same period every
# time, so it can be kept alive indefinitely — see the renewal loop below.
TOKEN_PERIOD="${VAULT_TOKEN_PERIOD:-768h}"
RENEW_INTERVAL="${VAULT_RENEW_INTERVAL:-43200}" # 12h, comfortably inside the period
# Space-separated product names that get their own narrower token (e.g.
# "olympus"). Empty = the mount-wide token only. Each name needs a matching
# policy of the same name to exist — step 6 writes it.
PRODUCT_TOKENS="${VAULT_PRODUCT_TOKENS:-}"
TOKEN_DIR="$(dirname "$TOKEN_FILE")"
# Word-split on purpose: this is a list, and every element is a single token.
PRODUCT_TOKEN_FILES=""
for product in $PRODUCT_TOKENS; do
  PRODUCT_TOKEN_FILES="$PRODUCT_TOKEN_FILES $TOKEN_DIR/$product.token"
done

# The CLI talks to the server over loopback; the app uses VAULT_ADDR=vault:8200.
export VAULT_ADDR="${VAULT_LOCAL_ADDR:-http://127.0.0.1:8200}"

log() { echo "[vault-bootstrap] $*"; }
die() { log "ERROR: $*"; exit 1; }

# The CLI pretty-prints -format=json, so squeeze whitespace before grepping.
status_json() { vault status -format=json 2>/dev/null | tr -d ' \n\t'; }
is_sealed() { status_json | grep -q '"sealed":true'; }
is_initialized() { status_json | grep -q '"initialized":true'; }

mkdir -p "$(dirname "$CONFIG")" "$(dirname "$INIT_FILE")" "$(dirname "$TOKEN_FILE")" "$FILE_STORAGE"

# disable_mlock: swap is already excluded by the container's memswap_limit, and
# mlock would otherwise need the IPC_LOCK capability. The UI is served on :8200.
cat > "$CONFIG" <<EOF
storage "file" {
  path = "$FILE_STORAGE"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
disable_mlock = true
ui = true
# Advertised to clients within the compose network (the app uses vault:8200).
api_addr = "${API_ADDR}"
EOF

log "starting Vault (file storage: $FILE_STORAGE)"
vault server -config="$CONFIG" &
VAULT_PID=$!
trap 'kill -TERM "$VAULT_PID" 2>/dev/null || true' TERM INT

# Wait for the API. A sealed or uninitialised server still answers, so "up"
# means the status endpoint replies at all — not that it is usable yet. The CLI
# exits 2 for sealed/uninitialised, so probe for output rather than exit status.
waited=0
until [ -n "$(vault status -format=json 2>/dev/null)" ]; do
  waited=$((waited + 1))
  [ "$waited" -ge 60 ] && die "Vault API did not come up within 60s"
  sleep 1
done

# ── 1. Initialise once ──────────────────────────────────────────────────────
if [ ! -s "$INIT_FILE" ]; then
  if is_initialized; then
    die "$FILE_STORAGE is already initialised but $INIT_FILE is missing. Restore it from backup (it holds the unseal key and root token), or wipe that directory to start over."
  fi
  log "initialising Vault (single unseal key — see docs/vault-setup.md)"
  vault operator init -key-shares=1 -key-threshold=1 -format=json > "$INIT_FILE"
  chmod 600 "$INIT_FILE"
fi

# `vault operator init -format=json` is pretty-printed; stripping whitespace
# makes the two values one-line greppable without needing jq in the image.
INIT_JSON="$(tr -d ' \n\t' < "$INIT_FILE")"
UNSEAL_KEY="$(printf '%s' "$INIT_JSON" | sed -n 's/.*"unseal_keys_b64":\["\([^"]*\)".*/\1/p')"
ROOT_TOKEN="$(printf '%s' "$INIT_JSON" | sed -n 's/.*"root_token":"\([^"]*\)".*/\1/p')"
[ -n "$UNSEAL_KEY" ] || die "could not read the unseal key from $INIT_FILE"
[ -n "$ROOT_TOKEN" ] || die "could not read the root token from $INIT_FILE"

# ── 2. Unseal ───────────────────────────────────────────────────────────────
if is_sealed; then
  log "unsealing Vault"
  vault operator unseal "$UNSEAL_KEY" >/dev/null
fi

export VAULT_TOKEN="$ROOT_TOKEN"

# ── 3. KV v2 at the configured prefix ───────────────────────────────────────
if ! vault secrets list -format=json | grep -q "\"${PREFIX}/\":"; then
  log "enabling KV v2 at ${PREFIX}/"
  vault secrets enable -path="$PREFIX" kv-v2 >/dev/null
fi

# ── 4. Scoped policy (no root, only this prefix) ────────────────────────────
vault policy write "$POLICY" - >/dev/null <<EOF
# Cerulean — secret mirroring (certs/, acme/, pki/) and vault:// resolution.
# KV v2 addresses data and metadata under separate paths.
path "${PREFIX}/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "${PREFIX}/metadata/*" {
  capabilities = ["read", "list"]
}
EOF

# ── 4b. Product-scoped policies (one path, not the whole mount) ─────────────
# Same operations as the mount-wide policy, narrowed to the product's own path,
# so a leaked copy of its token cannot touch a sibling's secrets. Still no
# `list` on the mount root: that would disclose every sibling key's name.
for product in $PRODUCT_TOKENS; do
  vault policy write "$product" - >/dev/null <<EOF
# Cerulean — ${product}'s own secrets, not the ${PREFIX}/ mount at large.
# KV v2 addresses data and metadata under separate paths.
path "${PREFIX}/data/${product}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "${PREFIX}/data/${product}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "${PREFIX}/metadata/${product}" {
  capabilities = ["read", "list"]
}
path "${PREFIX}/metadata/${product}/*" {
  capabilities = ["read", "list"]
}
EOF
done

# ── 5. Scoped service token ─────────────────────────────────────────────────
# Minted once and reused across restarts, and only replaced when it stops
# authenticating (e.g. the store was wiped and re-initialised). It is a
# periodic token, so renewals reset the TTL back to TOKEN_PERIOD forever — the
# app's copy never goes stale while this container is running.
# Reuse a token that still authenticates; mint one only when there is none or it
# has stopped working (e.g. the store was wiped and re-initialised). It is a
# periodic token, so renewals reset its TTL back to TOKEN_PERIOD forever — the
# holder's copy never goes stale while this container is running.
provision_token() {
  policy="$1"
  file="$2"

  if [ -s "$file" ]; then
    if VAULT_TOKEN="$(cat "$file")" vault token lookup >/dev/null 2>&1; then
      log "scoped token at $file is valid (policy: $policy)"
      return 0
    fi
    rm -f "$file"
    log "WARNING: the token at $file no longer authenticates — minting a new one."
    log "         Anyone holding a copy must fetch the replacement from that path."
  fi

  token_json="$(vault token create -orphan -policy="$policy" -period="$TOKEN_PERIOD" -format=json)"
  new_token="$(printf '%s' "$token_json" | tr -d ' \n' | sed -n 's/.*"client_token":"\([^"]*\)".*/\1/p')"
  [ -n "$new_token" ] || die "could not mint a scoped token (policy: $policy)"
  umask 077
  printf '%s\n' "$new_token" > "$file"
  log "minted scoped token (policy: $policy, period: $TOKEN_PERIOD) at $file"
}

provision_token "$POLICY" "$TOKEN_FILE"
for product in $PRODUCT_TOKENS; do
  provision_token "$product" "$TOKEN_DIR/$product.token"
done

log "ready — KV v2 at ${PREFIX}/, token policies: $POLICY${PRODUCT_TOKENS:+ + $PRODUCT_TOKENS} (root token stays in $INIT_FILE)"

# Keep the app's token alive. The Vault process must be up for the app to use it
# at all, so renewing here guarantees the token outlives any app uptime.
while :; do
  sleep "$RENEW_INTERVAL"
  for file in "$TOKEN_FILE" $PRODUCT_TOKEN_FILES; do
    if [ ! -s "$file" ]; then
      log "WARNING: no token at $file to renew — was it never minted?"
      continue
    fi
    if VAULT_TOKEN="$ROOT_TOKEN" vault token renew "$(cat "$file")" >/dev/null 2>&1; then
      log "renewed the scoped token at $file (period $TOKEN_PERIOD)"
    else
      log "WARNING: could not renew the token at $file — check that file"
    fi
  done
done &

wait "$VAULT_PID"
