#!/usr/bin/env bash
# Shared helpers for the Cerulean setup scripts.
set -euo pipefail

# ── .env handling ───────────────────────────────────────────────────────────
CERULEAN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${CERULEAN_ROOT}/.env"

env_get() {
  local key="$1"
  local fallback="${2:-}"
  if [ -f "$ENV_FILE" ]; then
    local line
    line="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -1 || true)"
    if [ -n "$line" ]; then
      printf '%s' "${line#*=}"
      return 0
    fi
  fi
  printf '%s' "$fallback"
}

env_set() {
  local key="$1"
  local value="$2"
  if [ ! -f "$ENV_FILE" ]; then
    cp "${CERULEAN_ROOT}/.env.example" "$ENV_FILE"
  fi
  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf '\n%s=%s\n' "$key" "$value" >>"$ENV_FILE"
  fi
}

env_load() {
  if [ ! -f "$ENV_FILE" ]; then
    echo "⚠  .env not found — copying .env.example to .env (edit it first!)" >&2
    cp "${CERULEAN_ROOT}/.env.example" "$ENV_FILE"
  fi
  # Server identity
  CERULEAN_SERVER_ID="$(env_get CERULEAN_SERVER_ID)"
  CERULEAN_LAB_DOMAIN="$(env_get CERULEAN_LAB_DOMAIN lab.innotel.us)"
  # Technitium
  # Technitium is host-networked and its console binds loopback + docker0 only
  # (DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES), so the default is the docker0
  # gateway — reachable from the host and from every container alike. Never
  # 127.0.0.1 (that is the caller itself) and never host.docker.internal (that
  # resolves to the *caller's* bridge, which the console does not bind).
  TECHNITIUM_URL="$(env_get TECHNITIUM_URL http://172.17.0.1:5380)"
  TECHNITIUM_TOKEN="$(env_get TECHNITIUM_TOKEN)"
  TECHNITIUM_PASSWORD="$(env_get TECHNITIUM_PASSWORD)"
  CERULEAN_ZONE="$(env_get CERULEAN_ZONE)"
  CERULEAN_ADMIN_PASSWORD="$(env_get CERULEAN_ADMIN_PASSWORD)"
  NPM_MODE="$(env_get NPM_MODE remote)"
  NPM_API_URL="$(env_get NPM_API_URL)"
  NPM_EMAIL="$(env_get NPM_EMAIL)"
  NPM_PASSWORD="$(env_get NPM_PASSWORD)"
  NPM_FORWARD_HOST="$(env_get NPM_FORWARD_HOST)"
  NPM_HOST_IP="$(env_get NPM_HOST_IP)"
  NPM_ADMIN_PORT="$(env_get NPM_ADMIN_PORT 81)"
  # Browser-reachable admin URL — setup.sh derives it when empty, because the
  # server falls back to loopback and that only resolves on the NPM host.
  NPM_PUBLIC_API_URL="$(env_get NPM_PUBLIC_API_URL)"
  NPM_BASE_DOMAIN="$(env_get NPM_BASE_DOMAIN)"
  NPM_PROXY_SSL="$(env_get NPM_PROXY_SSL 0)"
}

technitium_configured() {
  # Considered configured if URL points somewhere (even default), but for
  # setup guidance we want token/password present
  [ -n "$TECHNITIUM_TOKEN" ] || [ -n "$TECHNITIUM_PASSWORD" ] || [ -n "$(env_get TECHNITIUM_USER)" ]
}

# A usable Technitium API token on stdout: the pre-minted TECHNITIUM_TOKEN when
# set (service account), otherwise a fresh session from TECHNITIUM_USER/PASSWORD.
# Returns non-zero when neither works, so callers can warn instead of dying.
technitium_token() {
  if [ -n "${TECHNITIUM_TOKEN:-}" ]; then
    printf '%s' "$TECHNITIUM_TOKEN"
    return 0
  fi
  local pw user
  pw="$(env_get TECHNITIUM_ADMIN_PASSWORD)"
  [ -n "$pw" ] || pw="$(env_get TECHNITIUM_PASSWORD)"
  [ -n "$pw" ] || return 1
  user="$(env_get TECHNITIUM_USER admin)"
  curl -sf -G "${TECHNITIUM_URL:-http://172.17.0.1:5380}/api/user/login" \
    --data-urlencode "user=${user}" --data-urlencode "pass=${pw}" 2>/dev/null \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token") or "")' 2>/dev/null \
    | { read -r tok; [ -n "$tok" ] && printf '%s' "$tok"; } || return 1
}

npm_configured() {
  if [ "$NPM_MODE" = "local" ]; then
    [ -n "$NPM_EMAIL" ] && [ -n "$NPM_PASSWORD" ] && [ "$NPM_PASSWORD" != "change-me" ]
    return
  fi
  [ -n "$NPM_API_URL" ] && [ -n "$NPM_EMAIL" ] && [ -n "$NPM_PASSWORD" ] && [ "$NPM_PASSWORD" != "change-me" ]
}

# ── misc ────────────────────────────────────────────────────────────────────
log()  { printf '\033[1;34m▶\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m⚠\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }
