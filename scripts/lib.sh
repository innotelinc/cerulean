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
  # Technitium is host-networked, so the default is the host gateway
  # (mapped in docker-compose.yml as host.docker.internal), never 127.0.0.1.
  TECHNITIUM_URL="$(env_get TECHNITIUM_URL http://host.docker.internal:5380)"
  TECHNITIUM_TOKEN="$(env_get TECHNITIUM_TOKEN)"
  TECHNITIUM_PASSWORD="$(env_get TECHNITIUM_PASSWORD)"
  CERULEAN_ZONE="$(env_get CERULEAN_ZONE)"
  CERULEAN_ADMIN_PASSWORD="$(env_get CERULEAN_ADMIN_PASSWORD)"
  NPM_MODE="$(env_get NPM_MODE remote)"
  NPM_API_URL="$(env_get NPM_API_URL)"
  NPM_EMAIL="$(env_get NPM_EMAIL)"
  NPM_PASSWORD="$(env_get NPM_PASSWORD)"
  NPM_FORWARD_HOST="$(env_get NPM_FORWARD_HOST)"
  NPM_BASE_DOMAIN="$(env_get NPM_BASE_DOMAIN)"
  NPM_PROXY_SSL="$(env_get NPM_PROXY_SSL 0)"
}

technitium_configured() {
  # Considered configured if URL points somewhere (even default), but for
  # setup guidance we want token/password present
  [ -n "$TECHNITIUM_TOKEN" ] || [ -n "$TECHNITIUM_PASSWORD" ] || [ -n "$(env_get TECHNITIUM_USER)" ]
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
