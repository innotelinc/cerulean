#!/usr/bin/env bash
# Shared helpers for the Cerulean setup scripts.
set -euo pipefail

# ── .env handling ───────────────────────────────────────────────────────────
# Locate the repo root (parent of scripts/)
CERULEAN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${CERULEAN_ROOT}/.env"

# Get a value from .env (or fallback). Values must be single-line, unquoted.
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

# Set a value in .env (create the file from .env.example if missing).
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

# Load the keys the setup scripts need into the environment.
env_load() {
  if [ ! -f "$ENV_FILE" ]; then
    echo "⚠  .env not found — copying .env.example to .env (edit it first!)" >&2
    cp "${CERULEAN_ROOT}/.env.example" "$ENV_FILE"
  fi
  BIND_SSH_HOST="$(env_get BIND_SSH_HOST)"
  BIND_SSH_PORT="$(env_get BIND_SSH_PORT 22)"
  BIND_SSH_USER="$(env_get BIND_SSH_USER root)"
  BIND_SSH_KEY_PATH="$(env_get BIND_SSH_KEY_PATH)"
  BIND_SSH_PASSWORD="$(env_get BIND_SSH_PASSWORD)"
  BIND_TSIG_NAME="$(env_get BIND_TSIG_NAME cerulean)"
  BIND_TSIG_SECRET="$(env_get BIND_TSIG_SECRET)"
  BIND_ZONES="$(env_get BIND_ZONES "$(env_get CERULEAN_ZONE)")"
  CERULEAN_ADMIN_PASSWORD="$(env_get CERULEAN_ADMIN_PASSWORD)"
  NPM_API_URL="$(env_get NPM_API_URL)"
  NPM_EMAIL="$(env_get NPM_EMAIL)"
  NPM_PASSWORD="$(env_get NPM_PASSWORD)"
  NPM_FORWARD_HOST="$(env_get NPM_FORWARD_HOST)"
  NPM_BASE_DOMAIN="$(env_get NPM_BASE_DOMAIN)"
  NPM_PROXY_SSL="$(env_get NPM_PROXY_SSL 0)"
}

# ── SSH to the BIND server ──────────────────────────────────────────────────
ensure_sshpass() {
  if command -v sshpass >/dev/null 2>&1; then
    return 0
  fi
  echo "sshpass not found — installing it (needed for password-based SSH to BIND)…"
  if [ "$(id -u)" = "0" ]; then
    apt-get update -y && apt-get install -y sshpass
  else
    sudo apt-get update -y && sudo apt-get install -y sshpass
  fi
}

# Run a remote command on the BIND server. Output is returned on stdout.
ssh_run() {
  local cmd="$1"
  local opts=(-p "$BIND_SSH_PORT" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
  if [ -n "$BIND_SSH_KEY_PATH" ] && [ -f "$BIND_SSH_KEY_PATH" ]; then
    ssh "${opts[@]}" -i "$BIND_SSH_KEY_PATH" "$BIND_SSH_USER@$BIND_SSH_HOST" "$cmd"
  elif [ -n "$BIND_SSH_PASSWORD" ]; then
    ensure_sshpass
    sshpass -p "$BIND_SSH_PASSWORD" ssh "${opts[@]}" "$BIND_SSH_USER@$BIND_SSH_HOST" "$cmd"
  else
    echo "ERROR: no BIND SSH credentials (set BIND_SSH_KEY_PATH or BIND_SSH_PASSWORD in .env)" >&2
    return 1
  fi
}

bind_configured() {
  [ -n "$BIND_SSH_HOST" ] && { [ -n "$BIND_SSH_KEY_PATH" ] || [ -n "$BIND_SSH_PASSWORD" ]; }
}

npm_configured() {
  [ -n "$NPM_API_URL" ] && [ -n "$NPM_EMAIL" ] && [ -n "$NPM_PASSWORD" ] && [ "$NPM_PASSWORD" != "change-me" ]
}

# ── misc ────────────────────────────────────────────────────────────────────
log()  { printf '\033[1;34m▶\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m⚠\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }
