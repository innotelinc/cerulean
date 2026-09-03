#!/usr/bin/env bash
# Cerulean one-shot setup.
#
#   ./scripts/setup.sh [--no-start] [--with-authentik]
#
# Does everything needed to get a working portal on a fresh host:
#   1. Ensures .env exists and generates the admin password if unset
#   2. Configures BIND (TSIG key autogen + install on BIND for nsupdate
#      DNS-01 TXT challenge records)
#   3. Installs all dependencies and builds the portal
#   4. Starts the stack (docker compose)
#   5. Provisions nginx proxy manager proxy hosts via ./npm-proxy-hosts.py
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

NO_START=0
WITH_AUTHENTIK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --no-start) NO_START=1; shift ;;
    --with-authentik) WITH_AUTHENTIK=1; shift ;;
    *) fail "Unknown option: $1 (usage: ./scripts/setup.sh [--no-start] [--with-authentik])" ;;
  esac
done

log "Cerulean setup — ${CERULEAN_ROOT}"

# ── 0a. Enable the commit-attribution guard hooks (.githooks) ───────────────
# Point git at the version-controlled hooks dir so commits made from this
# clone are guarded (blocks attribution to anyone but Darnel Hunter).
if [ -d "${CERULEAN_ROOT}/.githooks" ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git config core.hooksPath "${CERULEAN_ROOT}/.githooks"
  ok "commit guard hook enabled (core.hooksPath -> .githooks)"
fi

# ── 0. .env + admin password ─────────────────────────────────────────────────
if [ ! -f "$ENV_FILE" ]; then
  cp "${CERULEAN_ROOT}/.env.example" "$ENV_FILE"
  ok "Created .env from .env.example — review the host/email values"
fi
env_load
ADMIN="$(env_get CERULEAN_ADMIN_PASSWORD)"
if [ -z "$ADMIN" ] || [ "$ADMIN" = "change-me" ]; then
  ADMIN="$(openssl rand -base64 18 | tr -d '/+=' | head -c 24)"
  env_set CERULEAN_ADMIN_PASSWORD "$ADMIN"
  ok "Generated portal admin password (see below)"
fi

# ── 1. BIND / TSIG ───────────────────────────────────────────────────────────
# DNS-01 challenges are validated by writing TXT records straight into BIND
# over SSH (nsupdate + TSIG).
#   BIND_MODE=local  (default: remote) — the compose stack bundles a BIND+sshd
#                    container (profile "bind"); nothing to configure here, the
#                    container generates its TSIG key and root password on
#                    first start (printed to its logs — copy into .env).
#   BIND_MODE=remote — generate + install the TSIG key on the remote BIND
#                    server automatically when BIND_SSH_* is configured.
BIND_MODE="$(env_get BIND_MODE remote)"
if [ "$BIND_MODE" = "local" ]; then
  log "BIND_MODE=local — bundled BIND container will serve the zones"
  log "Start it with: docker compose --profile bind up -d"
  if [ -z "$(env_get BIND_TSIG_SECRET)" ]; then
    warn "BIND_TSIG_SECRET not set — the bundled container generates one on first"
    warn "start (see: docker logs cerulean-bind); copy it into .env and restart."
  fi
elif bind_configured; then
  "${SCRIPT_DIR}/setup-bind.sh"
else
  warn "BIND is not configured in .env — skipping automatic BIND setup"
  warn "Set BIND_SSH_HOST/BIND_SSH_USER and a key or password (and BIND_TSIG_SECRET)"
  warn "in .env to enable DNS-01 validation through BIND."
fi

# ── 2. Install dependencies + build ──────────────────────────────────────────
log "Installing dependencies (npm install)…"
( cd "${CERULEAN_ROOT}" && npm install )
log "Building portal + server…"
( cd "${CERULEAN_ROOT}" && npm run build )
ok "Build complete"

# ── 3. Start the stack ───────────────────────────────────────────────────────
if [ "$NO_START" = "1" ]; then
  echo
  ok "Setup finished (--no-start). Start it with:"
  echo "    cd ${CERULEAN_ROOT}"
  echo "    docker compose up -d --build"
else
  log "Starting the stack…"
  if command -v docker >/dev/null 2>&1; then
    PROFILES=()
    [ "$(env_get BIND_MODE remote)" = "local" ] && PROFILES+=("--profile" "bind")
    [ "$(env_get NPM_MODE remote)" = "local" ] && PROFILES+=("--profile" "npm")
    ( cd "${CERULEAN_ROOT}" && docker compose up -d --build "${PROFILES[@]}" )
    ok "Stack is up. Dashboard: http://<this-host>:3000"
  else
    warn "docker not found — start the portal manually with:"
    echo "    cd ${CERULEAN_ROOT} && npm start"
  fi
fi

# ── 4. Provision nginx proxy manager proxy hosts ────────────────────────────
if npm_configured; then
  if command -v python3 >/dev/null 2>&1; then
    log "Provisioning nginx proxy manager proxy hosts (${NPM_API_URL})…"
    if python3 "${SCRIPT_DIR}/npm-proxy-hosts.py"; then
      ok "nginx proxy manager proxy hosts are up to date"
    else
      warn "NPM proxy host provisioning did not complete — check NPM_API_URL/NPM_EMAIL/NPM_PASSWORD"
      warn "and NPM_FORWARD_HOST in .env, then re-run: python3 scripts/npm-proxy-hosts.py"
    fi
  else
    warn "python3 not found — skipping automatic NPM proxy host provisioning"
  fi
else
  log "NPM not configured in .env — skipping proxy host provisioning"
fi

# ── 5. Authentik (optional: --with-authentik or when AUTHENTIK_ISSUER_URL set) ─
AUTHENTIK_ISSUER_URL="$(env_get AUTHENTIK_ISSUER_URL)"
if [ "$WITH_AUTHENTIK" = "1" ] || [ -n "$AUTHENTIK_ISSUER_URL" ]; then
  log "Configuring Authentik OIDC…"
  if [ -z "$AUTHENTIK_ISSUER_URL" ]; then
    NPM_BASE_DOMAIN="$(env_get NPM_BASE_DOMAIN "$(env_get CERULEAN_ZONE innotel.us)")"
    AUTHENTIK_ISSUER_URL="http://auth.${NPM_BASE_DOMAIN}"
    env_set AUTHENTIK_ISSUER_URL "$AUTHENTIK_ISSUER_URL"
  fi
  CLIENT_ID="$(env_get AUTHENTIK_CLIENT_ID)"
  if [ -z "$CLIENT_ID" ]; then
    CLIENT_ID="cerulean"
    env_set AUTHENTIK_CLIENT_ID "$CLIENT_ID"
  fi
  CLIENT_SECRET="$(env_get AUTHENTIK_CLIENT_SECRET)"
  if [ -z "$CLIENT_SECRET" ]; then
    CLIENT_SECRET="$(openssl rand -base64 32 | tr -d '/+=' | head -c 48)"
    env_set AUTHENTIK_CLIENT_SECRET "$CLIENT_SECRET"
    ok "Generated OIDC client secret for Authentik"
  fi
  REDIRECT_URI="$(env_get AUTHENTIK_REDIRECT_URI)"
  if [ -z "$REDIRECT_URI" ]; then
    REDIRECT_URI="http://cerulean.$(env_get NPM_BASE_DOMAIN "$(env_get CERULEAN_ZONE innotel.us)")/api/auth/oidc/callback"
    env_set AUTHENTIK_REDIRECT_URI "$REDIRECT_URI"
  fi
  if [ -z "$(env_get AUTHENTIK_ADMIN_PASSWORD)" ]; then
    warn "AUTHENTIK_ADMIN_PASSWORD is not set in .env — set it (the Authentik admin password) "
    warn "or provision the provider manually in the Authentik UI (Applications → Create)."
  fi
  if command -v python3 >/dev/null 2>&1; then
    if python3 "${SCRIPT_DIR}/authentik-setup.py"; then
      ok "Authentik OIDC provider is configured"
    else
      warn "Authentik provisioning did not complete — check AUTHENTIK_ADMIN_PASSWORD and that"
      warn "the stack is up (docker compose --profile authentik up -d), then re-run:"
      warn "python3 scripts/authentik-setup.py"
    fi
  fi
  echo "  First login: create the Authentik admin with:"
  echo "      docker compose --profile authentik exec authentik-server ak createsuperuser"
  echo "  (or set AUTHENTIK_BOOTSTRAP_PASSWORD in .env before the first start)."
  echo "  OIDC: ${AUTHENTIK_ISSUER_URL}  ·  redirect: ${REDIRECT_URI}"
fi

echo
echo "──────────────────────────────────────────────────────────"
echo "  Cerulean is ready!"
echo "  Dashboard:   http://<this-host>:3000"
echo "  Admin login: admin  (password below)"
echo "  Admin pass:  ${ADMIN}"
echo "  Authentik:   $(env_get AUTHENTIK_ISSUER_URL '(not configured)')  — add --with-authentik to enable SSO"
echo "  Vault:       $(env_get VAULT_ADDR '(not configured)')  — set VAULT_ADDR/VAULT_TOKEN to enable"
echo "──────────────────────────────────────────────────────────"
