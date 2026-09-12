#!/usr/bin/env bash
# Cerulean one-shot setup — Technitium master orchestrator.
#
#   ./scripts/setup.sh [--no-start] [--with-authentik] [--with-technitium] [--with-vault]
#
#   1. Ensures .env exists and generates the admin password + serverId if unset
#   2. Ensures Technitium DNS (bundled --profile technitium) is ready / reachable
#   3. Installs dependencies and builds the portal
#   4. Starts the stack (docker compose)
#   5. Provisions nginx proxy manager proxy hosts
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

NO_START=0
WITH_AUTHENTIK=0
WITH_TECHNITIUM=0
WITH_VAULT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --no-start) NO_START=1; shift ;;
    --with-authentik) WITH_AUTHENTIK=1; shift ;;
    --with-technitium) WITH_TECHNITIUM=1; shift ;;
    --with-vault) WITH_VAULT=1; shift ;;
    *) fail "Unknown option: $1 (usage: ./scripts/setup.sh [--no-start] [--with-authentik] [--with-technitium] [--with-vault])" ;;
  esac
done

log "Cerulean setup — ${CERULEAN_ROOT} (Technitium master orchestrator)"

if [ -d "${CERULEAN_ROOT}/.githooks" ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git config core.hooksPath "${CERULEAN_ROOT}/.githooks"
  ok "commit guard hook enabled (core.hooksPath -> .githooks)"
fi

# ── 0. .env + admin password + server identity ──────────────────────────────
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
# Server ID: stable slug for offline wildcard <id>.lab.innotel.us
SERVER_ID="$(env_get CERULEAN_SERVER_ID)"
if [ -z "$SERVER_ID" ]; then
  # keep empty — server/config.ts + DB will auto-generate and persist on boot
  log "CERULEAN_SERVER_ID not set — a stable ID will be generated on first boot (set it in .env for a pre-assigned hostname)"
fi
LAB_DOMAIN="$(env_get CERULEAN_LAB_DOMAIN lab.innotel.us)"
if [ -z "$LAB_DOMAIN" ]; then
  env_set CERULEAN_LAB_DOMAIN "lab.innotel.us"
fi

# ── 0b. Free host port 53 (systemd-resolved stub) ───────────────────────────
# The bundled Technitium binds :53 directly on the host (network_mode: host).
# systemd-resolved's stub listener (127.0.0.53:53) blocks that bind, so disable
# it and point the host resolver at the local DNS server instead.
# Set CERULEAN_KEEP_RESOLVED=1 to skip this (e.g. remote-only Technitium).
free_port_53() {
  if [ "${CERULEAN_KEEP_RESOLVED:-0}" = "1" ]; then
    log "CERULEAN_KEEP_RESOLVED=1 — leaving systemd-resolved alone"
    return 0
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0 # not a systemd host — nothing to free
  fi
  if ! ss -tulpn 2>/dev/null | grep -q '127\.0\.0\.(53|54):53'; then
    log "Port 53 already free on host — no resolver changes needed"
    return 0
  fi
  log "systemd-resolved stub holds :53 — disabling it (host DNS moves to Technitium)"
  systemctl disable --now systemd-resolved >/dev/null 2>&1 || true
  systemctl mask systemd-resolved >/dev/null 2>&1 || true
  if [ -f /etc/resolv.conf ] && ! grep -q 'pre-cerulean' /etc/resolv.conf 2>/dev/null; then
    cp /etc/resolv.conf /etc/resolv.conf.pre-cerulean 2>/dev/null || true
  fi
  # Host resolver: local Technitium first, Cloudflare fallback.
  printf '# Cerulean host resolver (managed by scripts/setup.sh)\nsearch innotel.us\nnameserver 127.0.0.1\nnameserver 1.1.1.1\n' > /etc/resolv.conf
  ok "Port 53 freed — systemd-resolved disabled+masked, /etc/resolv.conf -> 127.0.0.1"
  if ! getent hosts innotel.us >/dev/null 2>&1; then
    warn "Host resolution check failed — verify Technitium is up and :53 is bound"
  fi
}
free_port_53

# ── 1. Technitium DNS ───────────────────────────────────────────────────────
log "Technitium DNS: ${TECHNITIUM_URL:-http://host.docker.internal:5380} (HTTP API — no SSH/TSIG)"
if ! technitium_configured; then
  warn "Technitium credentials not set (TECHNITIUM_TOKEN or TECHNITIUM_USER/PASSWORD in .env)"
  warn "The bundled Technitium (docker compose --profile technitium up -d) may still work with defaults;"
  warn "set TECHNITIUM_ADMIN_PASSWORD in .env for the bundled container or TECHNITIUM_TOKEN for remote."
fi
if [ -z "$(env_get TECHNITIUM_URL)" ]; then
  warn "TECHNITIUM_URL not set — defaults to http://host.docker.internal:5380 (host-networked bundled container)"
fi
if [ "$WITH_TECHNITIUM" = "1" ] || [ -z "$(env_get TECHNITIUM_URL)" ]; then
  log "Tip: start the bundled Technitium with: docker compose --profile technitium up -d"
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
  echo "    docker compose --profile technitium up -d --build  # DNS/DHCP/blocking"
  echo "    docker compose up -d --build"
else
  log "Starting the stack…"
  if command -v docker >/dev/null 2>&1; then
    PROFILES=()
    # Always bring up cerulean; Technitium/Vault are opt-in profiles
    if [ "$WITH_TECHNITIUM" = "1" ]; then
      PROFILES+=("--profile" "technitium")
    fi
    # The vault profile self-initialises, auto-unseals, and mints the scoped
    # token the app reads from VAULT_TOKEN_FILE (see docs/vault-setup.md).
    if [ "$WITH_VAULT" = "1" ]; then
      PROFILES+=("--profile" "vault")
    fi
    [ "$(env_get NPM_MODE remote)" = "local" ] && PROFILES+=("--profile" "npm")
    ( cd "${CERULEAN_ROOT}" && docker compose up -d --build "${PROFILES[@]}" )
    ok "Stack is up. Dashboard: http://<this-host>:3000"
    if [ "$WITH_TECHNITIUM" = "1" ] || docker compose ps 2>/dev/null | grep -q cerulean-technitium; then
      ok "Technitium web console: http://<this-host>:5380 (admin / TECHNITIUM_ADMIN_PASSWORD)"
    else
      log "Start Technitium (DNS/DHCP/blocking) with: docker compose --profile technitium up -d"
    fi
  else
    warn "docker not found — start the portal manually with:"
    echo "    cd ${CERULEAN_ROOT} && npm start"
  fi
fi

# ── 4. Provision nginx proxy manager proxy hosts ────────────────────────────
if npm_configured; then
  if command -v python3 >/dev/null 2>&1; then
    log "Provisioning nginx proxy manager proxy hosts (${NPM_API_URL:-bundled})…"
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

# ── 5. Authentik (optional) ─────────────────────────────────────────────────
AUTHENTIK_ISSUER_URL="$(env_get AUTHENTIK_ISSUER_URL)"
if [ "$WITH_AUTHENTIK" = "1" ] || [ -n "$AUTHENTIK_ISSUER_URL" ]; then
  log "Configuring Authentik OIDC…"
  if [ -z "$AUTHENTIK_ISSUER_URL" ]; then
    NPM_BASE_DOMAIN="$(env_get NPM_BASE_DOMAIN "$(env_get CERULEAN_ZONE "${SERVER_ID:-cerulean}.${LAB_DOMAIN}")")"
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
    REDIRECT_URI="http://cerulean.$(env_get NPM_BASE_DOMAIN "${SERVER_ID:-cerulean}.${LAB_DOMAIN}")/api/auth/oidc/callback"
    env_set AUTHENTIK_REDIRECT_URI "$REDIRECT_URI"
  fi
  if [ -z "$(env_get AUTHENTIK_ADMIN_PASSWORD)" ]; then
    warn "AUTHENTIK_ADMIN_PASSWORD is not set in .env — set it (the Authentik admin password)"
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
echo "  Cerulean is ready! (Technitium master orchestrator)"
echo "  Dashboard:   http://<this-host>:3000"
if [ -n "$SERVER_ID" ]; then
  echo "  Server:      ${SERVER_ID}.${LAB_DOMAIN}  (*.${SERVER_ID}.${LAB_DOMAIN} wildcard: PKI 90d → ACME when online)"
else
  echo "  Server:      <auto-generated> — check Orchestrator page after boot for <serverId>.${LAB_DOMAIN}"
fi
echo "  Technitium:  ${TECHNITIUM_URL:-http://host.docker.internal:5380}  — DNS/DHCP/blocking plane (HTTP API)"
echo "  Admin login: admin  (password below)"
echo "  Admin pass:  ${ADMIN}"
echo "  Authentik:   $(env_get AUTHENTIK_ISSUER_URL '(not configured)')  — add --with-authentik to enable SSO"
if [ -n "$(env_get VAULT_ADDR)" ]; then
  echo "  Vault:       $(env_get VAULT_ADDR)  — durable secret store (scoped token read from $(env_get VAULT_TOKEN_FILE /vault/token/cerulean.token))"
  if ! docker ps --filter name=cerulean-vault --format '{{.Names}}' 2>/dev/null | grep -q cerulean-vault; then
    echo "               not running yet — start it with: docker compose --profile vault up -d"
  fi
else
  echo "  Vault:       (not configured) — add --with-vault, or set VAULT_ADDR+VAULT_TOKEN for an external Vault"
fi
echo "──────────────────────────────────────────────────────────"
