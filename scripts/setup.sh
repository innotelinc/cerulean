#!/usr/bin/env bash
# Cerulean one-shot setup.
#
#   ./scripts/setup.sh [--strategy bind|acmedns] [--no-start]
#
# Does everything needed to get a working portal on a fresh host:
#   1. Ensures .env exists and generates the admin password if unset
#   2. Configures the DNS-01 strategy you choose:
#        bind    — TSIG key autogen + install on BIND (nsupdate TXT records)
#        acmedns — delegates a subdomain to the acme-dns server and points
#                  the CNAME at it; still needs BIND for the CNAME (skips
#                  BIND entirely if BIND_SSH_* is unset — you add the CNAME
#                  manually in that case)
#   3. Installs all dependencies and builds the portal
#   4. Starts the stack (docker compose; acme-dns only when selected)
#   5. Provisions nginx proxy manager proxy hosts via ./npm-proxy-hosts.py
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

STRATEGY=""
NO_START=0
WITH_AUTHENTIK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --strategy) STRATEGY="${2:-}"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --with-authentik) WITH_AUTHENTIK=1; shift ;;
    *) fail "Unknown option: $1 (usage: ./scripts/setup.sh [--strategy bind|acmedns] [--no-start] [--with-authentik])" ;;
  esac
done

log "Cerulean setup — ${CERULEAN_ROOT}"

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

# ── 1. Strategy choice ───────────────────────────────────────────────────────
if [ -z "$STRATEGY" ]; then
  STRATEGY="$CERULEAN_STRATEGY"
fi
if [ -z "$STRATEGY" ]; then
  printf 'Which DNS-01 strategy? [bind/acmedns] (bind): '
  read -r STRATEGY
fi
case "$STRATEGY" in
  bind|acmedns) env_set CERULEAN_STRATEGY "$STRATEGY" ;;
  *) fail "Strategy must be 'bind' or 'acmedns', got: $STRATEGY" ;;
esac
log "Strategy: ${STRATEGY}"

# ── 2. BIND (both strategies use BIND for CNAME / delegation / records) ─────
if bind_configured; then
  "${SCRIPT_DIR}/setup-bind.sh"
else
  warn "BIND is not configured in .env — skipping automatic BIND setup"
  if [ "$STRATEGY" = "bind" ]; then
    fail "The 'bind' strategy requires BIND — set BIND_SSH_HOST/BIND_SSH_USER and a key or password in .env"
  fi
fi

# ── 3. acme-dns (optional) ───────────────────────────────────────────────────
if [ "$STRATEGY" = "acmedns" ]; then
  ACMEDNS_DOMAIN="$(env_get ACMEDNS_DOMAIN auth.innotel.us)"
  ACMEDNS_PUBLIC_IP="$(env_get ACMEDNS_PUBLIC_IP)"
  if [ -z "$ACMEDNS_PUBLIC_IP" ]; then
    printf 'Public IP of the host that will run the acme-dns container (port 53 must reach it): '
    read -r ACMEDNS_PUBLIC_IP
    env_set ACMEDNS_PUBLIC_IP "$ACMEDNS_PUBLIC_IP"
  fi
  log "Writing acme-dns/config.cfg for ${ACMEDNS_DOMAIN} (A ${ACMEDNS_PUBLIC_IP})…"
  mkdir -p "${CERULEAN_ROOT}/acme-dns/data"
  cat >"${CERULEAN_ROOT}/acme-dns/config.cfg" <<EOF
[general]
listen = "0.0.0.0:53"
protocol = "both"
domain = "${ACMEDNS_DOMAIN}"
nsname = "${ACMEDNS_DOMAIN}"
nsadmin = "admin.$(env_get CERULEAN_ZONE innotel.us)"
records = [
    "${ACMEDNS_DOMAIN}. A ${ACMEDNS_PUBLIC_IP}",
    "${ACMEDNS_DOMAIN}. NS ${ACMEDNS_DOMAIN}.",
]
debug = false

[database]
engine = "sqlite3"
connection = "/var/lib/acme-dns/acme-dns.db"

[api]
ip = "0.0.0.0"
disable_registration = false
port = "4443"
tls = "none"
corsorigins = [
    "*"
]
use_header = false
header_name = "X-Forwarded-For"

[logconfig]
loglevel = "info"
logtype = "stdout"
logformat = "text"
EOF
  ok "Wrote acme-dns/config.cfg"

  if bind_configured; then
    log "Adding delegation records to the ${CERULEAN_ZONE} zone on BIND…"
    ZONE_NAME="$(env_get CERULEAN_ZONE innotel.us)"
    # Values are inlined (ssh does not forward arbitrary env vars)
    ssh_run "cat >/tmp/cerulean-delegation.txt <<EOF
server 127.0.0.1
zone ${ZONE_NAME}.
update delete ${ACMEDNS_DOMAIN}. NS
update add ${ACMEDNS_DOMAIN}. 300 NS ${ACMEDNS_DOMAIN}.
update delete ${ACMEDNS_DOMAIN}. A
update add ${ACMEDNS_DOMAIN}. 300 A ${ACMEDNS_PUBLIC_IP}
send
EOF
nsupdate -k /etc/bind/cerulean.keys /tmp/cerulean-delegation.txt && rm -f /tmp/cerulean-delegation.txt" >/dev/null
    ok "Delegation added: ${ACMEDNS_DOMAIN}. NS ${ACMEDNS_DOMAIN}. / A ${ACMEDNS_PUBLIC_IP}"
  else
    warn "No BIND configured — add these records to your DNS provider for ${CERULEAN_ZONE}:"
    echo "    ${ACMEDNS_DOMAIN}.  IN  NS  ${ACMEDNS_DOMAIN}."
    echo "    ${ACMEDNS_DOMAIN}.  IN  A   ${ACMEDNS_PUBLIC_IP}"
    echo "  and point _acme-challenge.<domain> (CNAME) at <uuid>.${ACMEDNS_DOMAIN}. —"
    echo "  Cerulean prints the exact CNAME when you issue the first certificate."
  fi
  echo "  Remember: forward UDP+TCP 53 from your router to the acme-dns host."
fi

# ── 4. Install dependencies + build ──────────────────────────────────────────
log "Installing dependencies (npm install)…"
( cd "${CERULEAN_ROOT}" && npm install )
log "Building portal + server…"
( cd "${CERULEAN_ROOT}" && npm run build )
ok "Build complete"

# ── 5. Start the stack ───────────────────────────────────────────────────────
if [ "$NO_START" = "1" ]; then
  echo
  ok "Setup finished (--no-start). Start it with:"
  echo "    cd ${CERULEAN_ROOT}"
  if [ "$STRATEGY" = "acmedns" ]; then
    echo "    docker compose --profile acmedns up -d --build"
  else
    echo "    docker compose up -d --build"
  fi
else
  log "Starting the stack…"
  if command -v docker >/dev/null 2>&1; then
    if [ "$STRATEGY" = "acmedns" ]; then
      ( cd "${CERULEAN_ROOT}" && docker compose --profile acmedns up -d --build )
    else
      ( cd "${CERULEAN_ROOT}" && docker compose up -d --build )
    fi
    ok "Stack is up. Dashboard: http://<this-host>:3000"
  else
    warn "docker not found — start the portal manually with:"
    echo "    cd ${CERULEAN_ROOT} && npm start"
  fi
fi

# ── 6. Provision nginx proxy manager proxy hosts ────────────────────────────
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

# ── 7. Authentik (optional: --with-authentik or when AUTHENTIK_ISSUER_URL set) ─
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
echo "  Strategy:    ${STRATEGY}"
echo "  Dashboard:   http://<this-host>:3000"
echo "  Admin login: admin  (password below)"
echo "  Admin pass:  ${ADMIN}"
echo "  Authentik:   $(env_get AUTHENTIK_ISSUER_URL '(not configured)')  — add --with-authentik to enable SSO"
echo "  Vault:       $(env_get VAULT_ADDR '(not configured)')  — set VAULT_ADDR/VAULT_TOKEN to enable"
echo "──────────────────────────────────────────────────────────"
