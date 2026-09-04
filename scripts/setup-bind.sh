#!/usr/bin/env bash
# Configure BIND for Cerulean, automatically:
#
#   1. Generates a TSIG key (if BIND_TSIG_SECRET is not already set in .env)
#   2. Installs it on the BIND server: /etc/bind/cerulean.keys + include
#   3. Patches each managed zone with allow-update + allow-transfer
#      (backup → edit → named-checkconf → rollback on failure)
#   4. Reloads BIND and writes BIND_TSIG_NAME/SECRET back into .env
#
# Usage: ./scripts/setup-bind.sh [key-name]
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

KEY_NAME="${1:-$(env_get BIND_TSIG_NAME cerulean)}"
env_load
bind_configured || fail "BIND is not configured in .env — set BIND_SSH_HOST and BIND_SSH_USER + (BIND_SSH_KEY_PATH or BIND_SSH_PASSWORD)"
[ -n "$BIND_ZONES" ] || fail "No zones to manage — set CERULEAN_ZONE or BIND_ZONES in .env"

# 1. Generate the key if we don't have one yet
if [ -z "$BIND_TSIG_SECRET" ]; then
  log "Generating TSIG key '${KEY_NAME}' (openssl rand -base64 32)…"
  BIND_TSIG_SECRET="$(openssl rand -base64 32)"
  env_set BIND_TSIG_NAME "$KEY_NAME"
  env_set BIND_TSIG_SECRET "$BIND_TSIG_SECRET"
else
  log "Reusing existing TSIG key from .env"
fi

# The portal host's LAN IP is used for allow-transfer (AXFR record listing).
# Prefer the default-route source address — docker bridge gateways (172.x on
# docker0/br-*) never own the default route, so this cannot pick a docker IP.
PORTAL_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | grep -v '^127\.' | head -1 || true)"
if [ -z "$PORTAL_IP" ]; then
    # Fall back to a global-scope address that isn't on a docker/virtual iface.
    PORTAL_IP="$(ip -4 addr show scope global 2>/dev/null | \
        awk '/^[0-9]+: (docker|br-|veth|virbr|lo):/ { skip=1; next } /^[0-9]+: / { skip=0 } !skip && /inet / { print $2; exit }' | cut -d/ -f1 || true)"
fi
[ -n "$PORTAL_IP" ] || PORTAL_IP="$(env_get CERULEAN_PORTAL_IP 127.0.0.1)"
log "allow-transfer will permit portal host IP: ${PORTAL_IP}"

# 2. Remote prep: python3 (zone patcher) and dnsutils (dig for AXFR)
log "Ensuring python3 + dnsutils on ${BIND_SSH_HOST}…"
ssh_run 'command -v python3 >/dev/null || (apt-get update -y && apt-get install -y python3); command -v dig >/dev/null || (apt-get update -y && apt-get install -y dnsutils)' >/dev/null

# 3. Install the key on the BIND server (idempotent: only write if absent)
log "Installing TSIG key on ${BIND_SSH_HOST}…"
KEY_FILE="/etc/bind/cerulean.keys"
KEY_BLOCK=$(printf 'key "%s" {\n\talgorithm hmac-sha256;\n\tsecret "%s";\n};' "$KEY_NAME" "$BIND_TSIG_SECRET")
ssh_run "test -f ${KEY_FILE} || printf '%s\n' '${KEY_BLOCK}' > ${KEY_FILE}"
ssh_run "grep -q 'include \"${KEY_FILE}\";' /etc/bind/named.conf || sed -i '1i include \"${KEY_FILE}\";' /etc/bind/named.conf"

# 4. Patch zone blocks: allow-update + allow-transfer (brace-aware, with backup)
log "Patching zones [${BIND_ZONES}] on ${BIND_SSH_HOST}…"
# The patcher is embedded base64 so no quoting can break it on either shell.
PY_PATCH=$(cat <<'PYEOF'
import re, shutil, time, sys

path = sys.argv[1]
zones = [z.strip() for z in sys.argv[2].split(",") if z.strip()]
keyname = sys.argv[3]
portal_ip = sys.argv[4]

try:
    src = open(path).read()
except FileNotFoundError:
    print("skipped (not present): " + path)
    sys.exit(0)

changed = False
for zone in zones:
    m = re.search(r"zone\s+[\"']" + re.escape(zone) + r"[\"']\s*\{", src)
    if not m:
        print("zone not found in " + path + ": " + zone)
        continue
    start = src.index("{", m.start())
    depth = 0
    end = start
    for j in range(start, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                end = j
                break
    body = src[start + 1 : end]
    want = [
        "allow-update { key \"%s\"; };" % keyname,
        "allow-transfer { %s; };" % portal_ip,
    ]
    for line in want:
        if line not in body:
            body = body + "\n    " + line
            changed = True
    src = src[: start + 1] + body + "\n" + src[end:]

if changed:
    shutil.copy(path, path + ".bak-cerulean")
    open(path, "w").write(src)
    print("patched " + path)
else:
    print("no change needed: " + path)
PYEOF
)
B64=$(printf '%s' "$PY_PATCH" | base64 -w0)
ssh_run "printf '%s' '$B64' | base64 -d > /tmp/cerulean-patch.py && python3 /tmp/cerulean-patch.py /etc/bind/named.conf '$BIND_ZONES' '$KEY_NAME' '$PORTAL_IP' && python3 /tmp/cerulean-patch.py /etc/bind/named.conf.local '$BIND_ZONES' '$KEY_NAME' '$PORTAL_IP' && rm -f /tmp/cerulean-patch.py"

# 5. Validate and reload (roll back on failure)
log "Validating configuration (named-checkconf)…"
if ! ssh_run "named-checkconf"; then
  ssh_run "for f in /etc/bind/named.conf /etc/bind/named.conf.local; do if [ -f \"\$f.bak-cerulean\" ]; then cp \"\$f.bak-cerulean\" \"\$f\" && rm -f \"\$f.bak-cerulean\"; fi; done; systemctl reload named 2>/dev/null || systemctl reload bind9 2>/dev/null || true"
  fail "named-checkconf failed — restored backups, BIND untouched"
fi
log "Reloading BIND…"
ssh_run "systemctl reload named 2>/dev/null || systemctl reload bind9 2>/dev/null || (systemctl restart named || systemctl restart bind9) || true"

ok "BIND is configured. TSIG key written to ${ENV_FILE}"
echo
echo "   BIND_TSIG_NAME=${KEY_NAME}"
echo "   BIND_TSIG_SECRET=${BIND_TSIG_SECRET}"
echo
echo "   Zones patched: ${BIND_ZONES} (allow-update + allow-transfer ${PORTAL_IP})"
