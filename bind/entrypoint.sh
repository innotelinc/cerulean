#!/usr/bin/env bash
# Configure + start the bundled BIND + sshd for BIND_MODE=local.
set -euo pipefail

ZONES="${BIND_ZONES:-${CERULEAN_ZONE:-}}"
[ -n "$ZONES" ] || { echo "FATAL: BIND_ZONES (or CERULEAN_ZONE) must be set" >&2; exit 1; }

TSIG_NAME="${BIND_TSIG_NAME:-cerulean}"
TSIG_SECRET="${BIND_TSIG_SECRET:-}"
if [ -z "$TSIG_SECRET" ]; then
  TSIG_SECRET="$(openssl rand -base64 32)"
  echo "Generated TSIG secret for key '${TSIG_NAME}' — copy it into .env (BIND_TSIG_SECRET):"
  echo "  ${TSIG_SECRET}"
fi

# ── sshd ───────────────────────────────────────────────────────────────────
ROOT_PASS="${BIND_SSH_PASSWORD:-}"
if [ -z "$ROOT_PASS" ]; then
  ROOT_PASS="$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9' | head -c 24)"
  echo "Generated root SSH password — copy it into .env (BIND_SSH_PASSWORD):"
  echo "  ${ROOT_PASS}"
fi
echo "root:${ROOT_PASS}" | chpasswd
sed -i \
  -e 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' \
  -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' \
  -e 's/^#\?UsePAM.*/UsePAM no/' \
  /etc/ssh/sshd_config

# ── BIND: TSIG key file ────────────────────────────────────────────────────
cat > /etc/bind/cerulean.keys <<EOF
key "${TSIG_NAME}" {
  algorithm hmac-sha256;
  secret "${TSIG_SECRET}";
};
EOF

# ── BIND: named.conf + per-zone files ──────────────────────────────────────
# Build the allow-transfer address_match_list: "any" or comma-separated IPs.
PORTAL_IPS="${BIND_PORTAL_IPS:-any}"
if [ "$PORTAL_IPS" = "any" ]; then
  AT_LIST="any;"
else
  AT_LIST="$(echo "$PORTAL_IPS" | tr ',' ' ' | sed 's/  */; /g');"
fi
{
  echo 'options {'
  echo '  directory "/etc/bind/zones";'
  echo '  listen-on port 53 { any; };'
  echo '  listen-on-v6 port 53 { any; };'
  echo '  allow-query { any; };'
  echo '  recursion no;'
  echo "  allow-transfer { ${AT_LIST} };"
  echo '  dnssec-validation no;'
  echo '};'
  echo 'include "/etc/bind/cerulean.keys";'
  echo 'include "/etc/bind/named.conf.local";'
} > /etc/bind/named.conf

: > /etc/bind/named.conf.local
IFS=',' read -ra ZONE_LIST <<< "$ZONES"
for zone in "${ZONE_LIST[@]}"; do
  zone="$(echo "$zone" | tr -d ' ' | sed 's/\.$//')"
  [ -n "$zone" ] || continue
  ZONEFILE="/etc/bind/zones/db.${zone}"
  if [ ! -f "$ZONEFILE" ]; then
    SERIAL="$(date +%Y%m%d%H)"
    cat > "$ZONEFILE" <<EOF
\$TTL 300
@ IN SOA ns1.${zone}. hostmaster.${zone}. ( ${SERIAL} 3600 900 604800 86400 )
@ IN NS ns1.${zone}.
ns1 IN A 127.0.0.1
EOF
  fi
  cat >> /etc/bind/named.conf.local <<EOF
zone "${zone}" {
  type master;
  file "${ZONEFILE}";
  allow-update { key "${TSIG_NAME}"; };
};
EOF
done

# named runs as the "bind" user — make the whole tree group-readable and the
# zones dir group-writable (dynamic updates write journal + zone files there).
chown -R root:bind /etc/bind
chmod 644 /etc/bind/named.conf /etc/bind/named.conf.local /etc/bind/cerulean.keys
chmod 775 /etc/bind/zones

# ── Validate + start ───────────────────────────────────────────────────────
named-checkconf || { echo "FATAL: named-checkconf failed" >&2; exit 1; }
/usr/sbin/sshd
echo "BIND ready: zones=${ZONES} tsig=${TSIG_NAME} ssh=22"
exec /usr/sbin/named -g -u bind