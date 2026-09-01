#!/usr/bin/env bash
# Generate a TSIG key for Cerulean and print the BIND configuration snippets.
#
# The key is generated locally (openssl) — nothing is changed on the BIND
# server by this script. Paste the printed snippets into named.conf, then copy
# the BIND_TSIG_NAME / BIND_TSIG_SECRET lines into your .env.
#
# Usage: ./scripts/setup-bind.sh [key-name]
set -euo pipefail

KEY_NAME="${1:-cerulean.}"
SECRET="$(openssl rand -base64 32)"

echo "──────────────────────────────────────────────────────────────────"
echo "1) Add this key block to /etc/bind/named.conf (or a file it includes):"
echo "──────────────────────────────────────────────────────────────────"
cat <<EOF
key "${KEY_NAME}" {
    algorithm hmac-sha256;
    secret "${SECRET}";
};
EOF

echo
echo "──────────────────────────────────────────────────────────────────"
echo "2) Allow dynamic updates on each zone Cerulean manages"
echo "   (add to the zone blocks, e.g. inside \"zone \\\"innotel.us\\\" {\"):"
echo "──────────────────────────────────────────────────────────────────"
cat <<EOF
    allow-update { key "${KEY_NAME}"; };
EOF

echo
echo "──────────────────────────────────────────────────────────────────"
echo "3) Allow the portal to list records via zone transfer (AXFR)."
echo "   Add the portal host's IP to each zone block:"
echo "──────────────────────────────────────────────────────────────────"
cat <<EOF
    allow-transfer { <PORTAL_IP>; };
EOF

echo
echo "──────────────────────────────────────────────────────────────────"
echo "4) Restart BIND:  systemctl restart named   (or bind9/webmin UI)"
echo
echo "5) Add these to your Cerulean .env:"
echo "──────────────────────────────────────────────────────────────────"
cat <<EOF
BIND_TSIG_NAME=${KEY_NAME}
BIND_TSIG_SECRET=${SECRET}
EOF
echo
