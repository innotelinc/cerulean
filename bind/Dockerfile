# ── Bundled BIND + SSH for BIND_MODE=local ─────────────────────────────────
# Runs authoritative BIND (named) with dynamic-update zones, plus sshd so the
# Cerulean portal can manage records exactly like a remote BIND box (nsupdate
# over SSH + TSIG, dig AXFR for zone listing).
#
# The entrypoint builds /etc/bind from environment variables:
#   BIND_ZONES        comma-separated zones to serve (default CERULEAN_ZONE)
#   BIND_TSIG_NAME    TSIG key name (default "cerulean")
#   BIND_TSIG_SECRET  TSIG secret; generated if empty (printed to the log)
#   BIND_SSH_PASSWORD root SSH password; generated if empty (printed)
#   BIND_PORTAL_IPS   comma-separated IPs allowed to AXFR (default "any")
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bind9 dnsutils openssh-server procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /etc/bind/zones

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53/udp 53/tcp 22

ENTRYPOINT ["/entrypoint.sh"]