#!/usr/bin/env bash
# Say something when the Authentik updater fails.
#
# The updater alerts for the failures it can describe itself (a rollback, a pin
# that would not move, an outpost that stayed behind): it mails ALERT_EMAIL_TO
# and POSTs ALERT_WEBHOOK_URL from inside the run, and records that it did in
# $STATE_DIR/last-alert. This script is wired with OnFailure= so the failures it
# cannot describe — the process killed, docker gone, a start limit hit — still
# reach a person, and it stays quiet when the run already spoke.
#
# Usage: authentik-update-alert.sh [unit]        (default authentik-update.service)
# Exit: 0 always. A failed alert must not add a second failing unit to the pile.
set -uo pipefail

UNIT=${1:-authentik-update.service}
ALERT_TO=${ALERT_EMAIL_TO:-}
ALERT_WEBHOOK=${ALERT_WEBHOOK_URL:-}
STATE=${AUTHENTIK_UPDATE_STATE:-/var/lib/innotel/authentik-update}
QUIET_SECONDS=${ALERT_QUIET_SECONDS:-600}

mkdir -p "$STATE" 2>/dev/null || STATE="${TMPDIR:-/tmp}"

# The run alerted for itself if it wrote its own marker in the last few minutes.
if [ -f "$STATE/last-alert" ]; then
  stamped=$(stat -c %Y "$STATE/last-alert" 2>/dev/null || echo 0)
  age=$(( $(date +%s) - stamped ))
  if [ "$age" -lt "$QUIET_SECONDS" ]; then
    echo "authentik-update-alert: the run reported this itself ${age}s ago; not repeating"
    exit 0
  fi
fi

host=$(hostname -f 2>/dev/null || hostname)
result=$(systemctl show -p Result --value "$UNIT" 2>/dev/null || true)
code=$(systemctl show -p ExecMainStatus --value "$UNIT" 2>/dev/null || true)
body="$host: $UNIT failed (result=${result:-unknown}, exit=${code:-unknown})

$(journalctl -u "$UNIT" -n 15 --no-pager 2>/dev/null | tail -n 15)"
subject="Authentik update failed on $host (${result:-unknown}/${code:-unknown})"

printf '%s\n' "$body" >&2

if [ -n "$ALERT_TO" ] && [ -x /usr/sbin/sendmail ]; then
  printf 'To: %s\nSubject: %s\nFrom: authentik-update@%s\nAuto-Submitted: auto-generated\n\n%s\n' \
    "$ALERT_TO" "$subject" "$host" "$body" |
    /usr/sbin/sendmail -t || echo "authentik-update-alert: sendmail refused the message" >&2
fi

if [ -n "$ALERT_WEBHOOK" ]; then
  payload=$(printf '%s' "$subject" | sed 's/\\/\\\\/g; s/"/\\"/g')
  curl -fsS --max-time 15 -X POST -H 'Content-Type: application/json' \
    -d "{\"text\":\"$payload\"}" "$ALERT_WEBHOOK" >/dev/null ||
    echo "authentik-update-alert: the webhook refused the POST" >&2
fi

if [ -z "$ALERT_TO" ] && [ -z "$ALERT_WEBHOOK" ]; then
  echo "authentik-update-alert: nothing receives this (ALERT_EMAIL_TO / ALERT_WEBHOOK_URL unset); it is only in the journal" >&2
fi

exit 0
