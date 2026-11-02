#!/usr/bin/env bash
# Keep Cerulean's Authentik server and worker on the newest published release.
#
# Authentik is this estate's identity plane, and its server and worker share one
# image tag. That tag is pinned in two tracked files — cerulean's
# docker-compose.yml (the source of truth) and the generated
# ips/groups/1-primary.yml that the primary host deploys — and Monarch's LDAP
# outpost runs on the same version line, because an outpost is a client of the
# server. "Updating Authentik" is therefore one version applied everywhere, then
# committed, not one container recreated.
#
# The run is: resolve the newest release, stop when it is already the pin, pull
# it, take the bump, recreate the two containers, and only once they come up
# healthy commit and push the pins. A release whose image has not been built yet
# is reported and left for the next run — never deployed from source, never
# half-applied. A failed recreate restores the files and the old containers.
#
# Usage:
#   authentik-update.sh [--dry-run] [--no-deploy] [--no-push] [--no-outpost]
#                       [--notify-only] [--root DIR] [--version X.Y.Z]
#
# Environment:
#   ESTATE_ROOT               checkout root holding 1-primary/ and ips/
#                             (default /usr/src/projects/complete)
#   CERULEAN_DIR              cerulean checkout
#                             (default $ESTATE_ROOT/1-primary/cerulean)
#   STACK_DIR                 ips (platform-stack) checkout
#                             (default $ESTATE_ROOT/ips)
#   MONARCH_DIR               monarch checkout, when this host has one
#                             (default $ESTATE_ROOT/3-media/monarch)
#   AUTHENTIK_HEALTH_URL      server readiness probe, used only when the image
#                             ships no healthcheck
#                             (default http://127.0.0.1:9000/-/health/live/)
#   AUTHENTIK_HEALTH_TIMEOUT  seconds to wait for healthy (default 600)
#   AUTHENTIK_OUTPOST_HOST    where the LDAP outpost runs when it is not on this
#                             host, as user@address — reached over ssh with a
#                             key, or with SSHPASS and sshpass installed
#   AUTHENTIK_OUTPOST_NAME    the outpost container (default authentik-ldap)
#   ALERT_EMAIL_TO            mailbox a failed update is mailed to (sendmail)
#   ALERT_WEBHOOK_URL         JSON webhook a failed update is POSTed to
#   AUTHENTIK_UPDATE_STATE    alert/state directory
#                             (default /var/lib/innotel/authentik-update)
#   AUTHENTIK_IMAGE_GRACE     how long a released release may lack a pullable
#                             image before that is alerted on (default 21600s)
#   OUTPOST_ALERT_COOLDOWN    seconds between repeated outpost-behind alerts
#                             (default 21600)
#   CERULEAN_GIT_DIR          a real cerulean checkout this host may push from;
#                             deploy-side edits are mirrored into it and committed
#                             there, so what runs and what the repo records match
#   STACK_GIT_DIR             the same, for the platform-stack checkout
#   AUTHENTIK_UPDATE_LOCK     lock file (default /run/lock/authentik-update.lock)
#   GITHUB_TOKEN              raises the GitHub API rate limit (optional)
#
# Install (timer: once a day at 06:00):
#   install -Dm755 authentik-update.sh /opt/innotel/authentik-update/authentik-update.sh
#   install -Dm755 authentik-update-alert.sh /opt/innotel/authentik-update/authentik-update-alert.sh
#   install -Dm644 authentik-update.service /etc/systemd/system/authentik-update.service
#   install -Dm644 authentik-update-failed.service /etc/systemd/system/authentik-update-failed.service
#   install -Dm644 authentik-update.timer   /etc/systemd/system/authentik-update.timer
#   install -Dm644 authentik-update-announce.service /etc/systemd/system/authentik-update-announce.service
#   install -Dm644 authentik-update-announce.timer   /etc/systemd/system/authentik-update-announce.timer
#   systemctl daemon-reload && systemctl enable --now authentik-update.timer authentik-update-announce.timer
#
# Alerting is configured in /etc/innotel/authentik-update.env (ALERT_EMAIL_TO
# and/or ALERT_WEBHOOK_URL). Without either, a failure is only in the journal.
#
# Exit: 0 current or updated · 1 update or deploy failed · 2 precondition.
set -euo pipefail

ROOT="${ESTATE_ROOT:-/usr/src/projects/complete}"
CERULEAN_DIR="${CERULEAN_DIR:-$ROOT/1-primary/cerulean}"
STACK_DIR="${STACK_DIR:-$ROOT/ips}"
MONARCH_DIR="${MONARCH_DIR:-$ROOT/3-media/monarch}"

COMPOSE="$CERULEAN_DIR/docker-compose.yml"
README="$CERULEAN_DIR/README.md"
APP_ENV="$CERULEAN_DIR/.env"
STACK_ENV="$STACK_DIR/.env"
GROUP_PRIMARY="$STACK_DIR/groups/1-primary.yml"
GROUP_MEDIA="$STACK_DIR/groups/3-media.yml"
MONARCH_COMPOSE="$MONARCH_DIR/docker-compose.yml"

HEALTH_URL="${AUTHENTIK_HEALTH_URL:-http://127.0.0.1:9000/-/health/live/}"
HEALTH_TIMEOUT="${AUTHENTIK_HEALTH_TIMEOUT:-600}"
LOCK="${AUTHENTIK_UPDATE_LOCK:-/run/lock/authentik-update.lock}"

OUTPOST_HOST="${AUTHENTIK_OUTPOST_HOST:-}"
OUTPOST_NAME="${AUTHENTIK_OUTPOST_NAME:-authentik-ldap}"
ALERT_TO="${ALERT_EMAIL_TO:-}"
ALERT_WEBHOOK="${ALERT_WEBHOOK_URL:-}"
STATE_DIR="${AUTHENTIK_UPDATE_STATE:-/var/lib/innotel/authentik-update}"
IMAGE_GRACE="${AUTHENTIK_IMAGE_GRACE:-21600}"
CERULEAN_GIT_DIR="${CERULEAN_GIT_DIR:-}"
STACK_GIT_DIR="${STACK_GIT_DIR:-}"
OUTPOST=true
NOTIFY_ONLY=false
mkdir -p "$STATE_DIR" 2>/dev/null || STATE_DIR="${TMPDIR:-/tmp}"

API="https://api.github.com/repos/goauthentik/authentik/releases/latest"
IMAGE="ghcr.io/goauthentik/server"
SERVER_CONTAINERS=(cerulean-authentik cerulean-authentik-server authentik-server)
WORKER_CONTAINERS=(cerulean-authentik-worker authentik-worker)

DRY_RUN=false
DEPLOY=true
PUSH=true
REQUESTED_VERSION=""

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
warn() { printf '%s WARNING: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

# A failure that nobody hears about is the same as no update: this identity
# plane is the estate's only door, and a run that rolled back or never applied
# has to reach a person. Best effort on purpose — a broken alert channel must
# not turn into a second failure that hides the first.
alert() {  # subject, body
  local subject=$1 body=$2 payload host
  host=$(hostname -f 2>/dev/null || hostname)
  printf '%s\n' "$body" | sed 's/^/  /' >&2
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$subject" >>"$STATE_DIR/last-alert" 2>/dev/null || true
  if [ -n "$ALERT_TO" ] && [ -x /usr/sbin/sendmail ]; then
    printf 'To: %s\nSubject: %s\nFrom: authentik-update@%s\nAuto-Submitted: auto-generated\n\n%s\n' \
      "$ALERT_TO" "$subject" "$host" "$body" |
      /usr/sbin/sendmail -t || warn "could not hand the alert to sendmail — it is only in the journal"
  fi
  if [ -n "$ALERT_WEBHOOK" ]; then
    payload=$(printf '%s' "$subject — $body" | tr '\n' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g')
    curl -fsS --max-time 15 -X POST -H 'Content-Type: application/json' \
      -d "{\"text\":\"$payload\"}" "$ALERT_WEBHOOK" >/dev/null ||
      warn "the alert webhook refused the POST — it is only in the journal"
  fi
  if [ -z "$ALERT_TO" ] && [ -z "$ALERT_WEBHOOK" ]; then
    warn "nothing receives this alert (ALERT_EMAIL_TO / ALERT_WEBHOOK_URL unset); it is only in the journal"
  fi
}

die() {
  local code=$1 msg
  shift
  msg=$(printf '%s ERROR: %s' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*")
  printf '%s\n' "$msg" >&2
  # Exit 2 is a precondition this host can fix; exit 1 is a failed update.
  if [ "$code" -eq 1 ]; then alert "Authentik update failed on $(hostname)" "$msg"; fi
  exit "$code"
}

usage() {
  sed -n '2,43p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true ;;
    --no-deploy) DEPLOY=false ;;
    --no-push) PUSH=false ;;
    --no-outpost) OUTPOST=false ;;
    --notify-only) NOTIFY_ONLY=true ;;
    --root)
      [ $# -ge 2 ] || die 2 "--root needs a directory"
      ROOT=$2
      CERULEAN_DIR="$ROOT/1-primary/cerulean"
      STACK_DIR="$ROOT/ips"
      MONARCH_DIR="$ROOT/3-media/monarch"
      COMPOSE="$CERULEAN_DIR/docker-compose.yml"
      README="$CERULEAN_DIR/README.md"
      APP_ENV="$CERULEAN_DIR/.env"
      STACK_ENV="$STACK_DIR/.env"
      GROUP_PRIMARY="$STACK_DIR/groups/1-primary.yml"
      GROUP_MEDIA="$STACK_DIR/groups/3-media.yml"
      MONARCH_COMPOSE="$MONARCH_DIR/docker-compose.yml"
      shift
      ;;
    --version)
      [ $# -ge 2 ] || die 2 "--version needs a release"
      REQUESTED_VERSION=$2
      shift
      ;;
    -h|--help) usage ;;
    *) die 2 "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

# One run at a time: a slow migrate must not overlap the next timer tick.
if command -v flock >/dev/null 2>&1; then
  mkdir -p "$(dirname "$LOCK")" 2>/dev/null || true
  exec 9>"$LOCK" || die 2 "cannot open the lock file $LOCK"
  if ! flock -n 9; then
    log "another run holds $LOCK; leaving it alone"
    exit 0
  fi
fi

# ── The release ──────────────────────────────────────────────────────────────
latest_release() {
  local body tag
  if [ -n "$REQUESTED_VERSION" ]; then
    printf '%s\n' "$REQUESTED_VERSION"
    return 0
  fi
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    body=$(curl -fsS --max-time 30 -H "Authorization: Bearer $GITHUB_TOKEN" "$API") ||
      die 1 "could not reach the GitHub releases API"
  else
    body=$(curl -fsS --max-time 30 "$API") || die 1 "could not reach the GitHub releases API"
  fi
  tag=$(printf '%s\n' "$body" |
    sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -1)
  tag=${tag#version/}
  printf '%s\n' "${tag#v}"
}

# ── The pin ──────────────────────────────────────────────────────────────────
pin_in_compose() {  # file → the default tag in ${AUTHENTIK_IMAGE_TAG:-X}
  sed -nE 's#.*goauthentik/server:\$\{AUTHENTIK_IMAGE_TAG:-([0-9][0-9.]*)\}.*#\1#p' "$1" | head -1
}

pin_in_env() {  # file → AUTHENTIK_IMAGE_TAG, when that file sets it
  [ -f "$1" ] || return 0
  sed -nE 's/^[[:space:]]*AUTHENTIK_IMAGE_TAG="?([0-9][0-9.]*)"?[[:space:]]*$/\1/p' "$1" | head -1
}

newer_than() {  # candidate, current → is candidate newer
  [ -n "$2" ] && [ "$1" != "$2" ] &&
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

image_available() {  # image:tag → can this host actually pull it
  local ref=$1 tag repo tok code
  docker manifest inspect "$ref" >/dev/null 2>&1 && return 0
  # `docker manifest inspect` has reported "no such manifest" for a tag the
  # registry serves (2026.8.5 answered 200 while the CLI said it was missing), so
  # ask ghcr directly before calling a published release unbuilt. Guessing here
  # is costly in both directions: a false "missing" never updates, a false
  # "present" bumps to a tag that makes the next recreate fail.
  tag=${ref##*:}
  repo=${ref%:*}
  repo=${repo#ghcr.io/}
  tok=$(curl -fsS --max-time 30 "https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull" 2>/dev/null |
    sed -nE 's/.*"token"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p')
  [ -n "$tok" ] || return 1
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
    -H "Authorization: Bearer $tok" \
    -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json' \
    "https://ghcr.io/v2/${repo}/manifests/${tag}")
  [ "$code" = 200 ]
}

# ── The LDAP outpost: the Jellyfin login gate ────────────────────────────────
# The `jellyfin-ldap` provider is served by an outpost container, and an outpost
# is a client of the server: it has to run the server's version line or Jellyfin
# binds fail and the estate's drift check fails the run. It usually lives on
# another host (Monarch), so this recreates a local one, or reaches the host
# named by AUTHENTIK_OUTPOST_HOST and does the same there. The pin was already
# moved above in both compose files that declare it.

outpost_listening() {  # container → the LDAP listener is bound (3389 = 0xD3D)
  docker exec "$1" sh -c 'grep -qi ":0D3D" /proc/net/tcp /proc/net/tcp6 2>/dev/null' >/dev/null 2>&1
}

wait_outpost() {  # container, seconds
  local c=$1 deadline=$((SECONDS + ${2:-180})) state
  while [ "$SECONDS" -lt "$deadline" ]; do
    state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)
    if [ "$state" = running ] && outpost_listening "$c"; then return 0; fi
    sleep 3
  done
  return 1
}

recreate_local_outpost() {  # container
  local c=$1 project workdir files svc f
  local -a cmd=(docker compose)
  project=$(label_of "$c" com.docker.compose.project)
  workdir=$(label_of "$c" com.docker.compose.project.working_dir)
  files=$(label_of "$c" com.docker.compose.project.config_files)
  svc=$(label_of "$c" com.docker.compose.service)
  if [ -n "$project" ] && [ "$project" != "<no value>" ]; then cmd+=(--project-name "$project"); fi
  if [ -n "$workdir" ] && [ "$workdir" != "<no value>" ]; then cmd+=(--project-directory "$workdir"); fi
  if [ -n "$files" ] && [ "$files" != "<no value>" ]; then
    for f in $(printf '%s' "$files" | tr ',' ' '); do
      cmd+=(-f "$f")
      # Move the pin where this container was started from too, so the next
      # `compose up` on this host does not put the previous tag back.
      [ -f "$f" ] || continue
      grep -q 'goauthentik/ldap:[0-9]' "$f" || continue
      cp -a "$f" "$f.outpost-bak" 2>/dev/null || true
      sed -i -E "s#(goauthentik/ldap:)[0-9][0-9.]+#\1${latest}#g" "$f"
    done
  fi
  if [ -n "$workdir" ] && [ "$workdir" != "<no value>" ] && [ -f "$workdir/.env" ]; then
    cmd+=(--env-file "$workdir/.env")
  fi
  cmd+=(--profile authentik)
  "${cmd[@]}" up -d --no-deps "$svc" >/dev/null
}

# The same recreation, run on the host that owns the outpost. Sent over ssh as a
# script on stdin: the remote needs no copy of this file, only docker compose,
# which it already uses to run the container.
REMOTE_OUTPOST=$(cat <<'REMOTE'
set -eu
version=$1
name=$2
c=""
for n in "$name" cerulean-authentik-ldap authentik-ldap-outpost; do
  if docker inspect "$n" >/dev/null 2>&1; then c=$n; break; fi
done
if [ -z "$c" ]; then
  c=$(docker ps -a --format '{{.Names}} {{.Image}}' | awk '/goauthentik\/ldap/ {print $1; exit}')
fi
if [ -z "$c" ]; then
  echo "no goauthentik/ldap container on $(hostname)"
  exit 3
fi
lab() { docker inspect -f "{{index .Config.Labels \"$1\"}}" "$c" 2>/dev/null || true; }
project=$(lab com.docker.compose.project)
workdir=$(lab com.docker.compose.project.working_dir)
files=$(lab com.docker.compose.project.config_files)
svc=$(lab com.docker.compose.service)
set -- docker compose
if [ -n "$project" ] && [ "$project" != "<no value>" ]; then set -- "$@" --project-name "$project"; fi
if [ -n "$workdir" ] && [ "$workdir" != "<no value>" ]; then set -- "$@" --project-directory "$workdir"; fi
if [ -n "$files" ] && [ "$files" != "<no value>" ]; then
  for f in $(printf '%s' "$files" | tr ',' ' '); do set -- "$@" -f "$f"; done
fi
if [ -n "$workdir" ] && [ "$workdir" != "<no value>" ] && [ -f "$workdir/.env" ]; then
  set -- "$@" --env-file "$workdir/.env"
fi
# Move the pin where the container was started from too, so a later `compose up`
# on that host does not put the old tag back.
if [ -n "$files" ] && [ "$files" != "<no value>" ]; then
  for f in $(printf '%s' "$files" | tr ',' ' '); do
    [ -f "$f" ] || continue
    cp -a "$f" "$f.outpost-bak" 2>/dev/null || true
    sed -i -E "s#(goauthentik/ldap:)[0-9][0-9.]+#\1${version}#g" "$f"
  done
fi
"$@" --profile authentik up -d --no-deps "$svc" >/dev/null
i=0
while [ "$i" -lt 60 ]; do
  st=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)
  if [ "$st" = running ] && docker exec "$c" sh -c 'grep -qi ":0D3D" /proc/net/tcp /proc/net/tcp6 2>/dev/null'; then
    echo "serving $(docker inspect -f '{{.Config.Image}}' "$c")"
    exit 0
  fi
  i=$((i + 1))
  sleep 3
done
echo "did not come up (state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing))"
docker logs --tail 20 "$c" 2>&1 || true
exit 1
REMOTE
)

ssh_to() {  # target, remote command — stdin is the remote script
  if [ -n "${SSHPASS:-}" ] && command -v sshpass >/dev/null 2>&1; then
    sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$1" "$2"
  else
    ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$1" "$2"
  fi
}

# Deliberately not find_container: this runs before the server-side helpers are
# defined, because the "server is current" branch asks about the outpost too.
# Shared with the server/worker recreation below, and needed before it.
label_of() { docker inspect -f "{{index .Config.Labels \"$2\"}}" "$1" 2>/dev/null || true; }

outpost_container() {  # name of the LDAP outpost container, "" when there is none
  local n c
  for n in "$OUTPOST_NAME" cerulean-authentik-ldap authentik-ldap-outpost; do
    if docker inspect "$n" >/dev/null 2>&1; then printf '%s' "$n"; return 0; fi
  done
  c=$(docker ps -a --format '{{.Names}} {{.Image}}' 2>/dev/null |
    awk '/goauthentik\/ldap/ {print $1; exit}')
  printf '%s' "$c"
}

outpost_tag() {  # the tag the outpost actually runs, "" when it cannot be read
  local c img=""
  c=$(outpost_container)
  if [ -n "$c" ]; then
    img=$(docker inspect -f '{{.Config.Image}}' "$c" 2>/dev/null || true)
  elif [ -n "$OUTPOST_HOST" ]; then
    img=$(printf '%s\n' "docker inspect -f '{{.Config.Image}}' '$OUTPOST_NAME' 2>/dev/null || docker ps -a --format '{{.Image}}' | grep goauthentik/ldap | head -1" |
      ssh_to "$OUTPOST_HOST" 'bash -s' 2>/dev/null | tr -d '\r' | head -1)
  fi
  case "$img" in
    *:*) printf '%s' "${img##*:}" ;;
  esac
}

alert_outpost() {  # subject, body — the outpost lags on purpose sometimes, so once per cooldown
  local marker="$STATE_DIR/outpost-alert" now last cooldown
  cooldown="${OUTPOST_ALERT_COOLDOWN:-21600}"
  now=$(date +%s)
  last=$(sed -n '1p' "$marker" 2>/dev/null || true)
  case "$last" in ''|*[!0-9]*) last=0 ;; esac
  if [ $((now - last)) -lt "$cooldown" ]; then
    warn "the LDAP outpost is still behind $latest; already reported $((now - last))s ago (cooldown ${cooldown}s)"
    return 0
  fi
  printf '%s\n' "$now" >"$marker" 2>/dev/null || true
  alert "$1" "$2"
}

enter_outpost() {
  local outpost_c rc
  if [ "$OUTPOST" = false ]; then
    log "not touching the LDAP outpost (--no-outpost)"
    return 0
  fi
  if [ "$DRY_RUN" = true ] || [ "$DEPLOY" = false ]; then
    log "not recreating the LDAP outpost (--dry-run/--no-deploy)"
    return 0
  fi
  outpost_c=$(outpost_container)
  if [ -n "$outpost_c" ]; then
    log "recreating the LDAP outpost $outpost_c"
    if recreate_local_outpost "$outpost_c" && wait_outpost "$outpost_c"; then
      rm -f "$STATE_DIR/outpost-alert"
      log "the LDAP outpost $outpost_c is serving $latest"
      return 0
    fi
    alert "Authentik $latest is live but its LDAP outpost did not start on $(hostname)" \
      "Jellyfin's LDAP-Auth binds through $outpost_c; until it serves 3389 every media login fails with LDAP 49."
    return 1
  fi
  if [ -n "$OUTPOST_HOST" ]; then
    log "recreating the LDAP outpost on $OUTPOST_HOST"
    rc=0
    printf '%s\n' "$REMOTE_OUTPOST" | ssh_to "$OUTPOST_HOST" "bash -s -- '$latest' '$OUTPOST_NAME'" || rc=$?
    if [ "$rc" -eq 0 ]; then
      rm -f "$STATE_DIR/outpost-alert"
      log "the LDAP outpost on $OUTPOST_HOST is serving $latest"
      return 0
    fi
    # 3 is the outpost saying it has no such container, 255 is ssh itself. Both
    # leave the server healthy and the outpost behind, and both are reported
    # once per cooldown rather than on every tick.
    if [ "$rc" -eq 3 ]; then
      alert_outpost "Authentik $latest is live but no LDAP outpost was found on $OUTPOST_HOST" \
        "Nothing there runs a goauthentik/ldap container; if the outpost moved, repoint AUTHENTIK_OUTPOST_HOST."
      return 0
    fi
    if [ "$rc" -eq 255 ] || [ "$rc" -eq 127 ]; then
      alert_outpost "Authentik $latest is live but $OUTPOST_HOST could not be reached to move its LDAP outpost" \
        "ssh exited $rc. Jellyfin binds through that outpost and it is still on the previous release: give this host key access (or SSHPASS plus sshpass) to $OUTPOST_HOST."
      return 0
    fi
    alert_outpost "Authentik $latest is live but its LDAP outpost on $OUTPOST_HOST did not start" \
      "It was recreated and did not serve 3389, so Jellyfin LDAP-Auth binds fail until it does."
    return 1
  fi
  log "no LDAP outpost on this host and no AUTHENTIK_OUTPOST_HOST set; the pin moved, nothing to recreate"
  return 0
}

# ── Announcement ─────────────────────────────────────────────────────────────
# The apply run is 06:00. This is the same resolution, earlier, with nothing
# pulled and nothing restarted: a release that landed overnight is reported
# before the window opens, so it can be held by hand while the estate is quiet.

release_published() {  # version → its published date, "" when it cannot be read
  local body
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    body=$(curl -fsS --max-time 20 -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://api.github.com/repos/goauthentik/authentik/releases/tags/version/$1" 2>/dev/null || true)
  else
    body=$(curl -fsS --max-time 20 \
      "https://api.github.com/repos/goauthentik/authentik/releases/tags/version/$1" 2>/dev/null || true)
  fi
  printf '%s\n' "$body" |
    sed -nE 's/.*"published_at"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -1
}

announce() {  # current, latest
  local current=$1 latest=$2 marker published
  if [ "$latest" = "$current" ]; then
    log "authentik $current is current; nothing to announce"
    return 0
  fi
  if ! newer_than "$latest" "$current"; then
    log "authentik $latest is not newer than the running $current; nothing to announce"
    return 0
  fi
  marker="$STATE_DIR/announced-$latest"
  if [ -f "$marker" ]; then
    log "authentik $latest was already announced; the 06:00 run applies it"
    return 0
  fi
  published=$(release_published "$latest")
  alert "Authentik $latest is published${published:+ ($published)}" \
    "$(hostname) runs authentik $current. The next apply run — 06:00 — will pull $latest, restart the server and worker, and move the Jellyfin LDAP outpost. Preview with --dry-run; hold it by pinning AUTHENTIK_IMAGE_TAG in the cerulean .env."
  printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$marker" 2>/dev/null || true
  log "announced authentik $latest${published:+ (published $published)}; the 06:00 run applies it"
}

latest=$(latest_release)
[[ "$latest" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die 1 "could not resolve a stable Authentik release (got '$latest')"

[ -f "$COMPOSE" ] || die 2 "no cerulean compose at $COMPOSE (set --root or ESTATE_ROOT)"
pinned=$(pin_in_compose "$COMPOSE")
[ -n "$pinned" ] || die 2 "no AUTHENTIK_IMAGE_TAG default in $COMPOSE"
# An .env entry wins over the compose default at runtime, so it is the pin that
# is actually deployed.
current=$(pin_in_env "$APP_ENV")
[ -n "$current" ] || current=$pinned

# Announcement resolves and reports only: no pull, no recreate, no commit.
if [ "$NOTIFY_ONLY" = true ]; then
  announce "$current" "$latest"
  exit 0
fi

if [ "$latest" = "$current" ] && [ "$pinned" = "$current" ]; then
  log "authentik $current is current"
  # The server can be current while the outpost that depends on it is not — the
  # state a run leaves when it could not reach that host, or when the outpost was
  # recreated by hand from the previous tag. Reconcile it here so the Jellyfin
  # gate also catches up on the tick after its host becomes reachable.
  if [ "$OUTPOST" = true ] && [ "$DEPLOY" = true ] && [ "$DRY_RUN" = false ]; then
    outpost_now=$(outpost_tag || true)
    if [ -n "$outpost_now" ] && [ "$outpost_now" != "$current" ]; then
      log "the LDAP outpost runs $outpost_now while the server runs $current; moving it"
      enter_outpost || exit 1
    fi
  fi
  exit 0
fi
if ! newer_than "$latest" "$current"; then
  if [ "$pinned" != "$current" ]; then
    warn "authentik runs $current but $COMPOSE still defaults to $pinned; leaving both alone — $latest is not newer than the running release"
  else
    log "authentik $latest is not newer than the running $current; leaving it alone"
  fi
  exit 0
fi

# Refuse before touching anything: a bump folded into someone's uncommitted work
# is a commit nobody asked for. Only the files this script edits are considered,
# so an unrelated dashboard or doc edit neither blocks an update nor rides along
# in its commit.
watch_files=("$COMPOSE" "$README" "$GROUP_PRIMARY" "$MONARCH_COMPOSE" "$GROUP_MEDIA")
# The pin also has to move in the checkouts this host can push from; they are
# edited directly when the deploy copy has no such file (the group composes on a
# host that only runs one group).
if [ -n "$CERULEAN_GIT_DIR" ]; then
  watch_files+=("$CERULEAN_GIT_DIR/docker-compose.yml" "$CERULEAN_GIT_DIR/README.md")
fi
if [ -n "$STACK_GIT_DIR" ]; then
  watch_files+=("$STACK_GIT_DIR/groups/1-primary.yml" "$STACK_GIT_DIR/groups/3-media.yml")
fi
for repo in "$CERULEAN_DIR" "$STACK_DIR" "$MONARCH_DIR"; do
  [ -d "$repo/.git" ] || continue
  ours=()
  for f in "${watch_files[@]}"; do
    case "$f" in
      "$repo"/*)
        if git -C "$repo" ls-files --error-unmatch -- "$f" >/dev/null 2>&1; then
          ours+=("$f")
        fi
        ;;
    esac
  done
  [ "${#ours[@]}" -gt 0 ] || continue
  dirty=$(git -C "$repo" status --porcelain --untracked-files=no -- "${ours[@]}")
  if [ -n "$dirty" ]; then
    printf '%s\n' "$dirty" >&2
    die 2 "$repo has uncommitted changes in the files this bump edits; commit or stash them, then rerun"
  fi
done

# ── Only a pullable image is worth changing a pin for ────────────────────────
if [ "$DRY_RUN" = true ]; then
  log "dry-run: would move authentik $current -> $latest"
elif [ "$DEPLOY" = false ]; then
  log "authentik $current -> $latest (--no-deploy: the pin moves, nothing is pulled or recreated)"
else
  if ! image_available "$IMAGE:$latest"; then
    # A release exists on GitHub a little before its image is pushed to ghcr.
    # That is normal for an hour and suspicious after several, so the wait is
    # silent inside the grace window and an alert afterwards — a release that
    # never gets an image leaves the estate pinned and silent otherwise.
    now=$(date +%s)
    seen="$STATE_DIR/unpullable-$latest"
    [ -f "$seen" ] || printf '%s\n' "$now" >"$seen"
    first=$(cat "$seen" 2>/dev/null || printf '%s' "$now")
    waited=$((now - first))
    if [ "$waited" -lt "$IMAGE_GRACE" ]; then
      log "authentik $latest is released but $IMAGE:$latest is not built yet; retrying (${waited}s of the ${IMAGE_GRACE}s tolerated)"
      exit 0
    fi
    die 1 "authentik $latest has been released for ${waited}s and $IMAGE:$latest is still not pullable; the estate stays on $current"
  fi
  rm -f "$STATE_DIR/unpullable-$latest"
  log "pulling $IMAGE:$latest"
  docker pull "$IMAGE:$latest" >/dev/null ||
    die 1 "could not pull $IMAGE:$latest; leaving the pin at $current"
fi

# ── The bump ─────────────────────────────────────────────────────────────────
stamp=$(date -u +%Y%m%d-%H%M%S)
backed_up=()
edited=()

backup() {
  [ -f "$1" ] || return 0
  cp -a "$1" "$1.bak-$stamp"
  backed_up+=("$1")
}

bump_server_pin() {  # cerulean compose and its README both name the tag
  local file=$1 before
  [ -f "$file" ] || return 0
  grep -q 'AUTHENTIK_IMAGE_TAG:-[0-9]' "$file" || return 0
  before=$(cat "$file")
  sed -i -E 's#(goauthentik/server:\$\{AUTHENTIK_IMAGE_TAG:-)[0-9][0-9.]+(\})#\1'"$latest"'\2#g' "$file"
  if [ "$before" != "$(cat "$file")" ]; then edited+=("$file"); fi
}

bump_outpost_pin() {  # the LDAP outpost follows the server's version line
  local file=$1 before
  [ -f "$file" ] || return 0
  grep -q 'goauthentik/ldap:[0-9]' "$file" || return 0
  before=$(cat "$file")
  sed -i -E 's#(goauthentik/ldap:)[0-9][0-9.]+#\1'"$latest"'#g' "$file"
  if [ "$before" != "$(cat "$file")" ]; then edited+=("$file"); fi
}

bump_env_pin() {  # an .env override would otherwise keep running the old image
  local file=$1 before
  [ -n "$(pin_in_env "$file")" ] || return 0
  before=$(cat "$file")
  sed -i -E 's#^([[:space:]]*AUTHENTIK_IMAGE_TAG=)"?[0-9][0-9.]+"?#\1'"$latest"'#' "$file"
  if [ "$before" != "$(cat "$file")" ]; then edited+=("$file"); fi
}

for candidate in "${watch_files[@]}" "$APP_ENV" "$STACK_ENV"; do
  backup "$candidate"
done
bump_server_pin "$COMPOSE"
bump_server_pin "$README"
bump_server_pin "$GROUP_PRIMARY"   # generated: a tag-only bump is exactly its regeneration
bump_outpost_pin "$MONARCH_COMPOSE"
bump_outpost_pin "$GROUP_MEDIA"
bump_env_pin "$APP_ENV"
bump_env_pin "$STACK_ENV"
if [ -n "$CERULEAN_GIT_DIR" ]; then
  bump_server_pin "$CERULEAN_GIT_DIR/docker-compose.yml"
  bump_server_pin "$CERULEAN_GIT_DIR/README.md"
fi
if [ -n "$STACK_GIT_DIR" ]; then
  bump_server_pin "$STACK_GIT_DIR/groups/1-primary.yml"
  bump_outpost_pin "$STACK_GIT_DIR/groups/3-media.yml"
fi

if [ "${#edited[@]}" -eq 0 ]; then
  die 1 "nothing carried the pin — $COMPOSE has no tag to move and no group file matched"
fi
log "authentik $current -> $latest in: ${edited[*]}"

restore_files() {
  local f
  for f in "${backed_up[@]}"; do
    if [ -f "$f.bak-$stamp" ]; then cp -a "$f.bak-$stamp" "$f"; fi
  done
}

drop_backups() {
  local f
  for f in "${backed_up[@]}"; do rm -f "$f.bak-$stamp"; done
}

# ── Recreate the server and worker in place ──────────────────────────────────
find_container() {
  local name
  for name in "$@"; do
    if docker inspect "$name" >/dev/null 2>&1; then printf '%s' "$name"; return 0; fi
  done
  return 1
}


RECREATE_CMD=()
RECREATE_SERVICES=()

build_recreate_cmd() {  # server container, worker container
  local server_c=$1 worker_c=$2 project workdir files svc_server svc_worker f
  local -a files_list=()
  project=$(label_of "$server_c" com.docker.compose.project)
  workdir=$(label_of "$server_c" com.docker.compose.project.working_dir)
  files=$(label_of "$server_c" com.docker.compose.project.config_files)
  svc_server=$(label_of "$server_c" com.docker.compose.service)
  svc_worker=""
  if [ -n "$worker_c" ]; then svc_worker=$(label_of "$worker_c" com.docker.compose.service); fi

  if [ -z "$svc_server" ] || [ "$svc_server" = "<no value>" ]; then
    svc_server=authentik-server
  fi
  if [ -z "$svc_worker" ] || [ "$svc_worker" = "<no value>" ]; then
    if [ "$svc_server" != "${svc_server%-server}" ]; then
      svc_worker="${svc_server%-server}-worker"
    else
      svc_worker="$svc_server-worker"
    fi
  fi

  RECREATE_CMD=(docker compose)
  if [ -n "$project" ] && [ "$project" != "<no value>" ]; then
    RECREATE_CMD+=(--project-name "$project")
  fi
  if [ -n "$workdir" ] && [ "$workdir" != "<no value>" ]; then
    RECREATE_CMD+=(--project-directory "$workdir")
  fi
  if [ -n "$files" ] && [ "$files" != "<no value>" ]; then
    IFS=',' read -r -a files_list <<<"$files"
    for f in "${files_list[@]}"; do RECREATE_CMD+=(-f "$f"); done
  elif [ -f "$GROUP_PRIMARY" ]; then
    RECREATE_CMD+=(-f "$GROUP_PRIMARY")
  else
    RECREATE_CMD+=(-f "$COMPOSE")
  fi
  # Interpolate from the file the project was created with: its own directory's
  # .env. Handing Compose a different --env-file re-resolves secrets and hosts,
  # which is how an "update" turns into an outage. The stack's .env is the right
  # choice only when the compose file actually lives in the stack.
  if [ -n "$workdir" ] && [ "$workdir" != "<no value>" ] && [ -f "$workdir/.env" ]; then
    RECREATE_CMD+=(--env-file "$workdir/.env")
  elif [ -f "$STACK_ENV" ]; then
    case "$files" in
      "$STACK_DIR"/*) RECREATE_CMD+=(--env-file "$STACK_ENV") ;;
    esac
  fi
  # The Authentik services are profile-gated in both compose files.
  RECREATE_CMD+=(--profile authentik)
  RECREATE_SERVICES=("$svc_server" "$svc_worker")
}

recreate() {
  "${RECREATE_CMD[@]}" up -d --no-deps "${RECREATE_SERVICES[@]}"
}

wait_healthy() {  # server container, worker container (may be empty)
  local server_c=$1 worker_c=$2 deadline=$((SECONDS + HEALTH_TIMEOUT))
  local code="" state="" health="" waited=0
  while [ "$SECONDS" -lt "$deadline" ]; do
    # The image ships its own probe (`ak healthcheck`), so Docker's verdict is
    # the authoritative one; the HTTP probe covers an image without a
    # healthcheck. Note the path: this release answers /-/health/live/, while
    # /health/live/ is a 404 — waiting on the wrong one fails a good upgrade.
    health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
      "$server_c" 2>/dev/null || echo missing)
    state=running
    if [ -n "$worker_c" ]; then
      state=$(docker inspect -f '{{.State.Status}}' "$worker_c" 2>/dev/null || echo missing)
      if [ "$state" = exited ] || [ "$state" = dead ]; then
        log "the worker is $state while waiting for readiness"
        return 1
      fi
    fi
    if [ "$health" = healthy ] && [ "$state" = running ]; then
      return 0
    fi
    if [ "$health" = none ]; then
      code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$HEALTH_URL" 2>/dev/null || true)
      if { [ "$code" = 200 ] || [ "$code" = 204 ]; } && [ "$state" = running ]; then
        return 0
      fi
    fi
    waited=$((waited + 5))
    if [ $((waited % 60)) -eq 0 ]; then
      log "waiting for authentik $latest (server=$health${code:+, http=$code} worker=$state, ${waited}s)"
    fi
    sleep 5
  done
  return 1
}

rollback() {
  warn "restoring the previous Authentik files and containers"
  restore_files
  "${RECREATE_CMD[@]}" up -d --no-deps "${RECREATE_SERVICES[@]}" >/dev/null 2>&1 ||
    warn "recreating the previous containers failed too"
  warn "if $latest already ran its migrations, the database is ahead of the restored image — the dump taken before this run is the recovery point"
}

server_c=$(find_container "${SERVER_CONTAINERS[@]}" || true)
worker_c=$(find_container "${WORKER_CONTAINERS[@]}" || true)

if [ "$DEPLOY" = false ] || [ "$DRY_RUN" = true ]; then
  log "not recreating anything (--no-deploy/--dry-run)"
elif [ -z "$server_c" ]; then
  log "no Authentik container on this host; the pins are updated, nothing to recreate"
else
  # A version line change runs migrations; keep the pre-upgrade database.
  if [ "${current%.*}" != "${latest%.*}" ] && [ -x "$CERULEAN_DIR/scripts/authentik-db-backup.sh" ]; then
    log "the version line changes ${current%.*} -> ${latest%.*}; dumping the identity database first"
    if ! "$CERULEAN_DIR/scripts/authentik-db-backup.sh"; then
      restore_files
      drop_backups
      die 1 "the pre-upgrade database dump failed; not upgrading"
    fi
  fi
  build_recreate_cmd "$server_c" "$worker_c"
  log "recreating authentik $current -> $latest ($server_c${worker_c:+, $worker_c})"
  if ! recreate >/dev/null; then
    rollback
    die 1 "recreating authentik $latest failed; rolled back to $current"
  fi
  if ! wait_healthy "$server_c" "$worker_c"; then
    rollback
    die 1 "authentik $latest did not become healthy; rolled back to $current"
  fi
  log "authentik $latest is healthy"
fi

OUTPOST_FAILED=false
enter_outpost || OUTPOST_FAILED=true

# ── Commit and push the pins ─────────────────────────────────────────────────
# Commit from a real checkout when this host has one: the deploy copy is not a
# git repo, so without this the pins that are actually running are edited and
# never reach the repos, and the two drift the moment the next release lands.
sync_to_checkout() {  # checkout, source root, files… → the paths to commit
  local checkout=$1 root=$2 f rel dst
  shift 2
  if [ "$checkout" = "$root" ] || [ ! -d "$checkout/.git" ]; then
    printf '%s\n' "$@"
    return 0
  fi
  # Fast-forward only: a checkout carrying local work is left alone, and the
  # commit below reports it rather than this script resolving someone's diff.
  git -C "$checkout" pull --ff-only --quiet 2>/dev/null ||
    warn "$checkout is not a fast-forward of its upstream; committing onto what is there"
  for f in "$@"; do
    rel=${f#"$root"/}
    dst="$checkout/$rel"
    mkdir -p "$(dirname "$dst")"
    cp -a "$f" "$dst"
    printf '%s\n' "$dst"
  done
}

cerulean_files=()
stack_files=()
monarch_files=()
for f in "${edited[@]}"; do
  case "$f" in
    "$CERULEAN_DIR"/*|"$CERULEAN_GIT_DIR"/*) cerulean_files+=("$f") ;;
    "$STACK_DIR"/*|"$STACK_GIT_DIR"/*) stack_files+=("$f") ;;
    "$MONARCH_DIR"/*) monarch_files+=("$f") ;;
  esac
done

split_by_root() {  # root, checkout, files… → mirrored checkout paths, then kept ones
  local root=$1 checkout=$2 f
  local -a deploy_side=() kept=()
  shift 2
  for f in "$@"; do
    case "$f" in
      "$root"/*) deploy_side+=("$f") ;;
      "$checkout"/*) kept+=("$f") ;;
    esac
  done
  if [ "${#deploy_side[@]}" -gt 0 ]; then
    sync_to_checkout "$checkout" "$root" "${deploy_side[@]}"
  fi
  [ "${#kept[@]}" -gt 0 ] && printf '%s\n' "${kept[@]}"
  return 0
}

cerulean_repo="$CERULEAN_DIR"
if [ -n "$CERULEAN_GIT_DIR" ] && [ -d "$CERULEAN_GIT_DIR/.git" ]; then
  cerulean_repo="$CERULEAN_GIT_DIR"
  mapfile -t cerulean_files < <(split_by_root "$CERULEAN_DIR" "$CERULEAN_GIT_DIR" ${cerulean_files[@]+"${cerulean_files[@]}"})
fi
stack_repo="$STACK_DIR"
if [ -n "$STACK_GIT_DIR" ] && [ -d "$STACK_GIT_DIR/.git" ]; then
  stack_repo="$STACK_GIT_DIR"
  mapfile -t stack_files < <(split_by_root "$STACK_DIR" "$STACK_GIT_DIR" ${stack_files[@]+"${stack_files[@]}"})
fi

commit_and_push() {  # repo, message, files...
  local repo=$1 msg=$2 branch
  shift 2
  local staged=false f
  [ -d "$repo/.git" ] || return 0
  for f in "$@"; do
    rel=${f#"$repo"/}
    # Only tracked files: a local .env override or a .bak must not be committed.
    git -C "$repo" ls-files --error-unmatch -- "$rel" >/dev/null 2>&1 || continue
    git -C "$repo" add -- "$rel"
    staged=true
  done
  if [ "$staged" = false ] || git -C "$repo" diff --cached --quiet; then
    log "nothing to commit in $repo"
    return 0
  fi
  if [ "$DRY_RUN" = true ]; then
    log "dry-run: would commit in $repo: $(printf '%s' "$msg" | head -1)"
    git -C "$repo" restore --staged -- . >/dev/null 2>&1 || true
    return 0
  fi
  git -C "$repo" commit -q -m "$msg" ||
    die 1 "commit failed in $repo (a hook refused it?) — the files are bumped but uncommitted"
  log "committed in $repo: $(printf '%s' "$msg" | head -1)"
  if [ "$PUSH" = false ]; then
    log "not pushing $repo (--no-push); the commit is local"
    return 0
  fi
  branch=$(git -C "$repo" rev-parse --abbrev-ref HEAD)
  if git -C "$repo" push -q origin "HEAD:$branch"; then
    log "pushed $branch in $repo"
  else
    die 1 "push failed in $repo; the pin is applied and committed locally — pull --rebase and push by hand (a later run sees the pin already current and will not retry the push)"
  fi
}

cerulean_msg="Move Authentik to $latest

$latest is the newest published release and its image pulls, so the server and
its worker move together — they share one tag."
commit_and_push "$cerulean_repo" "$cerulean_msg" "${cerulean_files[@]}"

stack_msg="Pin Authentik $latest in the group composes

The pin moved in the member repos; these files carry it. A tag-only bump is
byte-for-byte what gen-group-compose.py produces, so no regeneration is needed."
if [ "${#stack_files[@]}" -gt 0 ]; then
  commit_and_push "$stack_repo" "$stack_msg" "${stack_files[@]}"
fi

monarch_msg="Move the LDAP outpost to $latest

An outpost is a client of Cerulean's Authentik and has to sit on the server's
version line."
if [ "${#monarch_files[@]}" -gt 0 ]; then
  commit_and_push "$MONARCH_DIR" "$monarch_msg" "${monarch_files[@]}"
fi

if [ "$DRY_RUN" = true ]; then
  restore_files
  log "dry-run: authentik would move $current -> $latest; nothing was changed"
  drop_backups
  exit 0
fi

drop_backups
rm -f "$STATE_DIR/announced-$latest"
log "authentik $latest applied"

# The server is up and the pins are committed, but a Jellyfin login that binds
# through a stale outpost is still a broken login — say so in the exit status.
if [ "$OUTPOST_FAILED" = true ]; then
  warn "authentik $latest is applied, but its LDAP outpost did not move — alert sent"
  exit 1
fi
