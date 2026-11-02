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
#   authentik-update.sh [--dry-run] [--no-deploy] [--no-push] [--root DIR]
#                       [--version X.Y.Z]
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
#   AUTHENTIK_HEALTH_URL      server readiness probe
#                             (default http://127.0.0.1:9000/health/live/)
#   AUTHENTIK_HEALTH_TIMEOUT  seconds to wait for healthy (default 600)
#   AUTHENTIK_UPDATE_LOCK     lock file (default /run/lock/authentik-update.lock)
#   GITHUB_TOKEN              raises the GitHub API rate limit (optional)
#
# Install (timer every 15 minutes):
#   install -Dm755 authentik-update.sh /opt/innotel/authentik-update/authentik-update.sh
#   install -Dm644 authentik-update.service /etc/systemd/system/authentik-update.service
#   install -Dm644 authentik-update.timer   /etc/systemd/system/authentik-update.timer
#   systemctl daemon-reload && systemctl enable --now authentik-update.timer
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

HEALTH_URL="${AUTHENTIK_HEALTH_URL:-http://127.0.0.1:9000/health/live/}"
HEALTH_TIMEOUT="${AUTHENTIK_HEALTH_TIMEOUT:-600}"
LOCK="${AUTHENTIK_UPDATE_LOCK:-/run/lock/authentik-update.lock}"

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
die() { local code=$1; shift; printf '%s ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; exit "$code"; }

usage() {
  sed -n '2,43p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true ;;
    --no-deploy) DEPLOY=false ;;
    --no-push) PUSH=false ;;
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

if [ "$latest" = "$current" ] && [ "$pinned" = "$current" ]; then
  log "authentik $current is current"
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
# is a commit nobody asked for. Untracked files are fine — only tracked changes
# would be swept into the bump commit.
for repo in "$CERULEAN_DIR" "$STACK_DIR" "$MONARCH_DIR"; do
  [ -d "$repo/.git" ] || continue
  dirty=$(git -C "$repo" status --porcelain --untracked-files=no)
  if [ -n "$dirty" ]; then
    printf '%s\n' "$dirty" >&2
    die 2 "$repo has uncommitted changes; refusing to fold a version bump into them (commit or stash them, then rerun)"
  fi
done

# ── Only a pullable image is worth changing a pin for ────────────────────────
if [ "$DRY_RUN" = true ]; then
  log "dry-run: would move authentik $current -> $latest"
elif [ "$DEPLOY" = false ]; then
  log "authentik $current -> $latest (--no-deploy: the pin moves, nothing is pulled or recreated)"
else
  image_available "$IMAGE:$latest" ||
    die 1 "authentik $latest is released but $IMAGE:$latest is not pullable yet; the next run will take it"
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

for candidate in "$COMPOSE" "$README" "$GROUP_PRIMARY" "$MONARCH_COMPOSE" "$GROUP_MEDIA" "$APP_ENV" "$STACK_ENV"; do
  backup "$candidate"
done
bump_server_pin "$COMPOSE"
bump_server_pin "$README"
bump_server_pin "$GROUP_PRIMARY"   # generated: a tag-only bump is exactly its regeneration
bump_outpost_pin "$MONARCH_COMPOSE"
bump_outpost_pin "$GROUP_MEDIA"
bump_env_pin "$APP_ENV"
bump_env_pin "$STACK_ENV"

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

label_of() { docker inspect -f "{{index .Config.Labels \"$2\"}}" "$1" 2>/dev/null || true; }

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
  if [ -f "$STACK_ENV" ]; then RECREATE_CMD+=(--env-file "$STACK_ENV"); fi
  # The Authentik services are profile-gated in both compose files.
  RECREATE_CMD+=(--profile authentik)
  RECREATE_SERVICES=("$svc_server" "$svc_worker")
}

recreate() {
  "${RECREATE_CMD[@]}" up -d --no-deps "${RECREATE_SERVICES[@]}"
}

wait_healthy() {  # worker container (may be empty)
  local worker_c=$1 deadline=$((SECONDS + HEALTH_TIMEOUT)) code="" state="" waited=0
  while [ "$SECONDS" -lt "$deadline" ]; do
    code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$HEALTH_URL" 2>/dev/null || true)
    state=running
    if [ -n "$worker_c" ]; then
      state=$(docker inspect -f '{{.State.Status}}' "$worker_c" 2>/dev/null || echo missing)
      if [ "$state" = exited ] || [ "$state" = dead ]; then
        log "the worker is $state while waiting for readiness"
        return 1
      fi
    fi
    if { [ "$code" = 200 ] || [ "$code" = 204 ]; } && [ "$state" = running ]; then
      return 0
    fi
    waited=$((waited + 5))
    if [ $((waited % 60)) -eq 0 ]; then
      log "waiting for authentik $latest (health=${code:-none} worker=$state, ${waited}s)"
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
  if ! wait_healthy "$worker_c"; then
    rollback
    die 1 "authentik $latest did not become healthy; rolled back to $current"
  fi
  log "authentik $latest is healthy"
fi

# ── Commit and push the pins ─────────────────────────────────────────────────
cerulean_files=()
stack_files=()
monarch_files=()
for f in "${edited[@]}"; do
  case "$f" in
    "$CERULEAN_DIR"/*) cerulean_files+=("$f") ;;
    "$STACK_DIR"/*) stack_files+=("$f") ;;
    "$MONARCH_DIR"/*) monarch_files+=("$f") ;;
  esac
done

commit_and_push() {  # repo, message, files...
  local repo=$1 msg=$2 branch
  shift 2
  local staged=false f
  [ -d "$repo/.git" ] || return 0
  for f in "$@"; do
    # Only tracked files: a local .env override or a .bak must not be committed.
    git -C "$repo" ls-files --error-unmatch -- "$f" >/dev/null 2>&1 || continue
    git -C "$repo" add -- "$f"
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
    die 1 "push failed in $repo; the commit is local — push it by hand or fix the remote"
  fi
}

cerulean_msg="Move Authentik to $latest

$latest is the newest published release and its image pulls, so the server and
its worker move together — they share one tag."
commit_and_push "$CERULEAN_DIR" "$cerulean_msg" "${cerulean_files[@]}"

stack_msg="Pin Authentik $latest in the group composes

The pin moved in the member repos; these files carry it. A tag-only bump is
byte-for-byte what gen-group-compose.py produces, so no regeneration is needed."
if [ "${#stack_files[@]}" -gt 0 ]; then
  commit_and_push "$STACK_DIR" "$stack_msg" "${stack_files[@]}"
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
log "authentik $latest applied"
