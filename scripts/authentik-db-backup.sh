#!/usr/bin/env bash
# authentik-db-backup.sh — dump Cerulean's Authentik identity database.
#
# Authentik is this estate's identity plane: the users, groups and flows every
# other app federates to (Signara, Onyx, the edge SSO gate). A restore that
# brings a service's documents back without it returns a stack nobody can log
# in to, so this dump is taken on the host that OWNS Authentik rather than by
# the services that merely consume it.
#
# Signara used to include it, because Signara ran on this host and joined
# Cerulean's docker network (`cerulean_default`). It now runs on
# 192.168.1.44, where that network cannot reach — a docker network does not
# span hosts — so the responsibility moved here. Signara's
# docs/DisasterRecovery.md §5 records the same move.
#
# Usage:
#   authentik-db-backup.sh [--dry-run] [--quiet] [--prune-only]
#
# Environment:
#   AUTHENTIK_CONTAINER       postgres container           (cerulean-authentik-postgres)
#   AUTHENTIK_POSTGRES_USER   role to dump as              (authentik)
#   AUTHENTIK_POSTGRES_DB     database to dump             (authentik)
#   BACKUP_DIR                where dumps are written      (/root/cerulean-backup/authentik)
#   BACKUP_RETENTION_DAYS     dumps older than this prune  (30)
#   BACKUP_REQUIRE_REMOTE     fail when no off-host mirror (false)
#   BACKUP_S3_ENDPOINT        optional rclone mirror endpoint
#   BACKUP_S3_BUCKET          optional rclone mirror bucket
#   BACKUP_S3_ACCESS_KEY      optional rclone mirror key id
#   BACKUP_S3_SECRET_KEY      optional rclone mirror secret
#   BACKUP_S3_REGION          optional rclone mirror region
#   BACKUP_LOCAL_ADDRESSES    this host's own addresses — a mirror that resolves
#                             to one of them is NOT off-host and is reported so
#   RCLONE                    rclone binary                    (rclone)
#
# Exit: 0 success (or --dry-run/--prune-only), 1 backup failed, 2 precondition.
set -Eeuo pipefail

AUTHENTIK_CONTAINER="${AUTHENTIK_CONTAINER:-cerulean-authentik-postgres}"
AUTHENTIK_POSTGRES_USER="${AUTHENTIK_POSTGRES_USER:-authentik}"
AUTHENTIK_POSTGRES_DB="${AUTHENTIK_POSTGRES_DB:-authentik}"
BACKUP_DIR="${BACKUP_DIR:-/root/cerulean-backup/authentik}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
STATUS_FILE="${STATUS_FILE:-$BACKUP_DIR/status.prom}"
RCLONE="${RCLONE:-rclone}"

DRY_RUN=false
QUIET=false
PRUNE_ONLY=false

REMOTE_CONFIGURED=false
REMOTE_OK=false
MIRROR_OFFHOST=0
LAST_SIZE=0

log() { [[ "$QUIET" == true ]] || echo "[authentik-backup] $*"; }
warn() { echo "[authentik-backup] WARNING: $*" >&2; }

usage() {
  sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

while (($#)); do
  case "$1" in
    --dry-run) DRY_RUN=true ;;
    --quiet) QUIET=true ;;
    --prune-only) PRUNE_ONLY=true ;;
    -h | --help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
  shift
done

endpoint_host() { # strip scheme, credentials, port and path off an S3 endpoint
  printf '%s' "$1" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#\?.*$##; s#/.*$##; s#^.*@##; s#:[0-9]+$##'
}

resolve_ipv4() { # best-effort; prints nothing when the name cannot be resolved
  local host="$1"
  case "$host" in
    '') return 0 ;;
    *[!0-9.]*) ;;                            # a name, needs a lookup
    *) printf '%s\n' "$host"; return 0 ;;    # already a literal address
  esac
  if command -v getent >/dev/null 2>&1; then
    getent hosts "$host" 2>/dev/null | awk '{ print $1 }' | grep -E '^[0-9.]+$' && return 0
  fi
  nslookup "$host" 2>/dev/null | awk -F': *' '/^Address/ { print $2 }' | grep -E '^[0-9.]+$'
  return 0
}

carried_over() { # $1 = metric name, from the previous status file
  awk -v k="$1" '$1 == k { print $2 }' "$STATUS_FILE" 2>/dev/null || true
}

write_status() { # $1 = last_status (0/1)
  local last_status="$1"
  # The failure paths run the trap before $BACKUP_DIR is created (a missing
  # container exits 2 first), and writing the failure has to survive that —
  # otherwise the operator sees a redirect error instead of why the dump
  # stopped, and the metric that says so never lands.
  mkdir -p "$(dirname "$STATUS_FILE")" 2>/dev/null || true
  {
    echo "cerulean_authentik_backup_last_status $last_status"
    if [[ "$last_status" == 1 ]]; then
      echo "cerulean_authentik_backup_last_success_timestamp $(date +%s)"
      echo "cerulean_authentik_backup_last_size_bytes $LAST_SIZE"
    else
      local carried
      carried="$(carried_over cerulean_authentik_backup_last_success_timestamp)"
      [[ -n "$carried" ]] && echo "cerulean_authentik_backup_last_success_timestamp $carried"
      carried="$(carried_over cerulean_authentik_backup_last_size_bytes)"
      [[ -n "$carried" ]] && echo "cerulean_authentik_backup_last_size_bytes $carried"
    fi
    if [[ "$REMOTE_CONFIGURED" == true ]]; then
      echo "cerulean_authentik_backup_remote_enabled 1"
      if [[ "$REMOTE_OK" == true ]]; then
        echo "cerulean_authentik_backup_remote_last_success_timestamp $(date +%s)"
      else
        local carried
        carried="$(carried_over cerulean_authentik_backup_remote_last_success_timestamp)"
        [[ -n "$carried" ]] && echo "cerulean_authentik_backup_remote_last_success_timestamp $carried"
      fi
    else
      echo "cerulean_authentik_backup_remote_enabled 0"
    fi
    echo "cerulean_authentik_backup_mirror_offhost $MIRROR_OFFHOST"
  } > "$STATUS_FILE"
}

finish() {
  local code=$?
  # A dry run must not publish a status: it would claim a backup that never
  # happened, and the metrics are read by people deciding whether to trust the
  # dump. (`--prune-only` does write one — it really did run.)
  if [[ "$DRY_RUN" == true ]]; then
    log "--dry-run: not writing $STATUS_FILE"
    exit "$code"
  fi
  if ((code == 0)); then
    write_status 1
    log "backup completed successfully"
  else
    write_status 0
    warn "backup failed (exit $code)"
  fi
  exit "$code"
}
trap finish EXIT

if command -v docker >/dev/null 2>&1; then
  if ! docker inspect "$AUTHENTIK_CONTAINER" >/dev/null 2>&1; then
    warn "container $AUTHENTIK_CONTAINER not found — is Authentik running on this host?"
    exit 2
  fi
else
  warn "docker not found in PATH"
  exit 2
fi

prune_local() {
  log "applying local retention of ${RETENTION_DAYS} days..."
  if [[ "$DRY_RUN" == true ]]; then
    find "$BACKUP_DIR" -type f -name 'authentik-*.dump' -mtime "+$RETENTION_DAYS" -print 2>/dev/null
    return 0
  fi
  find "$BACKUP_DIR" -type f -name 'authentik-*.dump' -mtime "+$RETENTION_DAYS" -delete 2>/dev/null || true
}

if [[ "$PRUNE_ONLY" == true ]]; then
  mkdir -p "$BACKUP_DIR"
  prune_local
  exit 0
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT="$BACKUP_DIR/authentik-$TIMESTAMP.dump"

if [[ "$DRY_RUN" == true ]]; then
  log "--dry-run: would dump ${AUTHENTIK_POSTGRES_DB} as ${AUTHENTIK_POSTGRES_USER}"
  log "--dry-run: would write $OUTPUT and prune dumps older than ${RETENTION_DAYS}d in $BACKUP_DIR"
  if [[ -n "${BACKUP_S3_ENDPOINT:-}" ]]; then
    log "--dry-run: would mirror to ${BACKUP_S3_ENDPOINT}/${BACKUP_S3_BUCKET:-<unset>}"
  else
    log "--dry-run: no BACKUP_S3_ENDPOINT — local only"
  fi
  exit 0
fi

mkdir -p "$BACKUP_DIR"

# The official postgres image trusts local (socket) connections, so the dump
# runs inside the container as the owning role — no password on this host.
log "dumping ${AUTHENTIK_POSTGRES_DB} from ${AUTHENTIK_CONTAINER}..."
tmp="$(mktemp "$BACKUP_DIR/.authentik-XXXXXX.dump")"
if ! docker exec "$AUTHENTIK_CONTAINER" \
  pg_dump -U "$AUTHENTIK_POSTGRES_USER" -Fc --no-owner "$AUTHENTIK_POSTGRES_DB" > "$tmp"; then
  rm -f "$tmp"
  exit 1
fi
if [[ ! -s "$tmp" ]]; then
  rm -f "$tmp"
  warn "pg_dump produced an empty dump"
  exit 1
fi
mv "$tmp" "$OUTPUT"
LAST_SIZE="$(stat -c %s "$OUTPUT" 2>/dev/null || echo 0)"
log "wrote $OUTPUT ($(numfmt --to=iec "$LAST_SIZE" 2>/dev/null || echo "$LAST_SIZE bytes"))"

# Off-host mirror. Optional by default, but never quiet: a dump that does not
# leave this host does not survive losing it, and that is a fact to state, not
# to assume (the estate lost a platform's history to exactly that gap).
if [[ -n "${BACKUP_S3_ENDPOINT:-}" || -n "${BACKUP_S3_ACCESS_KEY:-}" || -n "${BACKUP_S3_SECRET_KEY:-}" ]]; then
  if [[ -z "${BACKUP_S3_ENDPOINT:-}" || -z "${BACKUP_S3_ACCESS_KEY:-}" || -z "${BACKUP_S3_SECRET_KEY:-}" ]]; then
    warn "remote backup configuration is incomplete (need BACKUP_S3_ENDPOINT, BACKUP_S3_ACCESS_KEY, BACKUP_S3_SECRET_KEY)"
    exit 1
  fi
  : "${BACKUP_S3_BUCKET:?BACKUP_S3_BUCKET is required for remote backup}"
  REMOTE_CONFIGURED=true

  if ! command -v "$RCLONE" >/dev/null 2>&1; then
    warn "$RCLONE not found — the mirror is configured but cannot run"
    exit 1
  fi

  # rclone, not mc, for every object transfer in this estate: its stores refuse
  # streaming SigV4 uploads, and rclone signs plain payloads.
  mirror_flags=(--config /dev/null --log-level ERROR --s3-provider Other
    --s3-endpoint "$BACKUP_S3_ENDPOINT" --s3-access-key-id "$BACKUP_S3_ACCESS_KEY"
    --s3-secret-access-key "$BACKUP_S3_SECRET_KEY" --s3-force-path-style)
  if [[ -n "${BACKUP_S3_REGION:-}" ]]; then
    mirror_flags+=(--s3-region "$BACKUP_S3_REGION")
  fi
  mirror=":s3:$BACKUP_S3_BUCKET"

  log "mirroring the dump to remote S3..."
  "$RCLONE" "${mirror_flags[@]}" mkdir "$mirror/authentik"
  "$RCLONE" "${mirror_flags[@]}" copyto "$OUTPUT" "$mirror/authentik/authentik-$TIMESTAMP.dump"
  "$RCLONE" "${mirror_flags[@]}" delete --min-age "${RETENTION_DAYS}d" "$mirror/authentik/" || true
  "$RCLONE" "${mirror_flags[@]}" rmdirs --leave-root "$mirror/authentik/" || true
  REMOTE_OK=true

  mirror_host="$(endpoint_host "$BACKUP_S3_ENDPOINT")"
  if [[ -z "${BACKUP_LOCAL_ADDRESSES:-}" ]]; then
    warn "BACKUP_LOCAL_ADDRESSES is unset, so the mirror at $mirror_host cannot be shown to be off-host"
  else
    mirror_ips="$(resolve_ipv4 "$mirror_host")"
    local_hit=false
    for ip in $mirror_ips; do
      for declared in ${BACKUP_LOCAL_ADDRESSES//,/ }; do
        [[ "$ip" == "$declared" ]] && local_hit=true
      done
    done
    if [[ "$local_hit" == true ]]; then
      warn "the mirror host $mirror_host resolves to this host — these copies do not survive losing it"
    else
      MIRROR_OFFHOST=1
      log "mirror $mirror_host is off this host"
    fi
  fi
else
  if [[ "${BACKUP_REQUIRE_REMOTE:-false}" == true ]]; then
    warn "remote backup credentials are required but missing"
    exit 1
  fi
  warn "no off-host mirror configured — this dump lives only on this host and"
  warn "does not survive losing it; set BACKUP_S3_* (and BACKUP_REQUIRE_REMOTE=true)"
fi

prune_local
log "backup stored in $BACKUP_DIR"
exit 0
