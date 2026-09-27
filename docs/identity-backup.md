# The identity dump, and how a silent failure is reported

**Status: deployed** · Cerulean host (`192.168.1.71`)

> **What this is.** Authentik is the estate's identity plane — the users, groups,
> applications and flows every other platform federates to. A restore that brings
> a service's documents back without it returns a stack nobody can log in to, so
> the dump is taken **on the host that owns the database**, and it is watched by
> something other than the job that writes it.

## 1. Why it lives here

Signara used to take this dump because Signara ran on this host and joined
`cerulean_default`. It now runs on `192.168.1.44`, and a docker network does not
span hosts, so the old path had already been failing silently before it was
removed. Signara's `docs/DisasterRecovery.md` §5 records the same move; nothing
in that stack should be pointed at this PostgreSQL any more.

## 2. What is installed, and where

| Piece | Path on `192.168.1.71` |
|---|---|
| the dump | `/usr/local/sbin/authentik-db-backup.sh` (repo: `scripts/`) |
| the artefact check | `/usr/local/sbin/authentik-backup-check.py` (repo: `scripts/`) |
| the cron wrapper | `/usr/local/sbin/authentik-backup-cron.sh` (repo: `scripts/`) |
| the schedule | `/etc/cron.d/authentik-db-backup` — daily `30 2 * * *` |
| the dumps | `/root/cerulean-backup/authentik/authentik-<UTC>.dump` |
| the metrics | `/root/cerulean-backup/authentik/status.prom` |

The dump runs inside `cerulean-authentik-postgres` as the owning role (the
official postgres image trusts local socket connections, so no password lives on
the host). Retention is the script's own: `BACKUP_RETENTION_DAYS`, default 30.

## 3. The status metrics

`status.prom` is a Prometheus textfile, written at the end of every run and
published by rename so a reader never sees a half-written file:

```
cerulean_authentik_backup_last_status                 1     # 1 ok, 0 failed
cerulean_authentik_backup_last_success_timestamp      <unix>
cerulean_authentik_backup_last_size_bytes             <bytes>
cerulean_authentik_backup_remote_enabled              <0|1>
cerulean_authentik_backup_mirror_offhost              <0|1>
cerulean_authentik_backup_remote_last_success_timestamp <unix>   # when mirrored
```

A failed run keeps the *last good* timestamp and size, so staleness is still
visible in the metrics after a failure rather than being reset to zero.

## 4. How a failure is reported — two independent layers

The point of the second layer is the failure the first one cannot see.

**Layer 1 — the job's own failure.** `authentik-db-backup.sh` warns on stderr and
exits non-zero. It does not need the network, a metrics store or another host.

**Layer 2 — the artefact.** `authentik-backup-check.py` reads the *result*
instead of the exit code: is there a dump, is it newer than
`BACKUP_MAX_AGE_HOURS` (default 36), and is it at least
`BACKUP_MIN_SIZE_BYTES` (default 1 MiB). This is what catches a job that stopped
running altogether — a deleted cron entry, a container that moved, a backup
directory that changed owners — because a job that never starts produces no
output to alert on.

`/etc/cron.d/authentik-db-backup` runs the wrapper, which runs both. **Only
problems print**, so cron mails root on drift — the same convention as
`edge-dns-check-cron.sh` and `tenant-dns-drift-cron.sh` beside it. There is no
mail relay in this estate (`SMTP_HOST` is unset everywhere), so that mail lands
in `/var/mail/root` on this host; the metrics are the durable half.

**Layer 3 — the metrics store, where one runs.** The estate's per-host
monitoring stack (`ips/extensions/monitoring`, deployed here as project
`innotel-metrics`) reads `status.prom` through node-exporter's textfile
collector and evaluates `prometheus/rules/backup.yml`:

| Alert | Fires when |
|---|---|
| `AuthentikBackupFailed` | `cerulean_authentik_backup_last_status == 0` for 30m |
| `AuthentikBackupStale` | no successful dump in 36h (independent of the job) |
| `AuthentikBackupMirrorIsLocalOnly` | `mirror_offhost == 0` for 6h — warning |
| `AuthentikTextfileUnreadable` | `node_textfile_scrape_error == 1` for 15m |

These are keyed on the series being **present**, so a host that does not take
this dump — `.56` runs the same monitoring stack — stays quiet instead of firing
an alert about a backup it was never asked to take.

## 5. Checking it by hand

```bash
# the last status, as the checker and the collector see it
cat /root/cerulean-backup/authentik/status.prom

# assert it (quiet: prints only problems; exit 1 when there are any)
/usr/local/sbin/authentik-backup-check.py --quiet; echo "exit=$?"

# what the monitoring stack is reading
curl -s 127.0.0.1:9090/api/v1/query \
  --data-urlencode 'query=cerulean_authentik_backup_last_status'
curl -s 127.0.0.1:9090/api/v1/rules | grep -A3 AuthentikBackup
```

`--json` gives the same verdict machine-readably. The checker is read-only: it
never takes, moves or prunes a dump.

## 6. What is deliberately not covered

- **No off-host copy.** `BACKUP_S3_*` is unset, so `mirror_offhost` is 0 and these
  dumps do not survive losing this host. That is reported (a warning from the
  checker, an alert from `AuthentikBackupMirrorIsLocalOnly`) rather than assumed
  away — and it is the estate's known gap, not a fault of this script: no
  `rclone` remote credentials exist yet. Read a successful dump back *before*
  trusting it: `scripts/restore-drill.sh` in Signara is the pattern for that.
- **Restore.** This document covers the dump and its alerting. The restore
  procedure is `pg_restore` into a fresh `cerulean-authentik-postgres`, then
  repointing the outposts; it is not scripted here.
