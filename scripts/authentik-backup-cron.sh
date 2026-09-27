#!/bin/sh
# authentik-backup-cron.sh — run the identity dump, then assert it happened.
#
# Installed as /usr/local/sbin/authentik-backup-cron.sh and called from
# /etc/cron.d/authentik-db-backup on the host that owns Authentik (Cerulean,
# 192.168.1.71). The two settings the dump needs — BACKUP_LOCAL_ADDRESSES and the
# schedule — live in the cron.d file, so this wrapper is identical everywhere.
#
# Why a wrapper and not just the backup: `authentik-db-backup.sh` reports its own
# failure (warn on stderr, exit 1) and cron mails root on any output. What has no
# output is the case where it never runs at all — a deleted cron entry, a moved
# container, a dump directory that stopped being written. The checker reads the
# artefact instead, so both failures arrive the same way.
#
# Only problems print, so cron mails root on drift — the same convention as
# edge-dns-check-cron.sh beside it in /usr/local/sbin.

set -u

status=0

if ! /usr/local/sbin/authentik-db-backup.sh --quiet; then
  status=1
fi

# Runs after a failed dump too: the age and size of the last good artefact is
# worth reporting whether or not this run is the one that broke.
if ! /usr/local/sbin/authentik-backup-check.py --quiet; then
  status=1
fi

exit "$status"
