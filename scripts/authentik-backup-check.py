#!/usr/bin/env python3
"""authentik-backup-check.py — assert the identity dump ran, and stayed fresh.

Why this exists
---------------
`authentik-db-backup.sh` already reports its *own* failure: it warns on stderr
and exits non-zero, and cron mails root on any output. What it cannot report is
the failure where it never runs at all — the container moved, the dump directory
changed owners, the job was deleted, the host was rebuilt — because a job that
does not start produces no output to alert on. The dump then ages quietly and is
discovered on the day someone tries to log in to a restored stack.

This is the other half: it reads the artefact, not the exit code. A dump is only
"good" if a file is actually there, it is recent, and it is not truncated.

Read-only. It never takes, moves or prunes a dump.

Configuration (environment):
  BACKUP_DIR             where dumps and status.prom live
                         (default /root/cerulean-backup/authentik)
  BACKUP_MAX_AGE_HOURS   a dump older than this is stale          (default 36)
  BACKUP_MIN_SIZE_BYTES  a dump smaller than this is truncated    (default 1 MiB)

Usage:
  authentik-backup-check.py [--backup-dir DIR] [--max-age-hours H]
                            [--min-size-bytes N] [--quiet] [--json]

Exit codes: 0 the newest dump is present, fresh and non-trivial · 1 a problem ·
2 the check could not run.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time

PREFIX = "cerulean_authentik_backup_"
DUMP_GLOB = "authentik-*.dump"
STATUS_NAME = "status.prom"

DEFAULT_BACKUP_DIR = "/root/cerulean-backup/authentik"
DEFAULT_MAX_AGE_HOURS = 36.0
DEFAULT_MIN_SIZE_BYTES = 1024 * 1024


# ── pure helpers (unit-tested without a filesystem) ──────────────────────────


def parse_status(text: str) -> dict[str, float]:
    """Read the Prometheus textfile the backup writes.

    Only this job's series are kept, and a malformed value is skipped rather
    than raising: the file is written by a shell script and a stray line should
    not turn "the dump is stale" into "the check crashed".
    """
    values: dict[str, float] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not line.startswith(PREFIX):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            values[parts[0][len(PREFIX) :]] = float(parts[1])
        except ValueError:
            continue
    return values


def newest_dump(entries: list[tuple[str, float, int]]) -> tuple[str, float, int] | None:
    """Pick the most recently modified dump from (path, mtime, size) tuples."""
    if not entries:
        return None
    return max(entries, key=lambda e: e[1])


def list_dumps(backup_dir: str) -> list[tuple[str, float, int]]:
    entries: list[tuple[str, float, int]] = []
    for path in glob.glob(os.path.join(backup_dir, DUMP_GLOB)):
        try:
            stat = os.stat(path)
        except OSError:
            continue
        if os.path.isfile(path):
            entries.append((path, stat.st_mtime, stat.st_size))
    return entries


def evaluate(
    status: dict[str, float] | None,
    dump: tuple[str, float, int] | None,
    now: float,
    max_age_hours: float,
    min_size_bytes: int,
    backup_dir: str,
) -> tuple[list[str], list[str]]:
    """Return (problems, warnings). Problems are why exit code is 1."""
    problems: list[str] = []
    warnings: list[str] = []

    if status is None:
        problems.append(
            f"no {STATUS_NAME} in {backup_dir} — the dump job has never run here, "
            "or cannot write its status"
        )
    elif "last_status" not in status:
        problems.append(f"{STATUS_NAME} carries no {PREFIX}last_status")
    elif status["last_status"] != 1:
        problems.append(
            "the last dump run failed "
            f"({PREFIX}last_status={status['last_status']:g})"
        )

    if dump is None:
        problems.append(f"no {DUMP_GLOB} in {backup_dir} — nothing has been dumped")
    else:
        path, mtime, size = dump
        age_hours = max(0.0, (now - mtime) / 3600.0)
        if max_age_hours > 0 and age_hours > max_age_hours:
            problems.append(
                f"{os.path.basename(path)} is {age_hours:.1f}h old "
                f"(limit {max_age_hours:g}h) — the dump job has stopped running"
            )
        if min_size_bytes > 0 and size < min_size_bytes:
            problems.append(
                f"{os.path.basename(path)} is {size} bytes, below the "
                f"{min_size_bytes} floor — a truncated dump"
            )

    # A dump that never leaves the host passes every check above: it ran, it is
    # fresh, it is complete, and it dies with the box. Reported, but as a warning
    # — `BACKUP_S3_*` is optional on this host, so it must not page.
    if status is not None and status.get("mirror_offhost") == 0:
        warnings.append(
            "no proven off-host copy (mirror_offhost=0) — this dump does not "
            "survive losing this host; set BACKUP_S3_* (see docs/identity-backup.md)"
        )

    return problems, warnings


# ── entry point ──────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Assert the Authentik identity dump is present and fresh."
    )
    parser.add_argument(
        "--backup-dir",
        default=os.environ.get("BACKUP_DIR", DEFAULT_BACKUP_DIR),
        help="directory holding the dumps and status.prom",
    )
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=float(os.environ.get("BACKUP_MAX_AGE_HOURS", DEFAULT_MAX_AGE_HOURS)),
        help="a dump older than this many hours is stale (0 disables)",
    )
    parser.add_argument(
        "--min-size-bytes",
        type=int,
        default=int(os.environ.get("BACKUP_MIN_SIZE_BYTES", DEFAULT_MIN_SIZE_BYTES)),
        help="a dump smaller than this is truncated (0 disables)",
    )
    parser.add_argument("--quiet", action="store_true", help="print only problems")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    backup_dir = args.backup_dir
    if not os.path.isdir(backup_dir):
        print(f"authentik-backup-check: {backup_dir} does not exist", file=sys.stderr)
        return 2

    status_path = os.path.join(backup_dir, STATUS_NAME)
    status: dict[str, float] | None
    try:
        with open(status_path, encoding="utf-8") as handle:
            status = parse_status(handle.read())
    except FileNotFoundError:
        status = None
    except OSError as exc:
        print(f"authentik-backup-check: cannot read {status_path}: {exc}", file=sys.stderr)
        return 2

    dump = newest_dump(list_dumps(backup_dir))
    problems, warnings = evaluate(
        status, dump, time.time(), args.max_age_hours, args.min_size_bytes, backup_dir
    )

    if args.json:
        print(
            json.dumps(
                {
                    "backupDir": backup_dir,
                    "status": status,
                    "newestDump": (
                        {"path": dump[0], "mtime": dump[1], "size": dump[2]}
                        if dump
                        else None
                    ),
                    "problems": problems,
                    "warnings": warnings,
                },
                indent=2,
            )
        )
    else:
        for problem in problems:
            print(f"authentik-backup-check: {problem}")
        for warning in warnings:
            if not args.quiet:
                print(f"authentik-backup-check: WARNING: {warning}")
        if not problems and not args.quiet:
            path, mtime, size = dump  # type: ignore[misc]  # guaranteed: no problems
            age_hours = max(0.0, (time.time() - mtime) / 3600.0)
            print(
                f"authentik-backup-check: {os.path.basename(path)} "
                f"({size} bytes, {age_hours:.1f}h old) — ok"
            )

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
