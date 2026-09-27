#!/usr/bin/env python3
"""Tests for scripts/authentik-backup-check.py.

The check exists because a backup job that *stops running* produces no output to
alert on: `authentik-db-backup.sh` warns and exits non-zero when its own dump
fails, but a cron entry that was deleted, a container that moved, or a dump
directory that stopped being written all look like success from the job's side.
So the contract under test is the artefact:

  * a fresh, non-trivial dump with `last_status 1` is ok;
  * a dump older than the limit is reported even though every job exited 0;
  * a missing status file, a failed status, a missing dump and a truncated dump
    are each problems;
  * no proven off-host copy is a warning, not a problem — the mirror is optional
    here and must not page;
  * a malformed status line is skipped rather than crashing the check.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

_SCRIPT_PATH = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "authentik-backup-check.py")
)
_spec = importlib.util.spec_from_file_location("authentik_backup_check", _SCRIPT_PATH)
abc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(abc)

HOUR = 3600.0
NOW = 1_790_000_000.0

HEALTHY_STATUS = """\
cerulean_authentik_backup_last_status 1
cerulean_authentik_backup_last_success_timestamp 1789996400
cerulean_authentik_backup_last_size_bytes 19385314
cerulean_authentik_backup_remote_enabled 0
cerulean_authentik_backup_mirror_offhost 0
"""


class ParseStatus(unittest.TestCase):
    def test_reads_only_this_jobs_series(self):
        text = (
            "# HELP cerulean_authentik_backup_last_status ...\n"
            + HEALTHY_STATUS
            + "node_time_seconds 1.5\n\nsome_other_metric 3\n"
        )
        self.assertEqual(
            abc.parse_status(text),
            {
                "last_status": 1.0,
                "last_success_timestamp": 1789996400.0,
                "last_size_bytes": 19385314.0,
                "remote_enabled": 0.0,
                "mirror_offhost": 0.0,
            },
        )

    def test_malformed_value_is_skipped_not_fatal(self):
        status = abc.parse_status(
            "cerulean_authentik_backup_last_status 1\n"
            "cerulean_authentik_backup_last_size_bytes not-a-number\n"
            "cerulean_authentik_backup_truncated_line\n"
        )
        self.assertEqual(status, {"last_status": 1.0})

    def test_empty_input(self):
        self.assertEqual(abc.parse_status(""), {})


class NewestDump(unittest.TestCase):
    def test_picks_most_recent(self):
        entries = [("a", NOW - 10 * HOUR, 5), ("b", NOW - HOUR, 5), ("c", NOW - 100, 5)]
        self.assertEqual(abc.newest_dump(entries)[0], "c")

    def test_none_when_empty(self):
        self.assertIsNone(abc.newest_dump([]))


class ListDumps(unittest.TestCase):
    def test_only_authentik_dumps(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("authentik-20260927T175158Z.dump", "authentik-old.dump", "status.prom"):
                with open(os.path.join(tmp, name), "wb") as handle:
                    handle.write(b"x" * 8)
            os.mkdir(os.path.join(tmp, "authentik-a-directory.dump"))
            found = {os.path.basename(path) for path, _, _ in abc.list_dumps(tmp)}
        self.assertEqual(found, {"authentik-20260927T175158Z.dump", "authentik-old.dump"})


class Evaluate(unittest.TestCase):
    def status(self, **overrides):
        values = {
            "last_status": 1.0,
            "last_success_timestamp": NOW - HOUR,
            "last_size_bytes": 19_385_314.0,
            "remote_enabled": 0.0,
            "mirror_offhost": 1.0,
        }
        values.update(overrides)
        return values

    def run_eval(self, status, dump, *, max_age=36.0, min_size=1024 * 1024):
        return abc.evaluate(status, dump, NOW, max_age, min_size, "/backup")

    def test_healthy(self):
        problems, warnings = self.run_eval(
            self.status(), ("/backup/authentik-x.dump", NOW - HOUR, 19_385_314)
        )
        self.assertEqual(problems, [])
        self.assertEqual(warnings, [])

    def test_missing_status_file(self):
        problems, _ = self.run_eval(None, ("/backup/d.dump", NOW - HOUR, 19_385_314))
        self.assertEqual(len(problems), 1)
        self.assertIn("status.prom", problems[0])

    def test_status_without_last_status(self):
        problems, _ = self.run_eval(
            {"mirror_offhost": 1.0}, ("/backup/d.dump", NOW - HOUR, 19_385_314)
        )
        self.assertTrue(any("no cerulean_authentik_backup_last_status" in p for p in problems))

    def test_failed_status(self):
        problems, _ = self.run_eval(
            self.status(last_status=0.0), ("/backup/d.dump", NOW - HOUR, 19_385_314)
        )
        self.assertTrue(any("the last dump run failed" in p for p in problems))

    def test_no_dump_at_all(self):
        problems, _ = self.run_eval(self.status(), None)
        self.assertTrue(any("nothing has been dumped" in p for p in problems))

    def test_stale_dump_is_reported_even_with_a_successful_status(self):
        dump = ("/backup/authentik-old.dump", NOW - 40 * HOUR, 19_385_314)
        problems, _ = self.run_eval(self.status(), dump)
        self.assertTrue(any("has stopped running" in p for p in problems))

    def test_age_limit_disabled(self):
        dump = ("/backup/d.dump", NOW - 40 * HOUR, 19_385_314)
        problems, _ = self.run_eval(self.status(), dump, max_age=0)
        self.assertFalse(any("has stopped running" in p for p in problems))

    def test_truncated_dump(self):
        dump = ("/backup/authentik-x.dump", NOW - HOUR, 512)
        problems, _ = self.run_eval(self.status(), dump)
        self.assertTrue(any("truncated dump" in p for p in problems))

    def test_size_floor_disabled(self):
        dump = ("/backup/authentik-x.dump", NOW - HOUR, 512)
        problems, _ = self.run_eval(self.status(), dump, min_size=0)
        self.assertFalse(any("truncated" in p for p in problems))

    def test_local_only_is_a_warning_not_a_problem(self):
        problems, warnings = self.run_eval(
            self.status(mirror_offhost=0.0), ("/backup/d.dump", NOW - HOUR, 19_385_314)
        )
        self.assertEqual(problems, [])
        self.assertTrue(any("off-host" in w for w in warnings))

    def test_offhost_mirror_is_silent(self):
        _, warnings = self.run_eval(
            self.status(remote_enabled=1.0, mirror_offhost=1.0),
            ("/backup/d.dump", NOW - HOUR, 19_385_314),
        )
        self.assertEqual(warnings, [])


class CommandLine(unittest.TestCase):
    """The plumbing a cron entry depends on: exit codes and --quiet."""

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, _SCRIPT_PATH, *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_healthy_directory_exits_zero_and_prints_only_when_not_quiet(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = os.path.join(tmp, "authentik-20260927T175158Z.dump")
            with open(dump, "wb") as handle:
                handle.write(b"x" * (2 * 1024 * 1024))
            with open(os.path.join(tmp, "status.prom"), "w", encoding="utf-8") as handle:
                handle.write(HEALTHY_STATUS)

            loud = self._run("--backup-dir", tmp)
            self.assertEqual(loud.returncode, 0, loud.stderr)
            self.assertIn("— ok", loud.stdout)

            quiet = self._run("--backup-dir", tmp, "--quiet")
            self.assertEqual(quiet.returncode, 0, quiet.stderr)
            self.assertEqual(quiet.stdout.strip(), "")

    def test_empty_directory_fails_loudly_when_quiet(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run("--backup-dir", tmp, "--quiet")
        self.assertEqual(result.returncode, 1)
        self.assertIn("status.prom", result.stdout)
        self.assertIn("nothing has been dumped", result.stdout)

    def test_json_reports_problems(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run("--backup-dir", tmp, "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["newestDump"], None)
        self.assertTrue(payload["problems"])
        self.assertEqual(result.returncode, 1)

    def test_missing_directory_is_exit_2(self):
        result = self._run("--backup-dir", "/nonexistent-authentik-backup", "--quiet")
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
