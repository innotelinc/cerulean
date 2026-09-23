#!/usr/bin/env python3
"""Tests for scripts/zone-notify-reconcile.py — the two NOTIFY judgements.

The script has one decision and two readings of it:

  * the **reconcile** path judging only the zones Technitium already flagged
    `notifyFailed` (narrow by construction — a real second server that is not
    answering must be reported, never written); and
  * the **preflight** path judging every enabled Primary zone instead, so a
    deploy can refuse to come up into a state whose only possible outcome is a
    retrying, refusing NOTIFY.

Both are the same question — does every notify target resolve to this server? —
so both are covered here against a fake Technitium that answers the whole API
(zones, options, records, settings, and the writes), with name resolution faked
at `addresses_of`. What is asserted:

  * a zone whose NS records all point at this box is a self-notify; one naming a
    genuine second server is not, and the reconcile leaves it alone;
  * a target that resolves nowhere is a *different* problem, not a self-notify —
    the distinction that keeps the tool from writing over a broken delegation;
  * the server's own domain is not a target, because Technitium itself excludes
    it (this is why the one zone naming the server resolves green on the box);
  * the reconcile only looks at zones already flagged, the preflight looks at
    all of them — and the preflight writes nothing, ever;
  * the exit codes mean what the docstring says: 0 nothing wrong, 1 a finding,
    2 could not look. A caller gating a deploy has to tell those apart.
"""

import contextlib
import importlib.util
import io
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock
from urllib.parse import parse_qs, urlparse

_SCRIPT_PATH = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "zone-notify-reconcile.py")
)
_spec = importlib.util.spec_from_file_location("zone_notify_reconcile", _SCRIPT_PATH)
znr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(znr)

SERVER_DOMAIN = "dns.cerulean.test"
OWN_IP = "172.17.0.1"

# Every name the fake resolver knows. The own-names — the server's published
# name, its address, and the NS names a zone here delegates to — are what make a
# target "this server"; `ns2.example.net` is a genuine second server and
# `ns1.nowhere.test` a broken delegation, which must not be confused with one.
RESOLVE = {
    SERVER_DOMAIN: [OWN_IP],
    OWN_IP: [OWN_IP],
    "ns1.innotel.us": [OWN_IP],
    "ns2.innotel.us": [OWN_IP],
    "ns2.example.net": ["203.0.113.9"],
    "ns1.nowhere.test": [],
}


class FakeTechnitium:
    """Enough of the API for one judgement, including which writes were made."""

    def __init__(self, zones, options=None, records=None):
        self.zones = zones
        self.options = options or {}
        self.records = records or {}
        self.writes = []

    def get(self, path, authenticated=True):  # noqa: ARG002
        query = parse_qs(urlparse(path).query)
        if path.startswith("/api/zones/list"):
            return {"status": "ok", "response": {"zones": self.zones}}
        if path.startswith("/api/settings/get"):
            return {"status": "ok", "response": {"dnsServerDomain": SERVER_DOMAIN}}
        if path.startswith("/api/zones/options/get"):
            return {"status": "ok", "response": self.options.get(query["zone"][0], {})}
        if path.startswith("/api/zones/options/set"):
            self.writes.append((query["zone"][0], query.get("notify", [""])[0]))
            return {"status": "ok", "response": {}}
        if path.startswith("/api/zones/records/get"):
            return {"status": "ok", "response": {"records": self.records.get(query["domain"][0], [])}}
        raise AssertionError(f"unexpected Technitium path: {path}")


def ns_record(zone, nameserver):
    """One NS record in Technitium's shape (name is the zone, rData the target)."""
    return {"name": zone, "type": "NS", "rData": {"nameServer": nameserver}}


def zone(name, notify_failed=False, type_="Primary"):
    return {"name": name, "type": type_, "disabled": False, "notifyFailed": notify_failed}


def run_main(argv, technitium, env=None, urlopen=None):
    """Run the CLI against a fake API; returns (exit code, stdout, stderr).

    `technitium` replaces the API class outright, so the URL and token in the
    environment are only ever values the script passes along — no request
    leaves the process. Keep the real class and pass `urlopen` instead to
    exercise its own error handling.
    """
    out, err = io.StringIO(), io.StringIO()
    environment = {"TECHNITIUM_URL": f"http://{OWN_IP}:5380", "TECHNITIUM_TOKEN": "tok"}
    environment.update(env or {})
    code = None
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(sys, "argv", ["zone-notify-reconcile.py", *argv]))
        stack.enter_context(mock.patch.dict(os.environ, environment, clear=True))
        stack.enter_context(mock.patch.object(
            znr, "addresses_of", lambda name: list(RESOLVE.get(name.strip("."), []))))
        stack.enter_context(mock.patch.object(znr, "Technitium", technitium))
        if urlopen is not None:
            stack.enter_context(mock.patch.object(znr.urllib.request, "urlopen", urlopen))
        stack.enter_context(redirect_stdout(out))
        stack.enter_context(redirect_stderr(err))
        try:
            code = znr.main()
        except SystemExit as exc:  # the "could not run" paths exit rather than return
            code = exc.code if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue()


def fake(server):
    """A Technitium replacement class that hands back the prepared fake."""
    return lambda *args, **kwargs: server


class CanonicalTest(unittest.TestCase):
    def test_ipv4_mapped_equals_bare(self):
        self.assertEqual(znr.canonical("::ffff:73.68.203.71"), znr.canonical("73.68.203.71"))

    def test_a_hostname_is_left_alone(self):
        self.assertEqual(znr.canonical("ns1.innotel.us"), "ns1.innotel.us")

    def test_names_are_compared_without_a_trailing_dot_or_case(self):
        self.assertEqual(znr.normalise_name(" NS1.Innotel.US. "), "ns1.innotel.us")


class ZoneTargetsTest(unittest.TestCase):
    def test_zone_name_servers_are_the_ns_records_of_the_apex(self):
        api = FakeTechnitium([], records={"innotel.us": [ns_record("innotel.us", "ns1.innotel.us"),
                                                         ns_record("innotel.us", "ns2.innotel.us")]})
        self.assertEqual(
            znr.zone_targets(api, "innotel.us", "ZoneNameServers", {}, SERVER_DOMAIN),
            ["ns1.innotel.us", "ns2.innotel.us"],
        )

    def test_a_subdomain_ns_record_is_not_the_zones_delegation(self):
        """Only the apex's NS records say who a NOTIFY goes to."""
        api = FakeTechnitium([], records={"innotel.us": [ns_record("other.innotel.us", "ns9.example.net")]})
        self.assertEqual(znr.zone_targets(api, "innotel.us", "ZoneNameServers", {}, SERVER_DOMAIN), [])

    def test_the_servers_own_domain_is_excluded_like_technitium_does(self):
        """Technitium skips its own server name — the one green zone on the box."""
        records = {"lab.innotel.us": [ns_record("lab.innotel.us", SERVER_DOMAIN),
                                      ns_record("lab.innotel.us", "ns1.innotel.us")]}
        api = FakeTechnitium([], records=records)
        self.assertEqual(
            znr.zone_targets(api, "lab.innotel.us", "ZoneNameServers", {}, SERVER_DOMAIN),
            ["ns1.innotel.us"],
        )

    def test_duplicate_targets_are_reported_once(self):
        records = {"x.test": [ns_record("x.test", "ns1.innotel.us"), ns_record("x.test", "NS1.INNOTEL.US.")]}
        api = FakeTechnitium([], records=records)
        self.assertEqual(znr.zone_targets(api, "x.test", "ZoneNameServers", {}, SERVER_DOMAIN),
                         ["ns1.innotel.us"])

    def test_specified_name_servers_come_from_the_zone_options(self):
        api = FakeTechnitium([])
        options = {"notifyNameServers": ["ns1.innotel.us", ""]}
        self.assertEqual(znr.zone_targets(api, "x.test", "SpecifiedNameServers", options, SERVER_DOMAIN),
                         ["ns1.innotel.us"])

    def test_notify_none_has_no_targets(self):
        self.assertEqual(znr.zone_targets(FakeTechnitium([]), "x.test", "None", {}, SERVER_DOMAIN), [])


class SelfOnlyTest(unittest.TestCase):
    def test_every_target_on_this_server_is_a_self_notify(self):
        self.assertTrue(znr.self_only({"ns1.innotel.us": [OWN_IP]}, {OWN_IP}))

    def test_one_genuine_second_server_makes_it_not_ours(self):
        self.assertFalse(znr.self_only({"ns1.innotel.us": [OWN_IP],
                                        "ns2.example.net": ["203.0.113.9"]}, {OWN_IP}))

    def test_a_name_that_resolves_nowhere_is_not_a_self_notify(self):
        self.assertFalse(znr.self_only({"ns1.innotel.us": []}, {OWN_IP}))

    def test_no_targets_at_all_is_not_a_self_notify(self):
        self.assertFalse(znr.self_only({}, {OWN_IP}))

    def test_a_second_address_on_this_box_does_not_hide_a_foreign_one(self):
        self.assertFalse(znr.self_only({"ns1.innotel.us": [OWN_IP, "192.168.1.46"]}, {OWN_IP}))

    def test_a_second_address_on_this_box_still_is_a_self_notify(self):
        """NS1 and NS2 both resolving here is the estate's real state."""
        self.assertTrue(znr.self_only({"ns1.innotel.us": [OWN_IP],
                                       "ns2.innotel.us": ["192.168.1.46"]},
                                      {OWN_IP, "192.168.1.46"}))


class ReconcileTest(unittest.TestCase):
    """The narrow path: only zones Technitium has already flagged."""

    def _server(self, notify_failed=True):
        zones = [zone("innotel.us", notify_failed)]
        options = {"innotel.us": {"notify": "ZoneNameServers"}}
        records = {"innotel.us": [ns_record("innotel.us", "ns1.innotel.us"),
                                  ns_record("innotel.us", "ns2.innotel.us")]}
        return FakeTechnitium(zones, options, records)

    def test_reports_a_self_notifying_zone_and_exits_1(self):
        code, out, _ = run_main([], fake(self._server()))
        self.assertEqual(code, 1)
        self.assertIn("innotel.us", out)
        self.assertIn("can only fail to notify", out)

    def test_apply_writes_notify_none_and_records_the_undo(self):
        server = self._server()
        code, out, _ = run_main(["--apply"], fake(server))
        self.assertEqual(code, 1)
        self.assertEqual(server.writes, [("innotel.us", "None")])
        self.assertIn("undo: notify=ZoneNameServers", out)

    def test_a_zone_that_is_not_flagged_is_not_reconciled(self):
        """Narrow by construction: the flag is what puts a zone in scope."""
        server = self._server(notify_failed=False)
        code, out, _ = run_main(["--apply"], fake(server))
        self.assertEqual(code, 0)
        self.assertEqual(server.writes, [])
        self.assertIn("no zone is flagged notifyFailed", out)

    def test_a_genuine_second_server_is_reported_and_never_written(self):
        zones = [zone("cattape.us", notify_failed=True)]
        options = {"cattape.us": {"notify": "ZoneNameServers"}}
        records = {"cattape.us": [ns_record("cattape.us", "ns1.innotel.us"),
                                  ns_record("cattape.us", "ns2.example.net")]}
        server = FakeTechnitium(zones, options, records)
        code, out, _ = run_main(["--apply"], fake(server))
        self.assertEqual(code, 0)
        self.assertEqual(server.writes, [])
        self.assertIn("a second server is not answering; left alone", out)


class PreflightTest(unittest.TestCase):
    """The deploy gate: every enabled Primary zone, and nothing written."""

    def _server(self, notify_failed=False, notify="ZoneNameServers"):
        zones = [zone("innotel.us", notify_failed)]
        options = {"innotel.us": {"notify": notify}}
        records = {"innotel.us": [ns_record("innotel.us", "ns1.innotel.us")]}
        return FakeTechnitium(zones, options, records)

    def test_exits_1_before_technitium_has_flagged_the_zone(self):
        code, out, _ = run_main(["--preflight"], fake(self._server(notify_failed=False)))
        self.assertEqual(code, 1)
        self.assertIn("not flagged yet", out)
        self.assertIn("before bringing the stack up", out)

    def test_exits_0_when_every_zone_is_green(self):
        code, out, _ = run_main(["--preflight"], fake(self._server(notify="None")))
        self.assertEqual(code, 0)
        self.assertIn("none is armed to notify only this server", out)

    def test_writes_nothing_even_when_armed(self):
        server = self._server()
        code, _, _ = run_main(["--preflight"], fake(server))
        self.assertEqual(code, 1)
        self.assertEqual(server.writes, [])

    def test_preflight_never_applies(self):
        code, _, err = run_main(["--preflight", "--apply"], fake(self._server()))
        self.assertEqual(code, 2)
        self.assertIn("--preflight writes nothing", err)


class CouldNotRunTest(unittest.TestCase):
    """Exit 2 is its own answer: a caller gating a deploy must tell it from a finding."""

    def test_no_technitium_url_is_exit_2(self):
        code, _, err = run_main(["--preflight"], fake(None), env={"TECHNITIUM_URL": ""})
        self.assertEqual(code, 2)
        self.assertIn("TECHNITIUM_URL is not set", err)

    def test_an_unreachable_server_is_exit_2_not_a_finding(self):
        """The script's own handler, not a stub: a refused connection is not a finding."""
        import urllib.error

        def refuse(*args, **kwargs):
            raise urllib.error.URLError("connection refused")

        code, _, err = run_main(["--preflight"], znr.Technitium, urlopen=refuse)
        self.assertEqual(code, 2)
        self.assertIn("cannot reach Technitium", err)

    def test_a_refused_token_is_exit_2(self):
        import urllib.error

        def refused(request, timeout=None):  # noqa: ARG001
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {},
                                         io.BytesIO(b'{"status":"error"}'))

        code, _, err = run_main(["--preflight"], znr.Technitium, urlopen=refused)
        self.assertEqual(code, 2)
        self.assertIn("HTTP 401", err)
        self.assertNotIn("armed", err)


if __name__ == "__main__":
    unittest.main()
