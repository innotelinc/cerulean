#!/usr/bin/env python3
"""Tests for scripts/edge-dns-check.py.

The check exists because AthenIQ's public names are CNAMEs to `innotel.us`,
whose one A record is the estate's shared edge. The address a client receives
comes from following that chain on the authoritative server, so the contract
under test is the resolution:

  * a CNAME chain that reaches the apex A is ok;
  * a name that grows its own A/AAAA (bypassing the edge) is drift;
  * an apex A that is repointed is drift even when every name is still a
    well-formed CNAME;
  * a dangling CNAME / loop / wrong address is reported, not crashed.

The HTTP path is exercised against a fake Technitium so the token/URL plumbing
is real.
"""

import http.server
import importlib.util
import json
import os
import threading
import unittest

_SCRIPT_PATH = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "edge-dns-check.py")
)
_spec = importlib.util.spec_from_file_location("edge_dns_check", _SCRIPT_PATH)
edc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(edc)

EDGE = "73.68.203.71"

# A healthy zone: apex A is the edge, the names CNAME to it.
HEALTHY = [
    {"name": "innotel.us", "type": "A", "rData": {"ipAddress": EDGE}},
    {"name": "learn.innotel.us", "type": "CNAME", "rData": {"cname": "innotel.us"}},
    {"name": "studio.innotel.us", "type": "CNAME", "rData": {"cname": "innotel.us"}},
    {"name": "apps.learn.innotel.us", "type": "CNAME", "rData": {"cname": "innotel.us"}},
]


class FakeTechnitium(http.server.BaseHTTPRequestHandler):
    records = HEALTHY

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path.startswith("/api/zones/records/get"):
            body = json.dumps({"status": "ok", "response": {"records": self.records}}).encode()
        elif self.path.startswith("/api/user/login"):
            body = json.dumps({"status": "ok", "token": "fake-token"}).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


class Resolution(unittest.TestCase):
    def test_a_chain_through_the_apex_resolves(self):
        m = edc.build_record_map(HEALTHY)
        addrs, reason = edc.resolve_addresses(m, "learn.innotel.us")
        self.assertEqual(addrs, [EDGE])
        self.assertEqual(reason, "")

    def test_a_multi_hop_chain_resolves(self):
        records = [
            {"name": "innotel.us", "type": "A", "rData": {"ipAddress": EDGE}},
            {"name": "mid.innotel.us", "type": "CNAME", "rData": {"cname": "innotel.us"}},
            {"name": "leaf.innotel.us", "type": "CNAME", "rData": {"cname": "mid.innotel.us"}},
        ]
        m = edc.build_record_map(records)
        addrs, _ = edc.resolve_addresses(m, "leaf.innotel.us")
        self.assertEqual(addrs, [EDGE])

    def test_a_name_with_its_own_A_is_a_different_address(self):
        records = HEALTHY + [
            {"name": "studio.innotel.us", "type": "A", "rData": {"ipAddress": "192.168.1.59"}},
        ]
        m = edc.build_record_map(records)
        addrs, _ = edc.resolve_addresses(m, "studio.innotel.us")
        self.assertEqual(addrs, ["192.168.1.59"])

    def test_a_dangling_cname_is_reported(self):
        records = [{"name": "learn.innotel.us", "type": "CNAME",
                    "rData": {"cname": "gone.innotel.us"}}]
        addrs, reason = edc.resolve_addresses(edc.build_record_map(records), "learn.innotel.us")
        self.assertEqual(addrs, [])
        self.assertIn("no records", reason)

    def test_a_cname_loop_is_reported(self):
        records = [
            {"name": "a.innotel.us", "type": "CNAME", "rData": {"cname": "b.innotel.us"}},
            {"name": "b.innotel.us", "type": "CNAME", "rData": {"cname": "a.innotel.us"}},
        ]
        addrs, reason = edc.resolve_addresses(edc.build_record_map(records), "a.innotel.us")
        self.assertEqual(addrs, [])
        self.assertIn("loop", reason.lower())


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), FakeTechnitium)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.env = {
            "TECHNITIUM_URL": "http://127.0.0.1:%d" % self.server.server_port,
            "TECHNITIUM_USER": "admin",
            "TECHNITIUM_PASSWORD": "secret",
            "EDGE_DNS_IP": EDGE,
            "EDGE_DNS_NAMES": "learn.innotel.us,studio.innotel.us",
        }
        self._saved = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_a_healthy_zone_passes(self):
        self.assertEqual(edc.main(["--quiet"]), 0)

    def test_a_bypassing_name_is_drift(self):
        FakeTechnitium.records = HEALTHY + [
            {"name": "studio.innotel.us", "type": "A", "rData": {"ipAddress": "10.0.0.5"}},
        ]
        self.addCleanup(lambda: setattr(FakeTechnitium, "records", HEALTHY))
        self.assertEqual(edc.main(["--quiet"]), 1)

    def test_a_repointed_apex_is_drift(self):
        FakeTechnitium.records = [
            {"name": "innotel.us", "type": "A", "rData": {"ipAddress": "203.0.113.9"}},
            {"name": "learn.innotel.us", "type": "CNAME", "rData": {"cname": "innotel.us"}},
        ]
        self.addCleanup(lambda: setattr(FakeTechnitium, "records", HEALTHY))
        self.assertEqual(edc.main(["--quiet"]), 1)


if __name__ == "__main__":
    unittest.main()
