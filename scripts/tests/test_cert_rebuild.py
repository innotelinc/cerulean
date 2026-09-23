#!/usr/bin/env python3
"""Tests for scripts/cert-rebuild.py — the body of a host reassignment.

The tool's one write is a PUT of an existing proxy host with a different
certificate. It builds that body from the host's own GET, and the field that
matters is `locations`: NPM answers `null` for a host that has no location
blocks, and its update route rejects that with `data/locations must be array`.

That is not a detail of the host being written — the abort kills the run, so
every host after it keeps pointing at the certificate that was about to be
deleted, and no superseded certificate is ever removed. It was measured on host
181 (`preview-smoke-preview.studio.olympus.innotel.us`) on 2026-09-23, four
hosts into the first apply. What is asserted here:

  * `null` locations travel as an empty list, and a real location list is passed
    through untouched — both are "no change" for a host that has none;
  * a host that omits the key entirely still gets a list, because NPM's route
    wants the array either way;
  * the certificate id in the body is the one asked for, including `0`, which is
    how the detach path takes a host off a certificate before deleting it;
  * every field NPM returned for a host is carried, and nothing NPM did not
    return is invented — the route rejects unknown fields;
  * the host record itself is left alone, because the caller re-reads
    `certificate_id` from it to decide what still points where.
"""

import copy
import importlib.util
import os
import unittest

_SCRIPT_PATH = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cert-rebuild.py")
)
_spec = importlib.util.spec_from_file_location("cert_rebuild", _SCRIPT_PATH)
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)

# A host as NPM's GET returns it, in the shape that aborted the run: no location
# blocks (`null`), plus the fields the update route accepts and a few it does not.
HOST = {
    "id": 181,
    "created_on": "2026-08-01T00:00:00.000Z",
    "modified_on": "2026-09-23T00:00:00.000Z",
    "owner_user_id": 1,
    "domain_names": ["preview-smoke-preview.studio.olympus.innotel.us"],
    "forward_scheme": "http",
    "forward_host": "192.168.1.90",
    "forward_port": 3000,
    "access_list_id": 0,
    "certificate_id": 51,
    "ssl_forced": True,
    "caching_enabled": False,
    "block_exploits": True,
    "advanced_config": "",
    "meta": {"letsencrypt_agree": False, "dns_challenge": False},
    "allow_websocket_upgrade": True,
    "http2_support": True,
    "forwarded_port": 80,
    "forwarded_scheme": "http",
    "locations": None,
    "hsts_enabled": False,
    "hsts_subdomains": False,
    "trust_forwarded_proto": False,
    "enabled": True,
}


class PutBodyTest(unittest.TestCase):
    def test_null_locations_become_an_empty_list(self):
        """The measured failure: NPM answers null, the update route wants an array."""
        self.assertEqual(cr.put_body(HOST, 60)["locations"], [])

    def test_a_real_location_list_is_passed_through(self):
        host = dict(HOST, locations=[{"path": "/api", "forward_scheme": "http",
                                      "forward_host": "192.168.1.91", "forward_port": 8080}])
        self.assertEqual(cr.put_body(host, 60)["locations"], host["locations"])

    def test_a_missing_locations_key_still_travels_as_a_list(self):
        host = {k: v for k, v in HOST.items() if k != "locations"}
        self.assertEqual(cr.put_body(host, 60)["locations"], [])

    def test_the_certificate_id_is_the_one_asked_for(self):
        self.assertEqual(cr.put_body(HOST, 62)["certificate_id"], 62)

    def test_zero_detaches_a_host(self):
        """How a host is taken off a certificate that is about to be deleted."""
        self.assertEqual(cr.put_body(HOST, 0)["certificate_id"], 0)

    def test_the_host_s_other_certificate_reference_is_replaced_not_merged(self):
        self.assertEqual(cr.put_body(HOST, 7)["certificate_id"], 7)
        self.assertNotEqual(cr.put_body(HOST, 7)["certificate_id"], HOST["certificate_id"])

    def test_every_field_the_route_accepts_is_carried(self):
        body = cr.put_body(HOST, 60)
        for key in cr.FIELDS:
            if key in HOST:
                self.assertIn(key, body, key)
        self.assertEqual(body["forward_host"], "192.168.1.90")
        self.assertEqual(body["forward_port"], 3000)
        self.assertTrue(body["ssl_forced"])
        self.assertEqual(body["meta"], HOST["meta"])

    def test_fields_npm_did_not_return_are_not_invented(self):
        """An unknown field is a rejected update, so the body is what NPM gave."""
        body = cr.put_body(HOST, 60)
        self.assertEqual(sorted(body), sorted(k for k in HOST if k in cr.FIELDS))
        for injected in ("id", "created_on", "modified_on", "owner_user_id",
                         "forwarded_port", "forwarded_scheme"):
            self.assertNotIn(injected, body)

    def test_the_host_record_is_not_modified(self):
        """The caller re-reads certificate_id from it; a mutated copy lies."""
        before = copy.deepcopy(HOST)
        cr.put_body(HOST, 60)
        self.assertEqual(HOST, before)


if __name__ == "__main__":
    unittest.main()
