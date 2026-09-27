#!/usr/bin/env python3
"""edge-dns-check.py — assert public names still resolve to the NPM edge.

Why this exists
---------------
The AthenIQ host moved to 192.168.1.59, but every public name is a CNAME to
`innotel.us`, whose single A record is the estate's shared egress
(73.68.203.71). The edge on `.46`/`.71` is what actually fronts the services.
If that apex A record is repointed, or a name is given a stray A/AAAA of its
own, clients bypass the edge and the site fails — while every container stays
healthy and every other check stays green. Nothing compared the two.

This asks the authoritative Technitium server what it actually *serves*,
follows CNAME chains to the address a client would receive, and compares that
to the expected edge address. Read-only: it never writes DNS.

Configuration (environment):
  TECHNITIUM_URL   base URL of the platform Technitium (default http://127.0.0.1:5380)
  TECHNITIUM_TOKEN a Technitium API token, OR
  TECHNITIUM_USER / TECHNITIUM_PASSWORD   an operator login instead
  EDGE_DNS_IP      the address the names must resolve to (default 73.68.203.71)
  EDGE_DNS_ZONE    the zone that holds them (default innotel.us)
  EDGE_DNS_NAMES   comma-separated names to check (overrides the default set)

Usage:
  edge-dns-check.py [--names a,b] [--edge-ip IP] [--zone ZONE] [--quiet] [--json]

Exit codes: 0 every name resolves to the edge · 1 drift · 2 the check could not run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15

# The names this deployment fronts through the edge. Kept as the default so the
# check works with no arguments; override with EDGE_DNS_NAMES/--names.
DEFAULT_NAMES = (
    "learn.innotel.us",
    "studio.innotel.us",
    "apps.learn.innotel.us",
    "meilisearch.learn.innotel.us",
    "auth.cerulean.innotel.us",
)
DEFAULT_EDGE_IP = "73.68.203.71"
DEFAULT_ZONE = "innotel.us"


def norm(name: str) -> str:
    return (name or "").strip().rstrip(".").lower()


# ── record handling (pure: unit-tested without a server) ─────────────────────

def build_record_map(records: list) -> dict[str, list[dict]]:
    """Group the zone's records by owner name (lowercase, no trailing dot)."""
    out: dict[str, list[dict]] = {}
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        owner = norm(rec.get("name", ""))
        if owner:
            out.setdefault(owner, []).append(rec)
    return out


def _address_of(rec: dict) -> str:
    rdata = rec.get("rData") or rec.get("value") or {}
    if isinstance(rdata, dict):
        return str(rdata.get("ipAddress") or rdata.get("ipv6Address") or "")
    return ""


def _cname_of(rec: dict) -> str:
    rdata = rec.get("rData") or rec.get("value") or {}
    if isinstance(rdata, dict):
        return norm(rdata.get("cname") or rdata.get("value") or "")
    return ""


def resolve_addresses(record_map: dict[str, list[dict]], name: str):
    """Follow CNAMEs to the addresses a client would get.

    Returns (addresses, reason) where exactly one is meaningful: a list of
    address strings on success, or a reason string when the chain cannot reach
    an A/AAAA record (dangling CNAME, loop, or no records at all).
    """
    seen: list[str] = []
    current = norm(name)
    while True:
        if current in seen:
            return [], "CNAME loop at %s" % current
        seen.append(current)
        recs = record_map.get(current, [])
        addrs = [_address_of(r) for r in recs
                 if str(r.get("type", "")).upper() in ("A", "AAAA")]
        addrs = [a for a in addrs if a]
        if addrs:
            return addrs, ""
        cnames = [_cname_of(r) for r in recs
                  if str(r.get("type", "")).upper() == "CNAME"]
        cnames = [c for c in cnames if c]
        if cnames:
            current = cnames[0]
            continue
        if not recs:
            return [], "no records for %s" % current
        return [], "no A/AAAA or CNAME at %s" % current


# ── Technitium access ───────────────────────────────────────────────────────

def technitium_token(base: str) -> str:
    token = (os.environ.get("TECHNITIUM_TOKEN") or "").strip()
    if token:
        return token
    user = (os.environ.get("TECHNITIUM_USER") or "").strip()
    password = (os.environ.get("TECHNITIUM_PASSWORD") or "").strip()
    if not (user and password):
        raise SystemExit(
            "edge-dns-check: set TECHNITIUM_TOKEN or TECHNITIUM_USER/TECHNITIUM_PASSWORD"
        )
    qs = urllib.parse.urlencode({"user": user, "pass": password})
    try:
        with urllib.request.urlopen(f"{base}/api/user/login?{qs}", timeout=TIMEOUT) as resp:
            payload = json.load(resp)
    except urllib.error.URLError as exc:
        raise SystemExit(f"edge-dns-check: cannot reach Technitium at {base}: {exc.reason}") from exc
    if payload.get("status") != "ok":
        raise SystemExit(f"edge-dns-check: Technitium login failed: {payload.get('errorMessage')}")
    return str(payload["token"])


def fetch_zone_records(base: str, token: str, zone: str) -> list:
    qs = urllib.parse.urlencode({"token": token, "domain": zone, "zone": zone,
                                 "listZone": "true"})
    try:
        with urllib.request.urlopen(f"{base}/api/zones/records/get?{qs}", timeout=TIMEOUT) as resp:
            payload = json.load(resp)
    except urllib.error.URLError as exc:
        raise SystemExit(f"edge-dns-check: cannot read zone {zone}: {exc.reason}") from exc
    if payload.get("status") not in ("ok", None):
        raise SystemExit(f"edge-dns-check: Technitium get failed: {payload.get('errorMessage')}")
    return (payload.get("response") or {}).get("records") or []


# ── the check ───────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--names", default="",
                        help="comma-separated names to check (default: the built-in set)")
    parser.add_argument("--edge-ip", default=os.environ.get("EDGE_DNS_IP", DEFAULT_EDGE_IP))
    parser.add_argument("--zone", default=os.environ.get("EDGE_DNS_ZONE", DEFAULT_ZONE))
    parser.add_argument("--quiet", action="store_true", help="print only problems")
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    args = parser.parse_args(argv)

    names = args.names or os.environ.get("EDGE_DNS_NAMES", "")
    names = [norm(n) for n in names.split(",") if n.strip()] or list(DEFAULT_NAMES)

    base = (os.environ.get("TECHNITIUM_URL") or "http://127.0.0.1:5380").rstrip("/")
    zone = norm(args.zone)
    edge_ip = args.edge_ip.strip()

    records = fetch_zone_records(base, technitium_token(base), zone)
    record_map = build_record_map(records)

    findings: list[dict] = []
    problems = 0

    # The apex A record is the whole edge for these CNAMEs — check it directly so
    # a repoint is caught even if every name is still a well-formed CNAME.
    apex_addrs, _ = resolve_addresses(record_map, zone)
    apex_ok = edge_ip in apex_addrs
    if not apex_ok:
        problems += 1
        findings.append({"name": zone, "ok": False, "addresses": apex_addrs,
                         "reason": "apex does not publish the edge address"})
    elif not args.quiet:
        print(f"{zone}: {edge_ip} (edge) — ok")

    for name in names:
        addrs, reason = resolve_addresses(record_map, name)
        ok = edge_ip in addrs
        if not ok:
            problems += 1
        findings.append({"name": name, "ok": ok, "addresses": addrs, "reason": reason})
        if not ok:
            detail = reason or ("resolves to %s" % ", ".join(addrs) if addrs else "no address")
            print(f"{name}: DOES NOT resolve to {edge_ip} — {detail}")
        elif not args.quiet:
            print(f"{name}: {edge_ip} — ok")

    if args.json:
        print(json.dumps({"edgeIp": edge_ip, "zone": zone,
                          "problems": problems, "findings": findings}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
