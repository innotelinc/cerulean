#!/usr/bin/env python3
"""Import parsed BIND zone JSON into Technitium DNS Server via its HTTP API.

Usage:
  python3 bind-import.py [--dry-run] [--zones z1,z2,...]

Reads /tmp/bind-migration/parsed/<zone>.json files (from bind-migrate.py).

Behaviour:
  * Creates missing Primary zones.
  * Deletes the auto-created apex NS (pointing at DNS_SERVER_DOMAIN), then
    imports the apex NS records from the BIND data.
  * Skips SOA (Technitium generates its own) and stale _acme-challenge TXT
    (Cerulean manages those dynamically).
  * Idempotent: skips records that already exist.
"""
import json
import pathlib
import sys
import urllib.parse
import urllib.request

PARSED_DIR = pathlib.Path("/tmp/bind-migration/parsed")
TECH_URL = "http://127.0.0.1:5380"
ALL_ZONES = ["fomocoin.one", "cattape.us", "denovocredit.com", "rizzaura.net", "innotel.us"]
AUTO_NS_HOST = "lab.innotel.us"  # DNS_SERVER_DOMAIN auto NS to remove


def api(token: str, path: str, params: dict, method: str = "GET"):
    qs = urllib.parse.urlencode(params)
    url = f"{TECH_URL}{path}?{qs}"
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
    return body


def login() -> str:
    import os
    pw = os.environ["TECH_PASSWORD"]
    r = api(None, "/api/user/login", {"user": "admin", "pass": pw})
    if r.get("status") != "ok":
        raise SystemExit(f"login failed: {r}")
    return r["token"]


def ensure_dot(name: str) -> str:
    return name if name.endswith(".") else name + "."


def record_params(rec: dict) -> dict:
    """Map a parsed record to Technitium /api/zones/records/add params."""
    t, d = rec["type"], rec["data"]
    p = {"domain": rec["name"], "type": t, "ttl": rec["ttl"]}
    if t == "A" or t == "AAAA":
        p["ipAddress"] = d
    elif t == "CNAME":
        p["cname"] = ensure_dot(d)
    elif t == "NS":
        p["nameServer"] = ensure_dot(d)
    elif t == "PTR":
        p["ptrName"] = ensure_dot(d)
    elif t == "MX":
        pref, ex = d.split(None, 1)
        p["preference"] = pref
        p["exchange"] = ensure_dot(ex.strip())
    elif t == "SRV":
        pri, w, port, tgt = d.split()
        p["priority"] = pri
        p["weight"] = w
        p["port"] = port
        p["target"] = ensure_dot(tgt)
    elif t in ("TXT", "SPF"):
        p["text"] = d  # Technitium handles quoting
    elif t == "CAA":
        flags, tag, val = d.split(None, 2)
        p["flags"] = flags
        p["tag"] = tag
        p["value"] = val.strip().strip('"')
    else:
        raise ValueError(f"unsupported type {t}: {d}")
    return p


def existing_key(name: str, rtype: str, data: str) -> str:
    return f"{name}|{rtype}|{data.rstrip('.')}"


def main():
    dry = "--dry-run" in sys.argv
    zones = ALL_ZONES
    for i, a in enumerate(sys.argv):
        if a == "--zones" and i + 1 < len(sys.argv):
            zones = [z.strip() for z in sys.argv[i + 1].split(",") if z.strip()]

    token = "" if dry else login()
    total_added = total_skipped = total_fail = 0

    for zone in zones:
        jf = PARSED_DIR / f"{zone}.json"
        if not jf.exists():
            print(f"!! {zone}: parsed file missing, skipping")
            continue
        payload = json.loads(jf.read_text())
        recs = payload["records"]

        # ── create zone if needed ────────────────────────────────────────
        if dry:
            print(f"[dry] would ensure zone {zone} (Primary)")
        else:
            r = api(token, "/api/zones/create", {"zone": zone, "type": "Primary"}, "POST")
            if r.get("status") == "ok":
                print(f"++ created zone {zone}")
            elif "already exists" in (r.get("errorMessage") or ""):
                print(f"== zone {zone} exists")
            else:
                print(f"!! zone {zone} create: {r.get('errorMessage') or r.get('status')}")

        # ── snapshot existing records for idempotency ────────────────────
        existing = set()
        if not dry:
            r = api(token, "/api/zones/records/get", {"domain": zone})
            for rec in (r.get("response", {}) or {}).get("records", []) or []:
                existing.add(existing_key(rec.get("name", ""), rec.get("type", ""), rec.get("rdata", {}).get("value", "") or str(rec.get("rdata", ""))))

        # ── delete auto-created apex NS (DNS_SERVER_DOMAIN) ──────────────
        auto_ns = {"domain": zone, "type": "NS", "nameServer": ensure_dot(AUTO_NS_HOST)}
        if dry:
            print(f"[dry] would delete auto apex NS {AUTO_NS_HOST} in {zone}")
        else:
            r = api(token, "/api/zones/records/delete", auto_ns, "POST")
            print(f"-- auto apex NS in {zone}: {r.get('status')}")

        # ── import records ───────────────────────────────────────────────
        added = skipped = failed = 0
        for rec in recs:
            name, rtype, data = rec["name"], rec["type"], rec["data"]
            # skip SOA + stale acme TXT
            if rtype == "SOA":
                continue
            if rtype == "TXT" and name.startswith("_acme-challenge."):
                print(f"   skip stale {name} TXT")
                continue
            key = existing_key(name, rtype, data)
            if key in existing:
                skipped += 1
                continue
            try:
                params = record_params(rec)
            except ValueError as e:
                print(f"   !! {name}: {e}")
                failed += 1
                continue
            if dry:
                added += 1
                continue
            r = api(token, "/api/zones/records/add", params, "POST")
            if r.get("status") == "ok" or "already exists" in (r.get("errorMessage") or ""):
                added += 1
            else:
                print(f"   !! {name} {rtype}: {r.get('errorMessage') or r.get('status')}")
                failed += 1

        print(f"{zone}: added={added} skipped={skipped} failed={failed}")
        total_added += added
        total_skipped += skipped
        total_fail += failed

    print(f"\nTOTAL: added={total_added} skipped={total_skipped} failed={total_fail}")
    if total_fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
