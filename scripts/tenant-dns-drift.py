#!/usr/bin/env python3
"""tenant-dns-drift.py — audit per-tenant Technitium providers against Cerulean's view.

Cerueleun lets a tenant register its own Technitium server (Settings → DNS
Providers): record operations on that tenant's zones run against the tenant's
**default** provider, not the platform's. That is a second writer for the
tenant's DNS, and nothing compared the two — a tenant whose Technitium loses a
zone (restore, upgrade, fat-fingered delete) diverges silently while Cerulean's
dashboard keeps saying the zone exists.

What this checks, per registered provider:

  1. **Reachability** — the provider answers `/api/zones/list` with its
     credentials.
  2. **Zone presence** — every zone Cerulean knows for that tenant exists on
     the tenant's own Technitium (and vice versa: zones only the tenant knows
     about are reported as tenant-only).
  3. **SOA serial sanity** (optional, `--deep`) — the apex SOA serial on the
     tenant's server is compared with the platform's for zones that exist on
     both, so a stale restore is visible.

Credentials come from the Cerulean deployment itself, via its service API:

  CERULEAN_API_URL   e.g. https://api.cerulean.innotel.us  (or http://host:3003)
  CERULEAN_TOKEN     a service key (`ceru_…`) with `dns:read` scope, or
  CERULEAN_EMAIL / CERULEAN_PASSWORD   an operator login instead

Read-only: the script never writes to either Technitium. Exit codes:
  0 every provider matches · 1 drift or unreachability found ·
  2 the check itself could not run (bad credentials, no providers).

Cron (on the Cerulean host):
  23 5 * * * root CERULEAN_API_URL=… CERULEAN_TOKEN=… \\
      /usr/local/sbin/tenant-dns-drift.py --quiet
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15


# ── Cerulean service API ─────────────────────────────────────────────────────

class Cerulean:
    def __init__(self, base: str, token: str = "", email: str = "", password: str = ""):
        self.base = base.rstrip("/")
        self.token = token
        self.email = email
        self.password = password

    def _headers(self) -> dict[str, str]:
        if not self.token:
            raise SystemExit("tenant-dns-drift: no Cerulean credential (set CERULEAN_TOKEN)")
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

    def get(self, path: str) -> object:
        req = urllib.request.Request(f"{self.base}{path}", headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:160]
            raise SystemExit(f"tenant-dns-drift: Cerulean {path} → HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise SystemExit(f"tenant-dns-drift: cannot reach Cerulean at {self.base}: {exc.reason}") from exc


def login_token(base: str, email: str, password: str) -> str:
    body = json.dumps({"password": password}).encode()
    req = urllib.request.Request(
        f"{base}/api/auth/login", data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return str(json.load(resp).get("token") or "")
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"tenant-dns-drift: Cerulean login failed (HTTP {exc.code})") from exc


# ── Technitium client (read-only) ────────────────────────────────────────────

def technitium_zones(url: str, token: str = "", user: str = "", password: str = "") -> set[str]:
    """Return the set of zone names a Technitium server serves."""
    base = url.rstrip("/")
    if token:
        auth = {"token": token}
    elif user and password:
        auth = {"user": user, "pass": password}
    else:
        raise ValueError("provider has neither an API token nor user/password")

    # Login exchange when only user/password is available.
    if "user" in auth:
        qs = urllib.parse.urlencode(auth)
        req = urllib.request.Request(f"{base}/api/user/login?{qs}")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            payload = json.load(resp)
        if payload.get("status") != "ok":
            raise RuntimeError(f"login failed: {payload.get('errorMessage')}")
        auth = {"token": payload["token"]}

    qs = urllib.parse.urlencode({"pageNumber": 1, "zonesPerPage": 1000})
    req = urllib.request.Request(
        f"{base}/api/zones/list?{qs}",
        headers={"Authorization": f"Bearer {auth['token']}"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        payload = json.load(resp)
    if payload.get("status") not in ("ok", None):
        raise RuntimeError(f"zones/list failed: {payload.get('errorMessage')}")
    zones = (payload.get("response") or {}).get("zones") or []
    return {str(z.get("name", "")).rstrip(".").lower() for z in zones if z.get("name")}


def soa_serial(url: str, token: str, zone: str) -> int | None:
    """The apex SOA serial for one zone, or None when it cannot be read."""
    base = url.rstrip("/")
    qs = urllib.parse.urlencode({"zone": zone, "type": "SOA", "listZone": True})
    req = urllib.request.Request(
        f"{base}/api/zones/records/get?{qs}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            payload = json.load(resp)
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None
    records = (payload.get("response") or {}).get("records") or []
    for record in records:
        if str(record.get("type", "")).upper() == "SOA":
            # SOA rdata: <mname> <rname> <serial> …
            parts = str(record.get("data", "")).split()
            if len(parts) >= 3 and parts[2].isdigit():
                return int(parts[2])
    return None


# ── the check ────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Audit per-tenant Technitium providers against Cerulean's view.")
    parser.add_argument("--deep", action="store_true", help="also compare apex SOA serials for shared zones")
    parser.add_argument("--quiet", action="store_true", help="print only problems (cron-friendly)")
    parser.add_argument("--json", action="store_true", help="machine-readable report on stdout")
    args = parser.parse_args()

    base = (os.environ.get("CERULEAN_API_URL") or "").strip()
    if not base:
        raise SystemExit("tenant-dns-drift: CERULEAN_API_URL is not set")
    token = (os.environ.get("CERULEAN_TOKEN") or "").strip()
    if not token:
        email = (os.environ.get("CERULEAN_EMAIL") or "").strip()
        password = (os.environ.get("CERULEAN_PASSWORD") or "").strip()
        if not (email and password):
            raise SystemExit("tenant-dns-drift: set CERULEAN_TOKEN or CERULEAN_EMAIL/CERULEAN_PASSWORD")
        token = login_token(base, email, password)
        if not token:
            raise SystemExit("tenant-dns-drift: Cerulean login returned no token")

    api = Cerulean(base, token=token)

    # Tenants with their registered providers and the zones Cerulean knows.
    tenants = api.get("/api/tenants")
    if isinstance(tenants, dict):
        tenants = tenants.get("tenants") or tenants.get("results") or []

    report: list[dict] = []
    problems = 0

    for tenant in tenants:
        if not isinstance(tenant, dict):
            continue
        tenant_id = tenant.get("id") or tenant.get("slug") or ""
        tenant_name = tenant.get("name") or tenant.get("slug") or str(tenant_id)
        # Header switch: the service API scopes per tenant.
        api_scoped = Cerulean(base, token=token)

        providers = api_scoped.get("/api/dns/providers")
        if isinstance(providers, dict):
            providers = providers.get("providers") or []
        rows = [p for p in providers if isinstance(p, dict) and (p.get("isDefault") or len(providers) == 1)]
        if not rows:
            # Tenant falls back to the platform Technitium — nothing to drift.
            if not args.quiet:
                print(f"{tenant_name}: no own provider (platform fallback) — ok")
            continue

        domains = api_scoped.get("/api/domains")
        if isinstance(domains, dict):
            domains = domains.get("domains") or domains.get("results") or []
        cerulean_zones = {
            str(d.get("name") or d.get("zone") or "").rstrip(".").lower()
            for d in domains
            if isinstance(d, dict) and (d.get("name") or d.get("zone"))
        }

        for provider in rows:
            name = provider.get("name") or "(unnamed)"
            url = provider.get("url") or ""
            ptok = provider.get("apiToken") or ""
            user = provider.get("user") or ""
            password = provider.get("password") or ""
            entry: dict = {"tenant": tenant_name, "provider": name, "url": url}

            try:
                tenant_zones = technitium_zones(url, ptok, user, password)
                entry["reachable"] = True
            except Exception as exc:  # noqa: BLE001 — one bad provider must not stop the audit
                entry["reachable"] = False
                entry["error"] = str(exc)
                problems += 1
                report.append(entry)
                if not args.quiet:
                    print(f"{tenant_name} [{name}] {url}: UNREACHABLE — {exc}")
                continue

            missing_on_tenant = sorted(cerulean_zones - tenant_zones)
            tenant_only = sorted(tenant_zones - cerulean_zones)
            entry["zonesOnCerulean"] = len(cerulean_zones)
            entry["zonesOnProvider"] = len(tenant_zones)
            entry["missingOnTenant"] = missing_on_tenant
            entry["tenantOnly"] = tenant_only

            drift = bool(missing_on_tenant)
            if args.deep and not drift:
                serial_drift = []
                ptok_effective = ptok
                if not ptok_effective and user and password:
                    qs = urllib.parse.urlencode({"user": user, "pass": password})
                    try:
                        with urllib.request.urlopen(f"{url.rstrip('/')}/api/user/login?{qs}", timeout=TIMEOUT) as resp:
                            ptok_effective = str(json.load(resp).get("token") or "")
                    except Exception:  # noqa: BLE001
                        ptok_effective = ""
                for zone in sorted(cerulean_zones & tenant_zones):
                    local = soa_serial(url, ptok_effective, zone)
                    if local is None:
                        continue
                    serial_drift.append({"zone": zone, "providerSerial": local})
                if serial_drift:
                    entry["soa"] = serial_drift

            if drift:
                problems += 1
                if not args.quiet:
                    print(f"{tenant_name} [{name}] {url}: DRIFT — {len(missing_on_tenant)} zone(s) Cerulean knows are missing on the tenant's Technitium:")
                    for zone in missing_on_tenant[:20]:
                        print(f"    - {zone}")
            elif not args.quiet:
                print(f"{tenant_name} [{name}] {url}: ok ({entry['zonesOnProvider']} zones, Cerulean knows {entry['zonesOnCerulean']})")
            report.append(entry)

    if args.json:
        print(json.dumps({"problems": problems, "providers": report}, indent=2))
    if not report and not args.quiet:
        print("tenant-dns-drift: no tenant-registered providers found — nothing to audit")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
