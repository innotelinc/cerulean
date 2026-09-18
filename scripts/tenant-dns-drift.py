#!/usr/bin/env python3
"""tenant-dns-drift.py — audit per-tenant Technitium providers against Cerulean's view.

Cerulean lets a tenant register its own Technitium server (Settings → DNS
Providers): record operations on that tenant's zones run against the tenant's
**default** provider, not the platform's. That is a second writer for the
tenant's DNS, and nothing compared the two — a tenant whose Technitium loses a
zone (restore, upgrade, fat-fingered delete) diverges silently while Cerulean's
dashboard keeps saying the zone exists.

What this checks, per tenant with a registered default provider:

  1. **Reachability** — the provider's URL answers at all.
  2. **Zone presence** — every zone Cerulean knows for that tenant is checked
     against the zones the provider actually serves. Presence on the provider
     is read through Cerulean's service bridge so the audit never needs (and
     never receives) provider credentials; with optional direct credentials in
     the environment the script talks to the provider's Technitium itself.
  3. **SOA serial sanity** (`--deep`) — for shared zones, the apex SOA serial
     the tenant's provider serves (records endpoint, tenant-scoped) is compared
     with the platform Technitium's serial for the same zone, so a stale
     restore is visible.

Credentials come from the Cerulean deployment itself, via its service API:

  CERULEAN_API_URL   e.g. https://api.cerulean.innotel.us  (or http://host:3003)
  CERULEAN_TOKEN     a service key (`ceru_…`) with dns/tenant read scopes, or
  CERULEAN_EMAIL / CERULEAN_PASSWORD   an operator login instead

Optional direct-provider check (skipped when unset):
  TECHNITIUM_URL / TECHNITIUM_TOKEN   or  TECHNITIUM_USER / TECHNITIUM_PASSWORD

Read-only: the script never writes to either Technitium. Exit codes:
  0 every provider matches · 1 drift or unreachability found ·
  2 the check itself could not run (bad credentials, no providers).

Cron (on the Cerulean host):
  23 5 * * * root /usr/local/sbin/tenant-dns-drift-cron.sh --quiet
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
    def __init__(self, base: str, token: str = ""):
        self.base = base.rstrip("/")
        self.token = token

    def _headers(self, tenant: str = "") -> dict[str, str]:
        if not self.token:
            raise SystemExit("tenant-dns-drift: no Cerulean credential (set CERULEAN_TOKEN)")
        hdr = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        if tenant:
            hdr["X-Cerulean-Tenant"] = tenant
        return hdr

    def get(self, path: str, tenant: str = "") -> object:
        req = urllib.request.Request(f"{self.base}{path}", headers=self._headers(tenant))
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


# ── Technitium clients ───────────────────────────────────────────────────────

def reachable(url: str) -> tuple[bool, str]:
    """A provider is reachable when its URL answers with any HTTP status."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url.rstrip("/"), method="GET")
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            return True, f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        return True, f"HTTP {exc.code}"  # an answer at all — endpoint is alive
    except Exception as exc:  # noqa: BLE001 — any transport failure = unreachable
        return False, str(exc)


def direct_technitium_zones(url: str) -> set[str] | None:
    """Zones on a Technitium server using env credentials, or None when the
    operator did not provide them / the URL does not match."""
    env_url = (os.environ.get("TECHNITIUM_URL") or "").strip().rstrip("/")
    if not env_url or env_url != url.rstrip("/"):
        return None
    token = (os.environ.get("TECHNITIUM_TOKEN") or "").strip()
    user = (os.environ.get("TECHNITIUM_USER") or "").strip()
    password = (os.environ.get("TECHNITIUM_PASSWORD") or "").strip()
    if not token and not (user and password):
        return None
    base = url.rstrip("/")
    if not token:
        qs = urllib.parse.urlencode({"user": user, "pass": password})
        req = urllib.request.Request(f"{base}/api/user/login?{qs}")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            payload = json.load(resp)
        if payload.get("status") != "ok":
            raise RuntimeError(f"login failed: {payload.get('errorMessage')}")
        token = str(payload["token"])
    qs = urllib.parse.urlencode({"pageNumber": 1, "zonesPerPage": 1000})
    req = urllib.request.Request(
        f"{base}/api/zones/list?{qs}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        payload = json.load(resp)
    if payload.get("status") not in ("ok", None):
        raise RuntimeError(f"zones/list failed: {payload.get('errorMessage')}")
    zones = (payload.get("response") or {}).get("zones") or []
    return {str(z.get("name", "")).rstrip(".").lower() for z in zones if z.get("name")}


def soa_serial_from_records(records: object) -> int | None:
    if not isinstance(records, list):
        return None
    for record in records:
        if str((record or {}).get("type", "")).upper() == "SOA":
            parts = str((record or {}).get("data", "")).split()
            if len(parts) >= 3 and parts[2].isdigit():
                return int(parts[2])
    return None


# ── the check ────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Audit per-tenant Technitium providers against Cerulean's view.")
    parser.add_argument("--deep", action="store_true", help="also compare apex SOA serials (tenant provider vs platform)")
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

    tenants = api.get("/api/service/tenants")
    if isinstance(tenants, dict):
        tenants = tenants.get("tenants") or tenants.get("results") or []

    report: list[dict] = []
    problems = 0

    for tenant in tenants:
        if not isinstance(tenant, dict):
            continue
        tenant_slug = str(tenant.get("slug") or tenant.get("id") or "")
        tenant_name = tenant.get("name") or tenant_slug

        providers = api.get("/api/service/dns/providers", tenant=tenant_slug)
        if isinstance(providers, dict):
            providers = providers.get("providers") or []
        own = [p for p in providers if isinstance(p, dict) and p.get("isDefault")]
        if not own:
            if not args.quiet:
                print(f"{tenant_name}: no own provider (platform fallback) — ok")
            continue

        # Zones Cerulean knows for this tenant.
        domains = api.get("/api/service/domains", tenant=tenant_slug)
        if isinstance(domains, dict):
            domains = domains.get("domains") or domains.get("results") or []
        cerulean_zones = {
            str(d.get("name") or d.get("zone") or "").rstrip(".").lower()
            for d in domains
            if isinstance(d, dict) and (d.get("name") or d.get("zone"))
        }

        for provider in own:
            name = provider.get("name") or "(unnamed)"
            url = provider.get("url") or ""
            entry: dict = {"tenant": tenant_name, "provider": name, "url": url,
                           "zonesOnCerulean": len(cerulean_zones)}

            ok, detail = reachable(url) if url else (False, "no url")
            entry["reachable"] = ok
            if not ok:
                entry["error"] = detail
                problems += 1
                report.append(entry)
                if not args.quiet:
                    print(f"{tenant_name} [{name}] {url}: UNREACHABLE — {detail}")
                continue

            # Zone presence: prefer direct env credentials when provided.
            provider_zones: set[str] | None = None
            try:
                provider_zones = direct_technitium_zones(url)
            except Exception as exc:  # noqa: BLE001
                entry["directCheckError"] = str(exc)

            missing_on_tenant: list[str] = []
            if provider_zones is not None:
                missing_on_tenant = sorted(cerulean_zones - provider_zones)
                entry["zonesOnProvider"] = len(provider_zones)
                entry["missingOnTenant"] = missing_on_tenant
                entry["tenantOnly"] = sorted(provider_zones - cerulean_zones)
            elif not args.quiet:
                print(f"{tenant_name} [{name}]: zone-presence via direct provider credentials not "
                      f"configured (set TECHNITIUM_URL/TOKEN to enable)")

            if args.deep:
                serial_drift = []
                for zone in sorted(cerulean_zones):
                    try:
                        tenant_rec = api.get(
                            f"/api/service/dns/records?zone={urllib.parse.quote(zone)}",
                            tenant=tenant_slug,
                        )
                        platform_rec = api.get(f"/api/service/dns/records?zone={urllib.parse.quote(zone)}")
                    except SystemExit:
                        raise
                    t_serial = soa_serial_from_records(tenant_rec)
                    p_serial = soa_serial_from_records(platform_rec)
                    if t_serial is not None and p_serial is not None and t_serial != p_serial:
                        serial_drift.append({"zone": zone, "providerSerial": t_serial, "platformSerial": p_serial})
                if serial_drift:
                    entry["soa"] = serial_drift

            drifted = bool(missing_on_tenant) or bool(entry.get("soa"))
            if drifted:
                problems += 1
                if not args.quiet:
                    print(f"{tenant_name} [{name}] {url}: DRIFT — "
                          f"{len(missing_on_tenant)} zone(s) missing on the tenant's Technitium, "
                          f"{len(entry.get('soa', []))} SOA serial mismatch(es)")
                    for zone in missing_on_tenant[:20]:
                        print(f"    - {zone}")
                    for s in entry.get("soa", [])[:20]:
                        print(f"    - {s['zone']}: provider serial {s['providerSerial']} vs platform {s['platformSerial']}")
            elif not args.quiet:
                print(f"{tenant_name} [{name}] {url}: ok ({detail}; Cerulean knows {len(cerulean_zones)} zone(s))")
            report.append(entry)

    if args.json:
        print(json.dumps({"problems": problems, "providers": report}, indent=2))
    if not report and not args.quiet:
        print("tenant-dns-drift: no tenant-registered providers found — nothing to audit")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
