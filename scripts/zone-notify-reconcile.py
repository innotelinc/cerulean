#!/usr/bin/env python3
"""zone-notify-reconcile.py — clear the Technitium "notify failed" false alarm.

A Technitium Primary zone can be configured to send DNS NOTIFY to its own name
servers ("Notify Secondary Servers" = *the zone's name servers*). On a deployment
that has **one** DNS server, every NS name in the zone resolves back to that same
server — so the server sends itself a NOTIFY, and, being the primary for the zone,
refuses it:

    DNS Server failed to notify name server 'ns1.innotel.us' (RCODE=Refused) for zone: innotel.us

Technitium retries every five minutes and keeps the zone flagged `notifyFailed`,
which is what shows up as a warning in the console. The NOTIFY cannot ever
succeed: there is no other server to transfer to. The honest configuration is
`notify = None` — the zone has no secondaries to notify.

This tool finds exactly the zones in that state and fixes them. It is *narrow by
construction*: it only looks at zones Technitium already reports as
`notifyFailed`, and it only writes when **every** notify target resolves to an
address the server itself answers on. A zone that fails to notify a genuine
second server is reported and left alone — that is a real problem, not a
false alarm.

    ./scripts/zone-notify-reconcile.py            # report (exit 1 when a fix is pending)
    ./scripts/zone-notify-reconcile.py --apply    # set notify=None on the self-notifying zones
    ./scripts/zone-notify-reconcile.py --preflight # every Primary zone, not just the flagged ones
    ./scripts/zone-notify-reconcile.py --json

`--preflight` is the same judgement read *before* Technitium raises the flag,
for a deploy to gate on: it judges every enabled Primary zone instead of only
the ones already reported `notifyFailed`, so a stack cannot be brought up into a
state whose only possible outcome is a retrying, refusing NOTIFY. It writes
nothing and refuses `--apply`, because the fix for a preflight finding is to
know it — the console and the reconcile run below are what clear it.

Environment (the Cerulean deployment):
    TECHNITIUM_URL       e.g. http://172.17.0.1:5380
    TECHNITIUM_TOKEN     an API token, or
    TECHNITIUM_USER / TECHNITIUM_PASSWORD

Exit codes: 0 nothing to do · 1 a self-notifying zone exists (or was fixed), or —
under `--preflight` — a zone is armed to notify only this server · 2 the check
could not run.

Note: Cerulean is not the only writer here. Nothing in this repo chooses a zone's
notify mode — Technitium's own default for a new Primary zone is the zone's name
servers — so a zone created later (through the console, or by a tenant's own
provider) will be flagged again. This script is the re-converge step for that;
it is not a product change to how zones are created.
"""

from __future__ import annotations

import argparse
import typing
import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15


def cannot_run(message: str) -> "typing.NoReturn":
    """Exit 2 — the documented "could not look".

    `raise SystemExit("...")` exits **1**, the same code as a finding, which
    would make a caller that gates a deploy unable to tell *nothing is wrong*
    from *I could not look*. Every path that cannot answer the question comes
    through here instead, so the three exit codes mean what they say.
    """
    print(f"zone-notify-reconcile: {message}", file=sys.stderr)
    raise SystemExit(2)


# ── Technitium API ───────────────────────────────────────────────────────────

class Technitium:
    def __init__(self, url: str, token: str = "", user: str = "", password: str = ""):
        self.base = url.rstrip("/")
        self.token = token
        self.user = user
        self.password = password
        self._session = ""

    def _token(self) -> str:
        """A bearer token: the configured one, or a login when only user/pass."""
        if self.token:
            return self.token
        if self._session:
            return self._session
        if not (self.user and self.password):
            cannot_run("set TECHNITIUM_TOKEN or TECHNITIUM_USER/TECHNITIUM_PASSWORD")
        qs = urllib.parse.urlencode({"user": self.user, "pass": self.password})
        payload = self.get(f"/api/user/login?{qs}", authenticated=False)
        if payload.get("status") != "ok":
            cannot_run(f"Technitium login failed: {payload.get('errorMessage')}")
        self._session = str(payload.get("token") or "")
        return self._session

    def get(self, path: str, authenticated: bool = True) -> dict:
        headers = {"Accept": "application/json"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self._token()}"
        req = urllib.request.Request(f"{self.base}{path}", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:160]
            cannot_run(f"Technitium {path} → HTTP {exc.code}: {detail}")
        except urllib.error.URLError as exc:
            cannot_run(f"cannot reach Technitium at {self.base}: {exc.reason}")


def addresses_of(name: str) -> set[str]:
    """Every address a name resolves to, or an empty set when it does not."""
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return set()
    return {str(info[4][0]) for info in infos}


def canonical(address: str) -> str:
    """Normalize a literal so 73.68.203.71 and ::ffff:73.68.203.71 compare equal."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def normalise_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def zone_targets(api: Technitium, name: str, mode: str, options: dict,
                 server_domain: str) -> list[str]:
    """Who a zone's NOTIFY would go to, exactly as Technitium chooses them.

    A zone name server equal to the server's own domain is excluded by
    Technitium itself, so it is not a target here either.
    """
    if mode == "ZoneNameServers":
        records = (api.get(f"/api/zones/records/get?domain={urllib.parse.quote(name)}&listZone=true")
                   .get("response") or {}).get("records") or []
        targets: list[str] = []
        for record in records:
            if str(record.get("type", "")).upper() != "NS" or normalise_name(str(record.get("name") or "")) != normalise_name(name):
                continue
            target = normalise_name(str((record.get("rData") or {}).get("nameServer") or ""))
            if target and target != server_domain and target not in targets:
                targets.append(target)
        return targets
    if mode == "SpecifiedNameServers":
        return [normalise_name(t) for t in (options.get("notifyNameServers") or []) if normalise_name(t)]
    return []


def self_only(resolved: dict[str, list[str]], own_addresses: set[str]) -> bool:
    """True when every notify target resolves to *this* server.

    A target that resolves nowhere makes it False on purpose: a name that does
    not resolve is a different, real problem, not a self-notify.
    """
    return bool(resolved) and all(
        addrs and all(canonical(a) in own_addresses for a in addrs)
        for addrs in resolved.values()
    )


# ── the check ────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Clear Technitium zones that only NOTIFY themselves.")
    parser.add_argument("--apply", action="store_true", help="set notify=None on the self-notifying zones")
    parser.add_argument("--preflight", action="store_true",
                        help="judge every enabled Primary zone, not only the flagged ones (writes nothing)")
    parser.add_argument("--json", action="store_true", help="machine-readable report on stdout")
    parser.add_argument("--quiet", action="store_true", help="print only problems (cron-friendly)")
    args = parser.parse_args()
    if args.preflight and args.apply:
        cannot_run("--preflight writes nothing — drop --apply (run the reconcile without "
                   "it to fix a zone)")

    url = (os.environ.get("TECHNITIUM_URL") or "").strip()
    if not url:
        cannot_run("TECHNITIUM_URL is not set")

    api = Technitium(
        url,
        token=(os.environ.get("TECHNITIUM_TOKEN") or "").strip(),
        user=(os.environ.get("TECHNITIUM_USER") or "").strip(),
        password=os.environ.get("TECHNITIUM_PASSWORD") or "",
    )

    settings = api.get("/api/settings/get").get("response") or {}
    server_domain = normalise_name(str(settings.get("dnsServerDomain") or ""))

    # The addresses this server answers on, derived from its own published name
    # (and from how Cerulean reaches it). A notify target that resolves here is
    # this server, whatever the zone's NS records call it.
    own_addresses = {canonical(a) for a in addresses_of(server_domain)} if server_domain else set()
    own_addresses |= {canonical(a) for a in addresses_of(urllib.parse.urlparse(url).hostname or "")}
    own_addresses.discard("")

    zones = (api.get("/api/zones/list?pageNumber=1&zonesPerPage=1000").get("response") or {}).get("zones") or []

    report: list[dict] = []
    pending = 0
    for zone in zones:
        if not isinstance(zone, dict) or zone.get("disabled"):
            continue
        # The reconcile path is deliberately narrow: Technitium has already
        # judged this zone, and only the ones it flagged are in scope. The
        # preflight drops that gate, because its whole point is to read the
        # same state before the flag exists.
        if args.preflight is False and not zone.get("notifyFailed"):
            continue

        name = str(zone.get("name") or "")
        entry: dict = {"zone": name, "type": zone.get("type"),
                       "notifyFailed": bool(zone.get("notifyFailed")),
                       "notifyFailedFor": zone.get("notifyFailedFor") or []}

        if str(zone.get("type")) != "Primary":
            entry["verdict"] = "not-a-primary-zone"
            report.append(entry)
            continue

        options = api.get(f"/api/zones/options/get?zone={urllib.parse.quote(name)}").get("response") or {}
        mode = str(options.get("notify") or "")
        entry["notify"] = mode

        targets = zone_targets(api, name, mode, options, server_domain)
        if not targets:
            # Nothing to notify: Technitium reports the flag from a previous
            # config, and the next update clears it. Not ours to write.
            entry["verdict"] = "no-name-server-target" if not mode else "no-targets"
            report.append(entry)
            continue

        entry["targets"] = targets
        resolved = {target: sorted(addresses_of(target)) for target in targets}
        entry["resolved"] = resolved

        if not self_only(resolved, own_addresses):
            # A real second server is not answering — reported, never written.
            entry["verdict"] = "genuine-failure"
            report.append(entry)
            continue

        entry["verdict"] = "self-notify" if not args.preflight else "armed"
        if args.apply:
            # The undo is emitted before the write, so a failed run still leaves
            # the operator the previous mode.
            entry["undo"] = f"notify={mode}"
            result = api.get(f"/api/zones/options/set?zone={urllib.parse.quote(name)}&notify=None")
            if result.get("status") != "ok":
                entry["verdict"] = "apply-failed"
                entry["error"] = result.get("errorMessage")
            else:
                entry["verdict"] = "fixed"
        pending += 1
        report.append(entry)

    if args.json:
        print(json.dumps({"mode": "preflight" if args.preflight else "reconcile",
                          "pending": pending, "server": server_domain,
                          "serverAddresses": sorted(own_addresses), "zones": report}, indent=2))
    elif args.quiet:
        for entry in report:
            if entry.get("verdict") in ("self-notify", "armed"):
                print(f"{entry['zone']}: notify={entry['notify']} → "
                      f"{', '.join(entry['targets'])}")
    else:
        if pending:
            for entry in report:
                if entry.get("verdict") not in ("self-notify", "armed", "fixed"):
                    continue
                print(f"{entry['zone']}: notify={entry['notify']} targets "
                      f"{', '.join(entry['targets'])}, all this server "
                      f"({', '.join(sorted(own_addresses))}) — every NOTIFY can only be refused")
                if entry.get("verdict") == "fixed":
                    print(f"    fixed: notify=None (undo: {entry['undo']})")
                elif entry.get("verdict") == "armed" and not entry.get("notifyFailed"):
                    print("    not flagged yet — Technitium retries every 5 minutes")
            if args.preflight:
                print(f"\n{pending} zone(s) are armed to notify only this server — set notify=None "
                      "(./scripts/zone-notify-reconcile.py --apply) before bringing the stack up")
            elif not args.apply:
                print(f"\n{pending} zone(s) can only fail to notify — re-run with --apply")
        for entry in report:
            if entry.get("verdict") == "genuine-failure":
                print(f"{entry['zone']}: notify targets {', '.join(entry.get('targets', []))} — "
                      "a second server is not answering; left alone")
        if args.preflight:
            if not pending:
                print(f"zone-notify-reconcile: {len(report)} enabled zone(s) judged on "
                      f"{server_domain} — none is armed to notify only this server")
        elif not report:
            print(f"zone-notify-reconcile: no zone is flagged notifyFailed on {server_domain}")

    return 1 if pending else 0


if __name__ == "__main__":
    sys.exit(main())
