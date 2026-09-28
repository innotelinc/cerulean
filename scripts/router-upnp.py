#!/usr/bin/env python3
"""router-upnp.py — port forwards on the Orbi, from a shell.

Why this exists
---------------
`docs/router.md` says a port forward is a UI-only change: `POST /dniapi/login`
answers lighttpd 400 to every body shape, and the SOAP interface it *will* accept
(DeviceConfig:1#SOAPLogin) has no action for the forwarding table. That is still
true of the firmware's own API — and it is not the whole story. The RBR750P also
runs **MiniUPnPd** on the LAN, and UPnP IGD is a scripted write path the firmware
itself provides: `WANIPConnection:1#AddPortMapping` edits the NAT table with no
login at all.

It is a *different* table, and that is the thing to know before using it. A
mapping added here does **not** appear under Advanced → Port Forwarding, and the
static rules there do not appear here (verified: the estate's own 80/443/53/8089
forwards are absent from `list`, while the client-created ZeroTier and game
mappings are present). So this is not a replacement for the UI — it is the path
for a forwarding change that has to happen *now*, or from a script, and the UI
remains where those rules are made permanent and visible.

Discovery is SSDP on the LAN (the same way a game console finds the router).
`--control-url` skips it when the multicast reply is blocked.

**Run this ON the host that will receive the traffic.** MiniUPnPd here is in
*secure mode*: it only accepts a mapping whose `NewInternalClient` is the
requester's own address, and answers `718 ConflictInMappingEntry` to anything
else. Measured on this estate: from `.46`, `59999/udp -> .46` is accepted while
`59998/udp -> .30` is refused 718; the same call made from `.30` succeeds. So a
forward for Zeus's SIP is added from `.30`, not from the development host —
`ssh root@192.168.1.30 'python3 …/router-upnp.py ensure --profile telephony'`.

A mapping added this way is also not the estate's record of the rule: nothing
in the router config references it and a firmware reboot may not persist it. It
is the fast path; `docs/router.md` §2 stays the source of truth, and the UI
remains where a forward is made permanent.

Usage
-----
    # what the router has (UPnP table only)
    scripts/router-upnp.py list

    # the documented telephony forwards, added if missing (idempotent)
    scripts/router-upnp.py ensure --profile telephony

    # explicit rows; a range is one rule, an internal port may differ
    scripts/router-upnp.py ensure \\
        --map 5061/tcp:192.168.1.30 \\
        --map 5060/udp:192.168.1.30 \\
        --range 10101-10120/udp:192.168.1.30

    # report only: exit 1 if any asked-for row is absent
    scripts/router-upnp.py check --profile telephony

    # undo
    scripts/router-upnp.py remove --profile telephony

Exit codes: 0 done/aligned · 1 drift (with --check) · 2 the router could not be
reached or answered something this script does not understand.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
SERVICE = "urn:schemas-upnp-org:service:WANIPConnection:1"
TIMEOUT = 6

# The estate's telephony forwards that have something listening on the far side
# (`docker port zeus-freepbx`): SIP signalling, SIP over TLS, and the RTP range.
# `docs/router.md` also lists 5062-5080/udp for SIP; nothing is published there,
# so forwarding it would only open ports to a closed door — it is deliberately
# not in this profile.
PROFILE_TELEPHONY = (
    "5060/udp:192.168.1.30",
    "5061/tcp:192.168.1.30",
    "10101-10120/udp:192.168.1.30",
)
DESCRIPTION = "innotel estate (router-upnp.py)"


# ── the mapping spec (pure: unit-tested without a router) ────────────────────
@dataclass(frozen=True)
class Mapping:
    """One PORT[/PROTO]:IP row, expanded to one entry per port.

    A range stays one object because the firmware treats an overlapping pair of
    rules as an error; expanding only at the wire keeps "which rows did I ask
    for" the same question as "which rows does the router have".
    """

    ports: tuple[int, ...]
    proto: str
    internal_ip: str

    def rows(self, description: str = DESCRIPTION) -> list[dict]:
        return [
            {
                "external_port": p,
                "internal_port": p,
                "proto": self.proto,
                "internal_ip": self.internal_ip,
                "description": description,
            }
            for p in self.ports
        ]


class SpecError(ValueError):
    """A mapping spec this script will not act on."""


def parse_spec(text: str) -> Mapping:
    """`5061/tcp:192.168.1.30`, `10101-10120/udp:192.168.1.30`.

    Refuses rather than repairs: a spec that silently becomes a different port is
    a forward nobody asked for.
    """
    portspec, _, ip = text.strip().partition(":")
    if not ip:
        raise SpecError(f"{text!r}: expected PORT[/PROTO]:INTERNAL_IP")
    portpart, _, proto = portspec.partition("/")
    proto = (proto or "tcp").lower()
    if proto not in ("tcp", "udp"):
        raise SpecError(f"{text!r}: protocol must be tcp or udp, not {proto!r}")
    start, dash, end = portpart.partition("-")
    try:
        first = int(start)
        last = int(end) if dash else first
    except ValueError:
        raise SpecError(f"{text!r}: {portpart!r} is not a port or range") from None
    if not (1 <= first <= 65535 and 1 <= last <= 65535) or last < first:
        raise SpecError(f"{text!r}: {portpart!r} is not a usable port range")
    return Mapping(tuple(range(first, last + 1)), proto, ip)


def desired_rows(specs: list[str], description: str = DESCRIPTION) -> list[dict]:
    rows: list[dict] = []
    for spec in specs:
        rows.extend(parse_spec(spec).rows(description))
    return rows


def _key(row: dict) -> tuple[int, str]:
    return (int(row["external_port"]), str(row["proto"]).lower())


def diff(desired: list[dict], present: list[dict]) -> tuple[list[dict], list[dict]]:
    """(to_add, conflicts) — desired rows the router lacks, and taken ports.

    A port already mapped to the *same* internal client is not missing (that is
    the idempotent case). A port mapped to a different client is a conflict, not
    a silent overwrite: replacing somebody else's forward is how a mapping that
    "worked yesterday" disappears.
    """
    have = {_key(r): r for r in present}
    to_add, conflicts = [], []
    for row in desired:
        found = have.get(_key(row))
        if found is None:
            to_add.append(row)
        elif str(found.get("internal_ip")) != row["internal_ip"]:
            conflicts.append({"desired": row, "present": found})
    return to_add, conflicts


# ── the IGD (SSDP + SOAP) ────────────────────────────────────────────────────
def discover(timeout: float = 4.0) -> str:
    """The WANIPConnection control URL, or `""` if SSDP is answered by nothing."""
    probe = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        f"ST: {SSDP_ST}\r\n\r\n"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    try:
        sock.sendto(probe, SSDP_ADDR)
        while True:
            data, _ = sock.recvfrom(8192)
            match = re.search(rb"(?im)^LOCATION:\s*(\S+)", data)
            if match:
                return describe_control_url(match.group(1).decode())
    except socket.timeout:
        return ""
    finally:
        sock.close()


def describe_control_url(location: str) -> str:
    """The WANIPConnection control URL inside one root description."""
    with urllib.request.urlopen(location, timeout=TIMEOUT) as response:
        text = response.read().decode(errors="replace")
    base = re.search(r"<URLBase>(.*?)</URLBase>", text)
    base = base.group(1).strip() if base else ""
    for service in re.findall(r"<service>(.*?)</service>", text, re.S):
        if "WANIPConnection" in service:
            control = re.search(r"<controlURL>(.*?)</controlURL>", service)
            if control:
                path = control.group(1).strip()
                return path if path.startswith("http") else base.rstrip("/") + path
    return ""


def soap(control_url: str, action: str, body: str) -> str:
    """One SOAP call, returning the response body. Raises on a transport error."""
    envelope = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="{SERVICE}">{body}</u:{action}></s:Body>'
        "</s:Envelope>"
    )
    request = urllib.request.Request(
        control_url,
        data=envelope.encode(),
        headers={"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{SERVICE}#{action}"'},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read().decode(errors="replace")


def upnp_error(exc: Exception) -> str:
    """A SOAP fault as `upnp=<code> <description>`, plus the secure-mode hint.

    The code is the whole diagnosis: 718 ConflictInMappingEntry from a mapping
    to another host is this router's secure mode refusing it, not a genuine
    port conflict, and a caller reading only the HTTP status cannot tell the two
    apart.
    """
    if not isinstance(exc, urllib.error.HTTPError):
        return str(exc)
    try:
        body = exc.read().decode(errors="replace")
    except Exception:  # noqa: BLE001 — a fault body is best-effort
        return f"HTTP {exc.code}"
    code = _tag(body, "errorCode")
    desc = _tag(body, "errorDescription") or str(exc.reason)
    detail = f"upnp={code} {desc}" if code else f"HTTP {exc.code} {desc}"
    if code == "718":
        detail += (
            " — this router only accepts a mapping made BY the internal host "
            "(MiniUPnPd secure mode): run this script on the host that receives "
            "the traffic, not from another machine"
        )
    return detail


def _tag(xml: str, name: str) -> str:
    match = re.search(rf"<{name}>(.*?)</{name}>", xml, re.S)
    return match.group(1).strip() if match else ""


def list_mappings(control_url: str, limit: int = 500) -> list[dict]:
    """The router's UPnP mapping table (an index walk; empty at the first gap)."""
    rows: list[dict] = []
    for index in range(limit):
        try:
            body = soap(
                control_url,
                "GetGenericPortMappingEntry",
                f"<NewPortMappingIndex>{index}</NewPortMappingIndex>",
            )
        except urllib.error.HTTPError:
            break  # 500/713 past the end of the table
        if "<NewExternalPort>" not in body:
            break
        rows.append(
            {
                "external_port": int(_tag(body, "NewExternalPort") or 0),
                "internal_port": int(_tag(body, "NewInternalPort") or 0),
                "proto": _tag(body, "NewProtocol").lower(),
                "internal_ip": _tag(body, "NewInternalClient"),
                "description": _tag(body, "NewPortMappingDescription"),
                "lease": int(_tag(body, "NewLeaseDuration") or 0),
            }
        )
    return rows


def add_mapping(control_url: str, row: dict, lease: int = 0) -> None:
    """Add one row. `lease` 0 means permanent, which MiniUPnPd honours."""
    body = (
        "<NewRemoteHost></NewRemoteHost>"
        f"<NewExternalPort>{row['external_port']}</NewExternalPort>"
        f"<NewProtocol>{str(row['proto']).upper()}</NewProtocol>"
        f"<NewInternalPort>{row['internal_port']}</NewInternalPort>"
        f"<NewInternalClient>{row['internal_ip']}</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        f"<NewPortMappingDescription>{row.get('description', DESCRIPTION)}</NewPortMappingDescription>"
        f"<NewLeaseDuration>{lease}</NewLeaseDuration>"
    )
    soap(control_url, "AddPortMapping", body)


def remove_mapping(control_url: str, row: dict) -> None:
    body = (
        "<NewRemoteHost></NewRemoteHost>"
        f"<NewExternalPort>{row['external_port']}</NewExternalPort>"
        f"<NewProtocol>{str(row['proto']).upper()}</NewProtocol>"
    )
    soap(control_url, "DeletePortMapping", body)


# ── CLI ──────────────────────────────────────────────────────────────────────
def _resolve(args) -> str:
    control_url = args.control_url or discover()
    if not control_url:
        print(
            "router-upnp: no UPnP IGD answered SSDP — pass --control-url "
            "(it is printed as LOCATION in an M-SEARCH reply), or add the rule in "
            "Advanced → Advanced Setup → Port Forwarding",
            file=sys.stderr,
        )
    return control_url


def _specs(args) -> list[str]:
    specs = list(args.map or [])
    if args.profile == "telephony":
        specs += list(PROFILE_TELEPHONY)
    if not specs:
        raise SpecError("nothing to do: pass --map/--range, or --profile telephony")
    return specs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Port forwards on the Orbi via UPnP IGD.",
        epilog=(
            "Exit: 0 done/aligned — 1 drift (--check) — 2 the router could not be "
            "reached. NOTE: this table is separate from the UI's Port Forwarding "
            "rules; a mapping added here is invisible there."
        ),
    )
    parser.add_argument("action", choices=["list", "ensure", "check", "remove", "add"])
    parser.add_argument("--map", action="append", metavar="PORT[/PROTO]:IP")
    parser.add_argument("--range", action="append", metavar="START-END/PROTO:IP", dest="map_range")
    parser.add_argument("--profile", choices=["telephony"], help="a named set of rows")
    parser.add_argument("--control-url", help="skip SSDP and use this control URL")
    parser.add_argument(
        "--lease", type=int, default=0, help="seconds; 0 (default) is permanent"
    )
    parser.add_argument(
        "--force", action="store_true", help="repoint a port another client holds"
    )
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    args.map = (args.map or []) + (args.map_range or [])  # one list to expand

    # `list` is the one action that needs no mapping at all, so it is answered
    # before the spec is expanded (a bare `list` is not a missing argument).
    if args.action == "list" and not (args.map or args.profile):
        control_url = _resolve(args)
        if not control_url:
            return 2
        rows = list_mappings(control_url)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print(f"{'ext':>7} {'proto':<4} {'int':>7}  {'internal client':<16} lease  description")
            for row in rows:
                print(
                    f"{row['external_port']:>7} {row['proto']:<4} {row['internal_port']:>7}  "
                    f"{row['internal_ip']:<16} {row['lease']:>5}  {row['description']}"
                )
            if not rows:
                print("(no UPnP mappings)")
        return 0

    try:
        specs = _specs(args)
        desired = desired_rows(specs)
    except SpecError as exc:
        print(f"router-upnp: {exc}", file=sys.stderr)
        return 2

    control_url = _resolve(args)
    if not control_url:
        return 2
    present = list_mappings(control_url)
    to_add, conflicts = diff(desired, present)

    if args.action == "check":
        for row in to_add:
            print(
                f"  missing  {row['external_port']}/{row['proto']} -> {row['internal_ip']}",
                file=sys.stderr,
            )
        for pair in conflicts:
            print(
                f"  conflict {pair['desired']['external_port']}/{pair['desired']['proto']} "
                f"held by {pair['present']['internal_ip']}, want "
                f"{pair['desired']['internal_ip']}",
                file=sys.stderr,
            )
        if to_add or conflicts:
            print(
                f"router-upnp: {len(desired) - len(to_add) - len(conflicts)} aligned, "
                f"{len(to_add)} missing, {len(conflicts)} conflicting",
                file=sys.stderr,
            )
            return 1
        if not args.quiet:
            print(f"router-upnp: all {len(desired)} forwarded")
        return 0

    if args.action == "remove":
        removed = 0
        wanted = {_key(row) for row in desired}
        for row in present:
            if _key(row) in wanted:
                remove_mapping(control_url, row)
                removed += 1
        print(f"router-upnp: removed {removed} mapping(s)")
        return 0

    if conflicts and not args.force:
        for pair in conflicts:
            print(
                f"router-upnp: refusing — {pair['desired']['external_port']}/"
                f"{pair['desired']['proto']} is already mapped to "
                f"{pair['present']['internal_ip']} (--force repoints it)",
                file=sys.stderr,
            )
        return 2
    for pair in conflicts:
        remove_mapping(control_url, pair["present"])
        to_add.append(pair["desired"])

    failures = 0
    for row in to_add:
        try:
            add_mapping(control_url, row, args.lease)
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            print(
                f"router-upnp: {row['external_port']}/{row['proto']} was refused: "
                f"{upnp_error(exc)}",
                file=sys.stderr,
            )
            failures += 1
    print(
        f"router-upnp: {len(to_add) - failures} added, "
        f"{len(desired) - len(to_add)} already present, {failures} refused"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
