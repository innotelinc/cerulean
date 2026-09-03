"""Parse a project's hosts definition file.

Accepted formats (whitespace separated, ``#`` comments ignored):

    <subdomain> <port> [websockets]          # preferred
    <subdomain> <target> <port> [websockets] # legacy (Monarch npm-hosts.conf)

The ``<target>`` column is a legacy container/host name and is ignored — the
forward host the proxy targets always comes from config (``NPM_FORWARD_HOST``
or auto-detected LAN IP). ``websockets`` is any of ``yes|true|1|on``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

WS_TRUE = {"yes", "true", "1", "on"}
_SUBDOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


@dataclass
class HostEntry:
    subdomain: str
    port: int
    websockets: bool = False
    target: str | None = None  # legacy column, informational only


def parse_hosts(text: str) -> list[HostEntry]:
    entries: list[HostEntry] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            raise ValueError(
                f"line {lineno}: expected '<subdomain> [target] <port> [websockets]'"
            )
        sub = parts[0].strip().lower()
        if not _SUBDOMAIN_RE.match(sub):
            raise ValueError(f"line {lineno}: invalid subdomain {sub!r}")
        # Disambiguate formats: a numeric 2nd token means `<sub> <port>`,
        # otherwise `<sub> <target> <port>`.
        if parts[1].isdigit():
            port_raw, ws_raw, target = parts[1], parts[2:], None
        else:
            if len(parts) < 3:
                raise ValueError(
                    f"line {lineno}: expected '<subdomain> <target> <port>'"
                )
            port_raw, ws_raw, target = parts[2], parts[3:], parts[1]
        try:
            port = int(port_raw)
        except ValueError:
            raise ValueError(f"line {lineno}: invalid port {port_raw!r}") from None
        if not 0 < port < 65536:
            raise ValueError(f"line {lineno}: port out of range: {port}")
        websockets = bool(ws_raw) and ws_raw[0].lower() in WS_TRUE
        entries.append(
            HostEntry(subdomain=sub, port=port, websockets=websockets, target=target)
        )
    if not entries:
        raise ValueError("no hosts defined")
    return entries


def parse_hosts_file(path: str) -> list[HostEntry]:
    with open(path, encoding="utf-8") as fh:
        return parse_hosts(fh.read())