#!/usr/bin/env python3
"""Parse BIND master zone files into normalized records for Technitium import.

Usage: python3 bind-migrate.py <zone-file> [<zone-file> ...]
Writes one JSON file per zone into /tmp/bind-migration/parsed/<zone>.json
Each record: {name (FQDN), type, ttl, data (rdata string)}
"""
import json
import pathlib
import re
import sys

OUT_DIR = pathlib.Path("/tmp/bind-migration/parsed")

CLASSES = ("IN", "CH", "HS")
KNOWN_TYPES = {
    "A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA", "PTR", "DNAME",
    "SOA", "SSHFP", "TLSA", "DNSKEY", "DS", "NAPTR", "LOC", "ALIAS",
    "ANAME", "SVCB", "HTTPS", "HINFO", "RP", "AFSDB", "SIG", "NXT",
}  # NOTE: "KEY" deliberately excluded — collides with the common hostname "key"


def strip_comments_and_parens(text_lines):
    """Join continuation lines inside parentheses, stripping comments."""
    out, buf, depth = [], "", 0
    for raw in text_lines:
        if depth == 0 and ";" in raw:
            quote = False
            cut = len(raw)
            for idx, ch in enumerate(raw):
                if ch == '"':
                    quote = not quote
                elif ch == ";" and not quote:
                    cut = idx
                    break
            raw = raw[:cut]
        depth += raw.count("(") - raw.count(")")
        buf += " " + raw
        if depth <= 0:
            out.append(buf.strip())
            buf, depth = "", 0
    if buf.strip():
        out.append(buf.strip())
    return [l for l in out if l]


def tokenize(line: str):
    """Split a zone-file line respecting quoted strings."""
    tokens, cur, in_quote = [], "", False
    for ch in line:
        if in_quote:
            cur += ch
            if ch == '"':
                in_quote = False
        elif ch == '"':
            in_quote = True
            cur += ch
        elif ch in " \t":
            if cur:
                tokens.append(cur)
                cur = ""
        else:
            cur += ch
    if cur:
        tokens.append(cur)
    return tokens


def parse_zone(path: pathlib.Path):
    zone_name = path.name.replace(".zone", "")
    origin = zone_name + "."
    default_ttl = 3600
    records = []
    soa = None
    prev_fqdn = None

    for line in strip_comments_and_parens(path.read_text().splitlines()):
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("$origin"):
            origin = line.split()[1]
            continue
        if line.lower().startswith("$ttl"):
            default_ttl = int(line.split()[1].rstrip("SMHDWsmhdw") or line.split()[1])
            continue
        if line.startswith("$"):
            print(f"  ! skipping unsupported directive: {line[:60]}", file=sys.stderr)
            continue

        toks = tokenize(line)
        if not toks:
            continue

        # ── determine owner name ──────────────────────────────────────────
        first_is_class = toks[0].upper() in CLASSES
        first_is_type = toks[0].upper() in KNOWN_TYPES
        if first_is_class or first_is_type:
            # inherited owner name (line began with whitespace in the file)
            fqdn = prev_fqdn or origin.rstrip(".")
            idx = 0
        else:
            name = toks[0]
            idx = 1
            if name == "@":
                fqdn = origin.rstrip(".")
            elif not name.endswith("."):
                fqdn = f"{name}.{origin.rstrip('.')}" if origin != "." else name
            else:
                fqdn = name.rstrip(".")

        # ── scan [ttl] [class] type ───────────────────────────────────────
        ttl = default_ttl
        rtype = None
        while idx < len(toks):
            t = toks[idx]
            if re.match(r"^\d+[SMHDW]?$", t, re.I):
                ttl = int(re.match(r"^(\d+)[SMHDW]?$", t, re.I).group(1))
                idx += 1
                continue
            if t.upper() in CLASSES:
                idx += 1
                continue
            if t.upper() in KNOWN_TYPES:
                rtype = t.upper()
                idx += 1
            break
        if rtype is None:
            continue

        rdata = " ".join(toks[idx:]).strip()
        if not rdata:
            continue

        # ── qualify rdata domains ─────────────────────────────────────────
        o = origin.rstrip(".")

        def qual(host: str) -> str:
            if host in ("@", "."):
                return o
            if not host.endswith(".") and not re.match(r"^\d+(\.\d+){3}$", host):
                return f"{host}.{o}" if o != "." else host
            return host.rstrip(".")

        if rtype in ("CNAME", "NS", "PTR", "DNAME"):
            rdata = qual(rdata.split()[0])
        elif rtype == "MX" and len(rdata.split()) >= 2:
            parts = rdata.split()
            rdata = f"{parts[0]} {qual(parts[1])}"
        elif rtype == "SRV" and len(rdata.split()) >= 4:
            parts = rdata.split()
            rdata = f"{parts[0]} {parts[1]} {parts[2]} {qual(parts[3])}"
        elif rtype in ("TXT", "SPF"):
            # normalize: strip quotes for transport; re-add on import
            rdata = rdata.strip()
            if rdata.startswith('"') and rdata.endswith('"'):
                rdata = rdata[1:-1]
        elif rtype == "CAA":
            # flags tag "value" -> keep as-is minus quotes on value
            parts = rdata.split(None, 2)
            if len(parts) == 3:
                val = parts[2].strip().strip('"')
                rdata = f"{parts[0]} {parts[1]} {val}"

        fqdn = fqdn.rstrip(".")
        prev_fqdn = fqdn

        rec = {"name": fqdn, "type": rtype, "ttl": ttl, "data": rdata}
        if rtype == "SOA":
            soa = rec
            continue
        records.append(rec)

    return zone_name, soa, records


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for arg in sys.argv[1:]:
        p = pathlib.Path(arg)
        zone, soa, recs = parse_zone(p)
        payload = {"zone": zone, "soa": soa, "records": recs}
        out = OUT_DIR / f"{zone}.json"
        out.write_text(json.dumps(payload, indent=1))
        types = {}
        for r in recs:
            types[r["type"]] = types.get(r["type"], 0) + 1
        summary = " ".join(f"{k}:{v}" for k, v in sorted(types.items()))
        print(f"{zone}: {len(recs)} records [{summary}] SOA={'yes' if soa else 'NO'} -> {out}")


if __name__ == "__main__":
    main()
