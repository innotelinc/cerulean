#!/usr/bin/env python3
"""Reassign every NPM proxy host to the certificate that actually covers it, then
delete the superseded certificates.

Why coverage comes from Cerulean and not from NPM: NPM's /upload route rewrites a
custom certificate's domain_names to just its CN, so a `*.innotel.us` wildcard is
listed in NPM as `innotel.us` and exact/wildcard matching against NPM metadata
silently finds nothing. Cerulean's own `domains_json` holds the real SAN set, and
`services/npm.ts` compensates the same way (it matches on the stable nice_name).

  /tmp/cert-rebuild.py            dry run — prints the plan
  /tmp/cert-rebuild.py --apply    does it
"""
import json
import sqlite3
import sys
import urllib.error
import urllib.request

NPM = "http://127.0.0.1:81"
APPLY = "--apply" in sys.argv
CERULEAN_ENV = "/usr/src/projects/complete/1-primary/cerulean/.env"
CERULEAN_DB = "/usr/src/projects/complete/1-primary/cerulean/data/cerulean.db"


def env(name):
    with open(CERULEAN_ENV) as fh:
        for line in fh:
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit(f"{name} not in {CERULEAN_ENV}")


def api(method, path, token=None, body=None):
    req = urllib.request.Request(f"{NPM}{path}", method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data, timeout=120) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"{method} {path} -> HTTP {exc.code}: {exc.read().decode()[:300]}")
    return json.loads(raw) if raw.strip() else {}


def labels(name):
    return len(name.split("."))


def covering(domains, host):
    """('exact'|'wildcard', matched-domain) or None."""
    if host in domains:
        return ("exact", host)
    best = None
    for d in domains:
        if not d.startswith("*."):
            continue
        base = d[2:]
        if labels(host) == labels(d) and host.endswith("." + base):
            if best is None or len(base) > len(best[1]):
                best = ("wildcard", d)
    return best


def cerulean_records():
    con = sqlite3.connect(f"file:{CERULEAN_DB}?mode=ro", uri=True)
    out = []
    for cid, domain, wildcard, status, domains_json, expires in con.execute(
            "SELECT id, domain, wildcard, status, domains_json, expires_at FROM certificates"):
        try:
            domains = json.loads(domains_json or "[]")
        except json.JSONDecodeError:
            domains = []
        if domain and domain not in domains:
            domains.append(domain)
        out.append({"cerulean_id": cid, "domain": domain, "wildcard": wildcard,
                    "status": status, "expires": expires, "domains": domains,
                    "nice_name": f"cerulean-{domain}" + ("-wildcard" if wildcard else "")})
    return out


def main():
    token = api("POST", "/api/tokens", body={
        "identity": env("NPM_EMAIL"), "secret": env("NPM_PASSWORD")})["token"]
    certs = api("GET", "/api/nginx/certificates", token)
    hosts = api("GET", "/api/nginx/proxy-hosts", token)
    by_nice = {c.get("nice_name"): c for c in certs}
    by_first = {((c.get("domain_names") or [None])[0]): c for c in certs}

    wanted, unmatched = [], []
    for r in cerulean_records():
        npm = by_nice.get(r["nice_name"]) or by_first.get(r["domain"])
        if npm:
            wanted.append({**r, "npm_id": npm["id"],
                           "npm_expires": npm.get("expires_on"),
                           "npm_nice": npm.get("nice_name")})
        else:
            unmatched.append(r)

    print(f"npm certs: {len(certs)} | hosts: {len(hosts)}")
    print(f"cerulean records: {len(wanted) + len(unmatched)} | matched to an NPM cert: {len(wanted)}")
    for r in unmatched:
        print(f"  ! no NPM cert for cerulean #{r['cerulean_id']} {r['domain']} (status={r['status']})")
    print("\n=== the Cerulean set hosts should end up on ===")
    for w in sorted(wanted, key=lambda w: w["npm_id"]):
        print(f'  npm id={w["npm_id"]:<4} ce#{w["cerulean_id"]:<3} expires={w["npm_expires"][:10]} domains={w["domains"]}')

    keep_ids = {w["npm_id"] for w in wanted}
    best_for, uncovered = {}, []
    for h in hosts:
        host = (h.get("domain_names") or [None])[0]
        if not host:
            continue
        choice = None
        for w in wanted:
            m = covering(w["domains"], host)
            if not m:
                continue
            rank = (0 if m[0] == "exact" else 1, -len(m[1]))
            if choice is None or rank < choice[0]:
                choice = (rank, w["npm_id"], m)
        if choice:
            best_for[h["id"]] = (choice[1], choice[2])
        else:
            uncovered.append((h["id"], host, h.get("certificate_id") or 0))

    moves = []
    for h in hosts:
        if h["id"] not in best_for:
            continue
        new_id, match = best_for[h["id"]]
        if (h.get("certificate_id") or 0) != new_id:
            moves.append((h["id"], (h.get("domain_names") or [None])[0], h.get("certificate_id") or 0,
                          new_id, f"{match[0]}:{match[1]}"))
    print(f"\n=== reassignment: {len(moves)} host(s) ===")
    for hid, host, old, new, why in moves:
        print(f"  host {hid:<5} {host:<44} cert {old} -> {new}  ({why})")

    survivors = {}
    print(f"\n=== no covering Cerulean cert: {len(uncovered)} host(s) ===")
    for hid, host, cid in uncovered:
        c = next((c for c in certs if c["id"] == cid), None)
        will_survive = bool(cid) and cid not in keep_ids
        print(f'  host {hid:<5} {host:<44} cert {cid} nice_name={(c or {}).get("nice_name")!r} '
              f'-> {"kept" if will_survive else "certless"}')
        if will_survive:
            survivors.setdefault(cid, []).append(host)

    deletable = [c for c in certs if c["id"] not in keep_ids and c["id"] not in survivors]
    print(f"\n=== certificates to delete: {len(deletable)} of {len(certs)} ===")
    for c in sorted(deletable, key=lambda c: c["id"]):
        print(f'  id={c["id"]:<4} expires={str(c.get("expires_on"))[:10]} nice_name={c.get("nice_name")!r} domains={c.get("domain_names")}')
    print(f"=== certificates kept for uncovered hosts: {len(survivors)} ===")
    for cid, hs in survivors.items():
        c = next(c for c in certs if c["id"] == cid)
        print(f'  id={cid} nice_name={c.get("nice_name")!r} hosts={hs}')

    if not APPLY:
        print("\nDRY RUN — pass --apply to execute.")
        return

    by_id = {h["id"]: h for h in hosts}
    fi = ("domain_names", "forward_scheme", "forward_host", "forward_port", "access_list_id",
          "certificate_id", "ssl_forced", "caching_enabled", "block_exploits", "advanced_config",
          "meta", "allow_websocket_upgrade", "http2_support", "locations", "hsts_enabled",
          "hsts_subdomains", "trust_forwarded_proto", "enabled")
    done = 0
    for hid, host, old, new, why in moves:
        h = by_id[hid]
        body = {k: h[k] for k in fi if k in h}
        body["certificate_id"] = new
        api("PUT", f"/api/nginx/proxy-hosts/{hid}", token, body)
        done += 1
        if done % 20 == 0:
            print(f"  ...reassigned {done}/{len(moves)}")
    print(f"reassigned {done} host(s)")

    # Certless hosts: only after their referenced cert is gone would NPM keep a
    # dangling reference, so detach first.
    for cid in {cid for _, _, cid in uncovered if cid and cid not in survivors}:
        for h in hosts:
            if (h.get("certificate_id") or 0) == cid:
                body = {k: h[k] for k in fi if k in h}
                body["certificate_id"] = 0
                api("PUT", f"/api/nginx/proxy-hosts/{h['id']}", token, body)
                print(f"  detached cert {cid} from host {h['id']} {(h.get('domain_names') or [''])[0]}")

    for c in deletable:
        api("DELETE", f"/api/nginx/certificates/{c['id']}", token)
        print(f"  deleted cert {c['id']} ({c.get('nice_name')!r})")

    after_certs = api("GET", "/api/nginx/certificates", token)
    after_hosts = api("GET", "/api/nginx/proxy-hosts", token)
    covered = sum(1 for h in after_hosts if h.get("certificate_id"))
    print(f"\nafter: {len(after_certs)} cert(s), {covered}/{len(after_hosts)} hosts with a certificate")


if __name__ == "__main__":
    main()
