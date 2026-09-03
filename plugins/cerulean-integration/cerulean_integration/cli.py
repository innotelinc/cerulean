#!/usr/bin/env python3
"""cerulean-integration — provision NPM hosts, BIND A records, and a
Cerulean-issued wildcard certificate for a project's subdomains.

Usage:
    cerulean-integration --hosts hosts.conf [--base-domain innotel.us] \
        [--forward-host 192.168.1.46] [--dry-run] [--skip-certs]

Configuration (env vars, or a repo .env):
    CERULEAN_API_URL        e.g. http://localhost:3003 (default)
    CERULEAN_ADMIN_PASSWORD Cerulean local-admin password (required)
    CERULEAN_BASE_DOMAIN    hostname suffix for subdomains + cert domain
                            (default innotel.us)
    CERULEAN_ZONE           BIND zone hosting the A records (optional —
                            resolved automatically when unset)
    NPM_FORWARD_HOST        upstream IP/host NPM forwards to (default:
                            auto-detected LAN IP)
    CERULEAN_RENEW_DAYS     reuse cert while valid > N days (default 30)
"""

from __future__ import annotations

import argparse
import sys

from .api import CeruleanClient
from .config import load_config
from .hosts import parse_hosts_file


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cerulean-integration",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--hosts", dest="hosts_file", help="hosts file (subdomain -> port)")
    p.add_argument("--base-domain", dest="base_domain", help="base domain / hostname suffix")
    p.add_argument("--forward-host", dest="forward_host", help="upstream IP NPM forwards to")
    p.add_argument("--api-url", dest="api_url", help="Cerulean API base URL")
    p.add_argument("--dotenv", dest="dotenv_path", help="path to .env (default: cwd/.env)")
    p.add_argument("--dry-run", action="store_true", help="print the plan, change nothing")
    p.add_argument("--skip-certs", action="store_true", help="do not issue/attach a certificate")
    p.add_argument("--skip-dns", action="store_true", help="do not write DNS A records")
    p.add_argument("--skip-hosts", action="store_true", help="do not create/update NPM hosts")
    p.add_argument("--renew-days", type=int, dest="renew_days", help="reuse cert while valid > N days")
    return p


def relative_name(full: str, zone: str) -> str:
    """Record name of `full` relative to `zone` ("@" at the apex)."""
    z = zone.strip().lower().rstrip(".")
    f = full.strip().rstrip(".")
    if f.lower() == z:
        return "@"
    if f.lower().endswith("." + z):
        return f[: -(len(z) + 1)]
    return f


def run(cfg) -> int:
    for warning in cfg.warnings:
        print(f"note: {warning}")
    if not cfg.password:
        print("error: CERULEAN_ADMIN_PASSWORD is not set", file=sys.stderr)
        return 2
    if not cfg.hosts_file:
        print(
            "error: --hosts FILE is required (or set CERULEAN_HOSTS_FILE)",
            file=sys.stderr,
        )
        return 2
    if not cfg.forward_host:
        print(
            "error: could not determine the forward host — set NPM_FORWARD_HOST",
            file=sys.stderr,
        )
        return 2

    try:
        entries = parse_hosts_file(cfg.hosts_file)
    except (OSError, ValueError) as err:
        print(f"error: {cfg.hosts_file}: {err}", file=sys.stderr)
        return 2

    client = CeruleanClient(
        cfg.api_url, cfg.password, timeout=cfg.timeout, dry_run=cfg.dry_run
    )
    try:
        client.login()
    except Exception as err:  # CeruleanError
        print(f"error: {err}", file=sys.stderr)
        return 1
    print(
        f"connected to Cerulean at {cfg.api_url} "
        f"{'(dry-run — no changes will be made)' if cfg.dry_run else ''}"
    )

    base = cfg.base_domain.strip().lower().rstrip(".")
    try:
        zone = client.resolve_zone(base, cfg.zone)
    except Exception as err:
        print(f"error: resolve zone for {base}: {err}", file=sys.stderr)
        return 1
    print(f"base domain: {base} (zone: {zone})")

    zone_domain: dict | None = None
    if not (cfg.skip_dns and cfg.skip_hosts):
        try:
            zone_domain = client.ensure_domain(zone)
        except Exception as err:
            print(f"error: ensure zone {zone}: {err}", file=sys.stderr)
            return 1
        print(f"zone: {zone} (Cerulean domain id {zone_domain.get('id')})")

    # 1. DNS A records (BIND via Cerulean's DNS API)
    if not cfg.skip_dns:
        if zone_domain is None:
            print("error: --skip-dns requires the zone domain (remove --skip-hosts)", file=sys.stderr)
            return 2
        if zone_domain.get("id") is None:
            print(
                f"[dns] zone {zone} not registered yet — would register and add "
                f"A records for {len(entries)} host(s) (dry-run)"
            )
        else:
            for entry in entries:
                full = f"{entry.subdomain}.{base}"
                rel = relative_name(full, zone)
                try:
                    action = client.upsert_a_record(
                        zone_domain["id"], rel, full, cfg.forward_host
                    )
                except Exception as err:
                    print(f"[dns] A {full} -> {cfg.forward_host}: ERROR {err}", file=sys.stderr)
                    return 1
                print(f"[dns] A {full} -> {cfg.forward_host}: {action}")
    else:
        print("[dns] skipped")

    # 2. NPM proxy hosts (via Cerulean's NPM integration)
    if not cfg.skip_hosts:
        for entry in entries:
            full = f"{entry.subdomain}.{base}"
            try:
                action = client.upsert_npm_host(
                    full,
                    cfg.forward_host,
                    entry.port,
                    "http",
                    websocket_support=entry.websockets,
                    ssl_forced=not cfg.skip_certs,
                )
            except Exception as err:
                print(f"[npm] {full}: ERROR {err}", file=sys.stderr)
                return 1
            print(
                f"[npm] {full} -> {cfg.forward_host}:{entry.port}"
                f"{' (websockets)' if entry.websockets else ''}: {action}"
            )
    else:
        print("[npm] skipped")

    # 3. Wildcard certificate (issued by Cerulean via DNS-01; Cerulean
    #    auto-attaches it to every matching NPM host)
    if not cfg.skip_certs:
        try:
            cert, action = client.ensure_wildcard_cert(
                base, renew_days=cfg.renew_days, timeout=cfg.cert_timeout
            )
        except Exception as err:
            print(f"[cert] wildcard *.{base}: ERROR {err}", file=sys.stderr)
            return 1
        print(
            f"[cert] wildcard *.{base}: {action}"
            + (f" (expires {cert.get('expiresAt')})" if cert.get("expiresAt") else "")
        )
    else:
        print("[cert] skipped (hosts created without SSL)")

    if cfg.dry_run and client.planned:
        print("\nplanned changes:")
        for item in client.planned:
            print(f"  - {item}")
    print("done")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    overrides = {k: v for k, v in vars(args).items() if v is not None and k != "dotenv_path"}
    cfg = load_config(args.dotenv_path, overrides)
    try:
        return run(cfg)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())