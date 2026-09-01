#!/usr/bin/env python3
"""npm-proxy-hosts.py — provision nginx proxy manager proxy hosts for Cerulean.

Idempotent: every proxy host in PROXY_HOSTS below is created when missing and
updated when it drifts. Safe to run on a fresh host and on every re-run.

Reads .env (repo root) when run standalone, or the environment when run from
setup.sh.

Required (in .env):
    NPM_API_URL, NPM_EMAIL, NPM_PASSWORD

Optional:
    NPM_FORWARD_HOST   upstream IP nginx proxy manager forwards to. Defaults to
                       this host's detected LAN IP (must be reachable from NPM).
    NPM_BASE_DOMAIN    base domain subdomains are built under. Defaults to
                       CERULEAN_ZONE (innotel.us).
    NPM_PROXY_SSL      1 = let NPM request its own Let's Encrypt cert (HTTP-01,
                       requires ports 80/443 to reach NPM). Default 0 = create
                       hosts without SSL; attach a Cerulean-issued certificate
                       from the portal once issued.
"""

import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request


# ── The complete proxy host map ─────────────────────────────────────────────
# Every service that should be reachable through nginx proxy manager, one
# subdomain each. `name` is the subdomain under NPM_BASE_DOMAIN, `port` is the
# upstream port nginx proxy manager forwards to, `scheme` the upstream scheme.
#
#   subdomain          upstream                 port   purpose
#   ─────────────────  ───────────────────────  ─────  ─────────────────────────
#   cerulean.<base>    http://<forward_host>    3000   Cerulean dashboard + API
#
# acme-dns is deliberately NOT in this list: its port 53 (UDP/TCP) must stay
# directly reachable from the internet for Let's Encrypt validation, and its
# API port 4443 is internal-only. NPM proxies HTTP(S) — it cannot (and must
# not) sit in front of either. Add new services here (one dict per proxy).
PROXY_HOSTS = [
    {
        "name": "cerulean",
        "port": 3000,
        "scheme": "http",
        "websocket": True,
        "purpose": "Cerulean dashboard + REST API",
    },
]


# ── .env + environment helpers ──────────────────────────────────────────────
def env(key, default=""):
    return os.environ.get(key, default)


def load_env_file(path):
    """Load KEY=VALUE lines from a .env file into os.environ (no override)."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("\"'")
            if key and key not in os.environ:
                os.environ[key] = value


def detect_lan_ip():
    """Best-effort: this host's primary LAN IPv4 (reachable from NPM)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))  # picks the default route, sends nothing
        return sock.getsockname()[0]
    except OSError:
        pass
    finally:
        sock.close()
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, stderr=subprocess.DEVNULL)
        for ip in out.split():
            if ip and not ip.startswith("127."):
                return ip.split("%")[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


# ── nginx proxy manager client ──────────────────────────────────────────────
class Npm:
    def __init__(self, api_url, email, password):
        self.api_url = api_url.rstrip("/")
        self.email = email
        self.password = password
        self.token = None

    def _request(self, method, path, body=None):
        if self.token is None:
            self._login()
        url = f"{self.api_url}/api{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace") if err.fp else ""
            raise RuntimeError(f"NPM {method} {path} failed (HTTP {err.code}): {detail}") from err

    def _login(self):
        body = json.dumps({"identity": self.email, "secret": self.password}).encode()
        req = urllib.request.Request(f"{self.api_url}/api/tokens", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace") if err.fp else ""
            raise RuntimeError(
                f"NPM token request failed (HTTP {err.code}): {detail} — "
                "check NPM_EMAIL/NPM_PASSWORD in .env"
            ) from err
        self.token = data.get("token")
        if not self.token:
            raise RuntimeError("NPM returned no token — check credentials")

    def list_hosts(self):
        return self._request("GET", "/nginx/proxy-hosts") or []

    def create_host(self, payload):
        return self._request("POST", "/nginx/proxy-hosts", payload)

    def update_host(self, host_id, payload):
        return self._request("PUT", f"/nginx/proxy-hosts/{host_id}", payload)


def host_payload(entry, base_domain, forward_host, ssl_via_npm, letsencrypt_email):
    domain = f"{entry['name']}.{base_domain}"
    payload = {
        "domain_names": [domain],
        "forward_scheme": entry.get("scheme", "http"),
        "forward_host": forward_host,
        "forward_port": int(entry["port"]),
        "certificate_id": "new" if ssl_via_npm else 0,
        "ssl_forced": bool(ssl_via_npm),
        "http2_support": True,
        "block_exploits": True,
        "caching_enabled": False,
        "allow_websocket_upgrade": bool(entry.get("websocket", True)),
        "access_list_id": 0,
        "advanced_config": "",
        "meta": {"letsencrypt_agree": False, "dns_challenge": False},
    }
    if ssl_via_npm:
        payload["meta"] = {
            "letsencrypt_agree": True,
            "dns_challenge": False,
            "letsencrypt_email": letsencrypt_email,
            "letsencrypt_force": True,
            "hsts": False,
            "hsts_subdomains": False,
        }
    return payload, domain


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(here, "..", ".env"), ".env"):
        load_env_file(path)

    api_url = env("NPM_API_URL")
    email = env("NPM_EMAIL")
    password = env("NPM_PASSWORD")
    if not (api_url and email and password):
        print("NPM not configured (set NPM_API_URL, NPM_EMAIL, NPM_PASSWORD in .env) — skipping.", file=sys.stderr)
        return 2
    if password == "change-me":
        print("NPM_PASSWORD is still the 'change-me' placeholder — skipping.", file=sys.stderr)
        return 2

    base_domain = env("NPM_BASE_DOMAIN", env("CERULEAN_ZONE", "innotel.us")).rstrip(".")
    forward_host = env("NPM_FORWARD_HOST")
    if not forward_host:
        forward_host = detect_lan_ip()
    if not forward_host:
        print(
            "Could not determine the upstream host NPM should forward to — "
            "set NPM_FORWARD_HOST in .env (the portal host's LAN IP).",
            file=sys.stderr,
        )
        return 2

    ssl_via_npm = env("NPM_PROXY_SSL", "0").lower() in ("1", "true", "yes")
    letsencrypt_email = env("ACME_EMAIL", email)

    npm = Npm(api_url, email, password)
    existing = npm.list_hosts()

    print(f"nginx proxy manager: {api_url}")
    print(f"Base domain: {base_domain}   Forward host: {forward_host}")
    print("Proxy hosts:")

    for entry in PROXY_HOSTS:
        payload, domain = host_payload(entry, base_domain, forward_host, ssl_via_npm, letsencrypt_email)
        found = next(
            (h for h in existing if domain in (h.get("domain_names") or [])),
            None,
        )
        if found is None:
            npm.create_host(payload)
            print(f"  ✓ created  {domain} → {payload['forward_scheme']}://{forward_host}:{payload['forward_port']}")
        else:
            # Preserve any certificate already attached (e.g. a Cerulean export),
            # so an update never silently drops SSL.
            if found.get("certificate_id"):
                payload["certificate_id"] = found["certificate_id"]
                payload["ssl_forced"] = found.get("ssl_forced", True)
                payload["meta"] = found.get("meta", {})
            npm.update_host(found["id"], payload)
            print(f"  ✓ updated  {domain} → {payload['forward_scheme']}://{forward_host}:{payload['forward_port']}")

    print("Done. When a certificate is issued for a host's domain, Cerulean")
    print("imports it into NPM and attaches it to the matching proxy host automatically.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
