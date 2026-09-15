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
    TECHNITIUM_URL / NPM_HOST_IP  when set, A records for the subdomains are
                       created via Technitium HTTP API (/api/zones/records/add)
                       so the proxy hosts actually resolve.
"""

import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
import urllib.parse


# ── The complete proxy host map ─────────────────────────────────────────────
#
# `forward_auth: False` opts a host out of the Authentik forward-auth gate.
# Only `secrets` (the Vault UI) keeps a LOCAL credential of its own and is
# gated; everything else is the Cerulean app or its API, which already signs in
# through Authentik (`auth` IS Authentik — gating it would lock the zone out)
# and is called programmatically by other hosts. Same pattern as
# 2-voice/capstone.
PROXY_HOSTS = [
    {
        "name": "cerulean",
        "port": 3003,
        "scheme": "http",
        "websocket": True,
        "purpose": "Cerulean dashboard + REST API",
        "forward_auth": False,
    },
    {
        "name": "app",
        "port": 3003,
        "scheme": "http",
        "websocket": True,
        "purpose": "Cerulean application",
        "forward_auth": False,
    },
    {
        "name": "api",
        "port": 3003,
        "scheme": "http",
        "websocket": False,
        "purpose": "Cerulean REST API",
        "forward_auth": False,
    },
    {
        "name": "auth",
        "port": 9000,
        "scheme": "http",
        "websocket": True,
        "purpose": "Authentik — SSO and user management",
        "forward_auth": False,
    },
    {
        "name": "secrets",
        "port": 8200,
        "scheme": "http",
        "websocket": False,
        "purpose": "HashiCorp Vault — secrets management (KV v2)",
    },
    {
        "name": "dns",
        "port": 3003,
        "scheme": "http",
        "websocket": True,
        "purpose": "DNS management",
        "forward_auth": False,
    },
    {
        "name": "certs",
        "port": 3003,
        "scheme": "http",
        "websocket": True,
        "purpose": "Certificate management",
        "forward_auth": False,
    },
    {
        "name": "admin",
        "port": 3003,
        "scheme": "http",
        "websocket": True,
        "purpose": "Administration",
        "forward_auth": False,
    },
]


# ── Cerulean Authentik forward auth ─────────────────────────────────────
# Injected as a proxy host's nginx "advanced config": an auth_request against
# the Authentik embedded outpost. The outpost runs the domain-level proxy
# provider (`cerulean-zone-npm-forward-auth`), so ONE provider covers the whole
# zone — the outpost matches the request by X-Forwarded-Host.
#
# NOTE: braces are doubled for .format() — only {outpost_url} is a field.
FORWARD_AUTH_SNIPPET = """\
# ── Cerulean Authentik forward auth (managed by npm-proxy-hosts.py) ──
# Increase buffer size for large headers (SSO redirects are big).
proxy_buffers 8 16k;
proxy_buffer_size 32k;
auth_request /outpost.goauthentik.io/auth/nginx;
error_page 401 = @goauthentik_proxy_signin;
auth_request_set $auth_cookie $upstream_http_set_cookie;
add_header Set-Cookie $auth_cookie;
auth_request_set $authentik_username $upstream_http_x_authentik_username;
auth_request_set $authentik_groups $upstream_http_x_authentik_groups;
auth_request_set $authentik_email $upstream_http_x_authentik_email;
auth_request_set $authentik_name $upstream_http_x_authentik_name;
auth_request_set $authentik_uid $upstream_http_x_authentik_uid;
proxy_set_header X-authentik-username $authentik_username;
proxy_set_header X-authentik-groups $authentik_groups;
proxy_set_header X-authentik-email $authentik_email;
proxy_set_header X-authentik-name $authentik_name;
proxy_set_header X-authentik-uid $authentik_uid;
location /outpost.goauthentik.io {{
    proxy_pass {outpost_url}/outpost.goauthentik.io;
    proxy_set_header Host $host;
    proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
    # The outpost runs the forward-auth provider in `forward_domain` mode and
    # identifies which app a request belongs to from the forwarded host. These
    # live in NPM's generated `location /`, which a custom location does NOT
    # inherit — without them the embedded outpost logs "failed to detect a
    # forward URL from nginx" and 401s/500s the auth subrequest.
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    add_header Set-Cookie $auth_cookie;
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}}
location @goauthentik_proxy_signin {{
    internal;
    add_header Set-Cookie $auth_cookie;
    return 302 {signin_url}/outpost.goauthentik.io/start?rd=$scheme://$http_host$request_uri;
}}
"""


def forward_auth_snippet(outpost_url, signin_url):
    """Render the auth_request nginx snippet for one proxy host.

    outpost_url is server-side only (NPM → Authentik over the LAN, direct —
    never through NPM's own vhosts); signin_url is what the BROWSER is
    redirected to on 401, so it must be the public auth domain.
    """
    return FORWARD_AUTH_SNIPPET.format(outpost_url=outpost_url.rstrip("/"),
                                       signin_url=signin_url.rstrip("/"))


def build_outpost_url(upstream_host):
    """URL of the Authentik embedded outpost as NPM reaches it.

    NPM must hit the outpost DIRECTLY (http://<upstream>:9000) — routing it
    through https://auth.<domain> would re-enter NPM's own vhost selection
    with the app's Host header and loop the request back to the app vhost.
    """
    return f"http://{upstream_host}:9000"


def resolve_forward_auth(base_domain, upstream):
    """Resolve forward auth from the environment: (enabled, outpost, signin, excluded)."""
    enabled = env("NPM_FORWARD_AUTH", "").strip().lower() not in {"0", "false", "no", "off"}
    excluded = {s.strip() for s in env("NPM_FORWARD_AUTH_EXCLUDE", "").split(",") if s.strip()}
    if "all" in excluded:
        enabled = False
    outpost = build_outpost_url(upstream)
    signin_url = (env("NPM_AUTHENTIK_URL", "") or "").strip().rstrip("/")
    if not signin_url and base_domain:
        signin_url = f"https://auth.{base_domain}"
    return enabled, outpost, signin_url or outpost, excluded


def snippet_for_host(entry, enabled, outpost_url, signin_url, excluded):
    """The auth snippet this host should carry ('' = no forward auth)."""
    if not enabled or entry.get("forward_auth") is False:
        return ""
    if entry["name"] in excluded:
        return ""
    return forward_auth_snippet(outpost_url, signin_url)


# ── .env + environment helpers ──────────────────────────────────────────────
def env(key, default=""):
    return os.environ.get(key, default)


def load_env_file(path):
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
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


# ── Technitium A-record provisioning ────────────────────────────────────────
def _technitium_token(technitium_url):
    token = env("TECHNITIUM_TOKEN") or env("TECHNITIUM_API_TOKEN")
    if token:
        return token.strip()
    user = env("TECHNITIUM_USER") or env("TECHNITIUM_ADMIN_USER") or "admin"
    pw = env("TECHNITIUM_PASSWORD") or env("TECHNITIUM_ADMIN_PASSWORD") or ""
    if not pw:
        return None
    qs = urllib.parse.urlencode({"user": user, "pass": pw})
    url = f"{technitium_url.rstrip('/')}/api/user/login?{qs}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "ok":
                return data.get("token")
    except Exception:
        pass
    return None


def ensure_a_record_technitium(domain, ip, zone, technitium_url):
    """Create/ensure an A record via Technitium HTTP API. Returns bool."""
    tok = _technitium_token(technitium_url)
    if not tok:
        return False
    # Ensure zone exists
    params = urllib.parse.urlencode({"zone": zone, "type": "Primary"})
    try:
        req = urllib.request.Request(f"{technitium_url.rstrip('/')}/api/zones/create?{params}")
        req.add_header("Authorization", f"Bearer {tok}")
        urllib.request.urlopen(req, timeout=10).read()
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace") if e.fp else ""
        if "already exists" not in body.lower() and e.code not in (409, 400):
            pass  # continue to record add; zone may already exist
    except Exception:
        pass
    # Add / ensure A record (idempotent: duplicate add is tolerated by Technitium or we treat as ok)
    params = urllib.parse.urlencode({"domain": domain, "zone": zone, "type": "A", "ttl": "300", "ipAddress": ip})
    try:
        req = urllib.request.Request(f"{technitium_url.rstrip('/')}/api/zones/records/add?{params}")
        req.add_header("Authorization", f"Bearer {tok}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get("status") in ("ok", None)  # some versions return ok, some no status on success
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace") if e.fp else ""
        if "already exists" in body.lower() or "duplicate" in body.lower():
            return True
        return False
    except Exception:
        return False


def host_payload(entry, base_domain, forward_host, ssl_via_npm, letsencrypt_email,
                 auth_snippet=""):
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
        "advanced_config": auth_snippet,
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
    env_paths = (os.path.join(here, "..", ".env"), ".env")

    # Guard against a stale ambient NPM_* environment. load_env_file() only
    # fills keys that are unset, so a leftover NPM_BASE_DOMAIN exported by
    # another stack wins over this repo's .env and this script would create
    # proxy hosts in a domain it does not own. Refuse instead of writing.
    ambient_domain = (os.environ.get("NPM_BASE_DOMAIN") or "").strip().strip(".").lower()
    file_domain = ""
    for path in env_paths:
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                key, _, value = raw.strip().partition("=")
                if key.strip() == "NPM_BASE_DOMAIN":
                    file_domain = value.strip().strip("\"'").strip(".").lower()
                    break
        if file_domain:
            break
    if ambient_domain and file_domain and ambient_domain != file_domain:
        print(f"FAIL NPM_BASE_DOMAIN={ambient_domain} is exported in the environment but this "
              f"repo's .env says {file_domain} — refusing to touch {ambient_domain} hosts "
              f"(unset NPM_BASE_DOMAIN so .env decides).", file=sys.stderr)
        return 1

    for path in env_paths:
        load_env_file(path)

    npm_mode = env("NPM_MODE", "remote").lower()
    api_url = (
        env("NPM_API_URL")
        if npm_mode == "remote"
        else env("NPM_LOCAL_API_URL", f"http://localhost:{env('NPM_ADMIN_PORT', '81')}")
    )
    email = env("NPM_EMAIL")
    password = env("NPM_PASSWORD")
    if not (api_url and email and password):
        print("NPM not configured (set NPM_MODE, NPM_API_URL, NPM_EMAIL, NPM_PASSWORD in .env) — skipping.", file=sys.stderr)
        return 2
    if password == "change-me":
        print("NPM_PASSWORD is still the 'change-me' placeholder — skipping.", file=sys.stderr)
        return 2

    base_domain = env("NPM_BASE_DOMAIN", env("CERULEAN_ZONE", "innotel.us")).rstrip(".")
    # When using default wildcard, prefer serverId lab domain
    if not env("CERULEAN_ZONE") and env("CERULEAN_SERVER_ID"):
        lab = env("CERULEAN_LAB_DOMAIN", "lab.innotel.us").strip().strip(".")
        if lab and base_domain == "innotel.us":
            base_domain = f"{env('CERULEAN_SERVER_ID')}.{lab}"
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
    npm_host_ip = env("NPM_HOST_IP")
    technitium_url = env("TECHNITIUM_URL", env("TECHNITIUM_API_URL", "http://cerulean-technitium:5380")).rstrip("/")
    # Derive a zone that will host the proxy A records
    zone = base_domain

    if npm_host_ip:
        print(f"DNS: ensuring A records for {len(PROXY_HOSTS)} subdomains → {npm_host_ip} (Technitium zone {zone} @ {technitium_url})")
    else:
        print("DNS: NPM_HOST_IP not set — skipping A-record creation (add A records")
        print("     pointing at the NPM host, or create them in Cerulean → Domains → Records).")
        print(f"     To auto-create via Technitium, set NPM_HOST_IP and TECHNITIUM_URL/TECHNITIUM_TOKEN in .env.")

    npm = Npm(api_url, email, password)
    existing = npm.list_hosts()

    print(f"nginx proxy manager: {api_url}")
    print(f"Base domain: {base_domain}   Forward host: {forward_host}")

    # Authentik forward auth: one domain-level proxy provider covers the whole
    # zone, so a gated host only needs the auth_request snippet in its nginx
    # "advanced config". See FORWARD_AUTH_SNIPPET for which hosts opt out.
    fa_enabled, fa_outpost, fa_signin, fa_excluded = resolve_forward_auth(base_domain, forward_host)
    if fa_enabled:
        gated = [e["name"] for e in PROXY_HOSTS
                 if snippet_for_host(e, True, fa_outpost, fa_signin, fa_excluded)]
        print(f"Authentik forward auth on for {len(gated)} host(s): "
              f"{', '.join(gated) or '(none)'} (outpost {fa_outpost}, sign-in {fa_signin})")
    else:
        print("WARN Authentik forward auth is OFF — the Vault UI would not require a Cerulean session.",
              file=sys.stderr)

    print("Proxy hosts:")

    for entry in PROXY_HOSTS:
        auth_snippet = snippet_for_host(entry, fa_enabled, fa_outpost, fa_signin, fa_excluded)
        payload, domain = host_payload(entry, base_domain, forward_host, ssl_via_npm,
                                       letsencrypt_email, auth_snippet)
        if npm_host_ip and base_domain in domain:
            ok = ensure_a_record_technitium(domain, npm_host_ip, zone, technitium_url)
            print(f"  DNS {'✓' if ok else '✗'} A {domain} → {npm_host_ip} (Technitium)")
        found = next(
            (h for h in existing if domain in (h.get("domain_names") or [])),
            None,
        )
        if found is None:
            npm.create_host(payload)
            print(f"  ✓ created  {domain} → {payload['forward_scheme']}://{forward_host}:{payload['forward_port']}")
        else:
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
