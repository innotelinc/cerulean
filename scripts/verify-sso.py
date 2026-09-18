#!/usr/bin/env python3
"""verify-sso.py — prove Cerulean's sign-in posture still holds on a live box.

Cerulean is the trust layer, so its own surfaces are the ones every other zone
leans on. Four things are asserted:

  1. Every edge admin name demands Authentik. The oauth2-proxy gateway in the
     NPM edge's network namespace (`cerulean-npm-sso`, client `npm-edge`) is
     driven through a real authorization-code flow with a temporary Authentik
     identity, and the sealed session must then open the admin UI — which only
     happens if the identity headers are believed, i.e. only over the loopback
     hop (the edge refuses them from anywhere else).
  2. The group check is real: the same flow with an identity outside
     NPM_SSO_REQUIRED_GROUP must be refused.
  3. Vault's UI lands on OIDC and nothing else is open. Vault has no "default
     auth method" setting (`sys/config/ui` is Enterprise-only), so its entry
     documents are redirected to `?with=oidc` by the proxy host's
     advanced_config (see scripts/npm-proxy-hosts.py). The auth_url endpoint is
     then asked for a real authorization URL, which proves the OIDC method and
     the `operator` role are configured, and an unauthenticated read is refused.
  4. The Technitium console is the DNS/DHCP admin plane and is host-networked, so
     it must listen on loopback + the docker0 gateway only. The shared
     oauth2-proxy session store is the opposite case and is checked as such: it is
     published on this host's LAN address ON PURPOSE, because every gateway on
     every host shares one store and a gateway on another host cannot reach this
     host's 172.17.0.1. What must hold there is the password, since a LAN
     neighbour who can reach the port must not be able to read anyone's session.
  5. The console's OWN sign-in is Authentik. Closing the port is only half of it:
     a gateway in front of the console proves *someone* signed in and never *who*,
     so the console would keep a password of its own. Its `/sso/login` is asked
     with the headers the gateway sends, and it must leave for this IdP as the
     client the provider has registered, for the callback it has registered.

The temporary identities are deleted on the way out, including when a check
fails. Nothing here is destructive: no container is started, stopped or edited.

Config (environment, falling back to this repo's .env):

    NPM_SSO_REQUIRED_GROUP      group that may sign in (default cerulean-platform)
    AUTHENTIK_ISSUER_URL        the app-scoped issuer; its origin is the IdP host
                                the flow runs on (read from .env)
    AUTHENTIK_API_URL           default the issuer origin
    AUTHENTIK_BOOTSTRAP_TOKEN   Authentik API token (admin). Required.
    CERULEAN_SSO_BASE           base domain for the admin names
                                (default NPM_BASE_DOMAIN, else cerulean.innotel.us)
    TECHNITIUM_SSO_NAME         the console's public name
                                (default dns.internal.innotel.us)
    AUTHENTIK_TECHNITIUM_CLIENT_ID  the console's OIDC client (default technitium)
    LAN_IP                      the host's LAN address (default: auto-detected)

Exit codes: 0 = pass, 1 = a check failed, 2 = cannot run (unconfigured or the
deployment is unreachable).

Usage:
    python3 scripts/verify-sso.py
    python3 scripts/verify-sso.py --verbose
"""

import argparse
import http.cookiejar
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUTH_FLOW = "default-authentication-flow"
MEMBER_USER = "e2e-cerulean-sso"
OUTSIDER_USER = "e2e-cerulean-outsider"
SESSION_COOKIE = "_innotel_sso"
VAULT_HOST = "secrets.cerulean.innotel.us"

# Every one of these is fronted by the edge's own gateway and answers with the
# NPM admin UI once the loopback hop carries a believed identity.
ADMIN_NAMES = [
    ("edge admin (proxy)", "proxy.innotel.us"),
    ("edge admin (zeus)", "admin.zeus.innotel.us"),
    ("edge admin (monarch)", "admin.monarch.innotel.us"),
    ("edge admin (signara)", "admin.signara.innotel.us"),
]

# The first-party app never keeps a password door open behind Authentik.
LOCAL_LOGIN_PATHS = ["/api/auth/login"]

CONSOLE_PORT = 5380
SESSION_STORE_PORT = 16380
DOCKER_BRIDGE_GATEWAY = "172.17.0.1"

OK = "\033[32mPASS\033[0m"
BAD = "\033[31mFAIL\033[0m"


class CannotRun(Exception):
    """Configuration or reachability problem — exit 2, not a test failure."""


class CheckFailed(Exception):
    """An assertion about the deployment failed — exit 1."""


class IdpDenied(Exception):
    """Authentik rendered its "Permission denied" page instead of issuing a
    code: the identity authenticated but the application is not bound to it."""

    def __init__(self, body):
        super().__init__("Authentik refused the authorization")
        self.body = body


# ── config ─────────────────────────────────────────────────────────────────


def read_env_file():
    """Parse this repo's .env into a dict (ignores blanks and comments)."""
    vals = {}
    path = os.path.join(REPO_ROOT, ".env")
    if not os.path.exists(path):
        return vals
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            vals[key.strip()] = val.strip().strip('"').strip("'")
    return vals


def detect_lan_ip():
    """The host's LAN address, as a LAN client would see it (no packets sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


class Config:
    def __init__(self, args):
        env_file = read_env_file()

        def pick(*names, default=""):
            for name in names:
                if os.environ.get(name):
                    return os.environ[name]
                if env_file.get(name):
                    return env_file[name]
            return default

        self.base = (args.base or pick("CERULEAN_SSO_BASE", "NPM_BASE_DOMAIN",
                                       default="cerulean.innotel.us")).strip("/")
        # The flow host is whichever host the issuer lives on: Authentik serves
        # the authorize endpoint, its own login flow and the API there, and the
        # session cookie is per-host — so it must not be guessed.
        self.issuer = pick("AUTHENTIK_ISSUER_URL")
        parsed = urllib.parse.urlparse(self.issuer)
        self.idp = (f"{parsed.scheme}://{parsed.netloc}"
                    if parsed.scheme and parsed.netloc
                    else pick("AUTHENTIK_PUBLIC_URL",
                              default="https://auth.cerulean.innotel.us").rstrip("/"))
        self.api = pick("AUTHENTIK_API_URL", default=self.idp).rstrip("/") + "/api/v3"
        self.token = pick("AUTHENTIK_BOOTSTRAP_TOKEN", "AUTHENTIK_TOKEN")
        self.group = pick("NPM_SSO_REQUIRED_GROUP", "SSO_REQUIRED_GROUP",
                          default="cerulean-platform")
        self.lan_ip = (args.host_ip or pick("LAN_IP") or detect_lan_ip())
        self.session_store_host = pick("DOCKER_BRIDGE_GATEWAY", default=DOCKER_BRIDGE_GATEWAY)
        # The console's own OIDC relying party, as scripts/technitium-sso.py
        # configures it. Defaulted rather than required: the name is a property of
        # this zone, and a deployment that renamed it says so in .env.
        self.console_name = pick(
            "TECHNITIUM_SSO_NAME", default="dns.internal.innotel.us"
        ).strip("/")
        self.console_client_id = pick("AUTHENTIK_TECHNITIUM_CLIENT_ID", default="technitium")
        self.vault_role = pick("VAULT_OIDC_ROLE", default="operator")
        self.vault_redirect = pick(
            "VAULT_OIDC_REDIRECT",
            default=f"https://{VAULT_HOST}/ui/vault/auth/oidc/oidc/callback",
        )
        self.password = "E2e-Sso-" + os.urandom(6).hex() + "!Aa1"
        self.verbose = args.verbose

        if not self.token:
            raise CannotRun(
                "no Authentik API token: set AUTHENTIK_BOOTSTRAP_TOKEN (env or .env)"
            )
        if not self.lan_ip:
            raise CannotRun("could not determine the host's LAN address (set LAN_IP)")


# ── HTTP ───────────────────────────────────────────────────────────────────


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    """A cookie-jar-backed client that never follows redirects, so the OIDC hops
    can be asserted one at a time."""

    def __init__(self, cfg, base=None):
        self.cfg = cfg
        self.base = base or cfg.idp
        self.jar = http.cookiejar.CookieJar()

    def _trace(self, method, url, status):
        if self.cfg.verbose:
            print(f"         {method} {url[:96]} -> {status}", file=sys.stderr)

    def _open(self, req, timeout=30):
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect()
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                return (resp.status, resp.headers.get("Location"),
                        resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as err:
            return (err.code, err.headers.get("Location"),
                    (err.read() or b"").decode("utf-8", "replace"))

    def cookie(self, name):
        for c in self.jar:
            if c.name == name:
                return c.value
        return None

    def get(self, url, headers=None):
        if url.startswith("/"):  # IdP-relative
            url = self.base + url
        req = urllib.request.Request(url)
        # Only used for the console, whose public name arrives as forwarded headers
        # rather than as a Host: the gateway terminates the name and proxies to
        # loopback, so without them the console forms a callback of
        # `http://127.0.0.1:5380/sso/callback` and the provider refuses it.
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        status, location, body = self._open(req)
        self._trace("GET", url, status)
        return status, location, body

    def post(self, url, payload, headers=None):
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        # Authentik's flow executor requires the CSRF cookie echoed back.
        req.add_header("X-authentik-CSRF", self.cookie("authentik_csrf") or "")
        req.add_header("Referer", self.base + "/")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        status, location, body = self._open(req)
        self._trace("POST", url, status)
        return status, location, body

    def follow_json(self, url, hops=8):
        """Authentik bounces a POST -> 302 -> GET before handing back the next
        flow stage; follow until the JSON stage arrives."""
        for _ in range(hops):
            status, location, body = self.get(url)
            if status == 200:
                return json.loads(body)
            if status == 302 and location:
                url = location
                continue
            raise CheckFailed(f"expected a JSON stage, got HTTP {status} for {url}")
        raise CheckFailed("too many redirects inside Authentik's auth flow")

    def follow_to_code(self, url, hops=8, allow_denial=False):
        """Follow redirects until the OAuth2 redirect_uri carries ?code=.

        With `allow_denial`, a rendered page in place of the code is reported as
        IdpDenied rather than a broken hop — Authentik answers the final
        authorize step with its "Permission denied" page (HTTP 200) when the
        identity is not bound to the application."""
        for _ in range(hops):
            status, location, body = self.get(url)
            if status == 200 and allow_denial:
                raise IdpDenied(body)
            if status == 302 and location:
                if "code=" in location:
                    return location
                url = location
                continue
            raise CheckFailed(f"authorize returned {status} instead of a code: {body[:300]}")
        raise CheckFailed("no authorization code after too many redirects")


# ── Authentik admin API ────────────────────────────────────────────────────


class AuthApi:
    def __init__(self, cfg):
        self.cfg = cfg

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.cfg.api + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.cfg.token)
        req.add_header("Accept", "application/json")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as err:
            raise CannotRun(
                f"{method} {path} -> HTTP {err.code}: {(err.read() or b'').decode()[:300]}"
            )

    def find_group(self, name):
        """`superuser_full_list` matters: the plain list is policy-filtered for
        service accounts and can hide real groups."""
        query = "/core/groups/?superuser_full_list=true&name=" + urllib.parse.quote(name)
        for group in self.call("GET", query)["results"]:
            if group.get("name") == name:
                return group["pk"]
        return None

    def delete_user(self, username):
        for stale in self.call(
            "GET", "/core/users/?username=" + urllib.parse.quote(username)
        )["results"]:
            self.call("DELETE", f"/core/users/{stale['pk']}/")

    def make_user(self, username, label, groups=()):
        """Create an active internal user with a random password; return its pk."""
        self.delete_user(username)
        user = self.call(
            "POST",
            "/core/users/",
            {
                "username": username,
                "name": label,
                "email": f"{username}@innotel.us",
                "is_active": True,
                "path": "users",
                "type": "internal",
            },
        )
        pk = user["pk"]
        self.call("POST", f"/core/users/{pk}/set_password/", {"password": self.cfg.password})
        for group in groups:
            self.call("POST", f"/core/groups/{group}/add_user/", {"pk": pk})
        return pk


# ── the flow ───────────────────────────────────────────────────────────────


def require(condition, message):
    """A hop assertion: raise on failure, print nothing on success."""
    if not condition:
        raise CheckFailed(message)


def unreachable(err, host):
    """A name that does not resolve, or a connection that never lands.

    Reported, never raised: a resolver that cannot see one of these names is a
    finding about *this* run, and an unhandled `socket.gaierror` out of urllib
    would bury the other results behind a traceback.
    """
    if "Name or service not known" in str(err) or "Temporary failure" in str(err):
        return f"cannot resolve {host} from this host ({err})"
    return f"cannot reach {host} ({err})"


def check(condition, message):
    if condition:
        print(f"  {OK}  {message}")
    else:
        raise CheckFailed(message)


def redis_probe(host, port=SESSION_STORE_PORT, timeout=4.0):
    """Redis's own protocol: `redis-cli` is not assumed on the host.

    A password-protected server answers an unauthenticated PING with
    `-NOAUTH Authentication required.`, which is the answer this check wants — an
    `+PONG` is the finding, because it means every session in the shared store is
    readable by anything that can open the port.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.sendall(b"PING\r\n")
            return conn.recv(128).decode("utf-8", "replace")
    except OSError as err:
        return f"(no answer: {err})"


def port_state(ip, port, timeout=4.0):
    """True when a TCP connection is accepted."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def sso_login(client, cfg, app, username, allow_idp_denial=False):
    """Drive a full authorization-code flow against one gateway, leaving the
    sealed session in the client's jar.

    Returns `(kind, status, body)`. `kind` is "flow" for a completed dance
    (`status` is then the callback hop), or "idp-denied" when Authentik refused
    to issue a code — a refusal just as final as a gateway 403.
    """
    status, location, _ = client.get(app + "/")
    require(status == 302, f"GET {app}/ -> HTTP {status} (expected 302 to the IdP)")
    require(cfg.idp in (location or ""),
            f"{app} redirected to {(location or '-')[:80]} instead of the IdP")
    require("client_id=" in (location or ""), "the authorize URL carries no client_id")

    status, location, body = client.get(location)
    if allow_idp_denial and status == 200:
        return "idp-denied", status, body
    require(status == 302 and location, f"authorize -> HTTP {status}: {body[:160]}")

    # Authentik hands back a flow URL on the host it actually serves; pin the
    # client to that origin so the session/CSRF cookies line up.
    flow = urllib.parse.urlparse(urllib.parse.urljoin(client.base, location))
    client.base = f"{flow.scheme}://{flow.netloc}"
    executor = (client.base + "/api/v3/flows/executor/" + AUTH_FLOW + "/?"
                + urllib.parse.urlencode({"query": urllib.parse.urlparse(location).query}))
    stage = client.follow_json(executor)
    for _ in range(6):
        component = stage.get("component")
        if component == "xak-flow-redirect":
            break
        if component == "ak-stage-identification":
            payload, label = {"uid_field": username}, "username"
        elif component == "ak-stage-password":
            payload, label = {"password": cfg.password}, "password"
        else:
            raise CheckFailed(f"unexpected Authentik stage {component}")
        status, next_url, body = client.post(executor, payload)
        if status not in (200, 302):
            raise CheckFailed(f"{label} rejected (HTTP {status}): {body[:200]}")
        stage = client.follow_json(next_url or executor)
    require(stage.get("component") == "xak-flow-redirect",
            "Authentik's flow never handed back the authorize URL")

    try:
        callback = client.follow_to_code(stage["to"], allow_denial=allow_idp_denial)
    except IdpDenied as denied:
        return "idp-denied", 200, denied.body
    status, _, callback_body = client.get(callback)
    return "flow", status, callback_body


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="base domain for the admin names")
    parser.add_argument("--host-ip", help="the host's LAN address (default: detected)")
    parser.add_argument("--verbose", action="store_true", help="trace every HTTP hop")
    args = parser.parse_args()

    try:
        cfg = Config(args)
    except CannotRun as err:
        print(f"SKIP: {err}", file=sys.stderr)
        return 2

    api = AuthApi(cfg)
    app_host = f"cerulean.{cfg.base}"
    print("Cerulean SSO verification")
    print(f"  idp     : {cfg.idp}")
    print(f"  api     : {cfg.api}")
    print(f"  base    : {cfg.base}")
    print(f"  group   : {cfg.group or '(none)'}")
    print(f"  host ip : {cfg.lan_ip}")
    print()

    member_pk = outsider_pk = None
    failures = 0
    try:
        # ── reachability (a failure here is a skip, not a bad deployment) ──
        try:
            status, _, _ = Client(cfg).get(cfg.idp + "/")
        except (urllib.error.URLError, OSError) as err:
            raise CannotRun(f"{cfg.idp} is unreachable: {err}") from err
        if status >= 500:
            raise CannotRun(f"the IdP answered HTTP {status}")

        # ── 1. temporary identities ────────────────────────────────────────
        print("[1] temporary Authentik identities")
        group_pk = api.find_group(cfg.group) if cfg.group else None
        if cfg.group and not group_pk:
            raise CannotRun(f"Authentik group {cfg.group!r} not found")
        member_pk = api.make_user(MEMBER_USER, "Cerulean SSO Verification",
                                  [group_pk] if group_pk else [])
        outsider_pk = api.make_user(OUTSIDER_USER, "Cerulean SSO Outsider")
        print(f"  {OK}  {MEMBER_USER} (pk={member_pk}) in {cfg.group or 'no group'}")
        print(f"  {OK}  {OUTSIDER_USER} (pk={outsider_pk}) in no group")

        # ── 2. every edge admin name, through a real login ─────────────────
        print("[2] the edge demands Authentik, then opens for the member")
        for label, host in ADMIN_NAMES:
            app = f"https://{host}"
            client = Client(cfg)
            print(f"  -- {label} ({host})")
            try:
                _, status, _ = sso_login(client, cfg, app, MEMBER_USER)
                require(status in (302, 200), f"callback -> HTTP {status} (expected a redirect)")
            except CheckFailed as err:
                print(f"  {BAD}  {err}")
                failures += 1
                continue
            except (urllib.error.URLError, OSError) as err:
                print(f"  {BAD}  {unreachable(err, host)}")
                failures += 1
                continue
            check(client.cookie(SESSION_COOKIE) is not None,
                  f"{SESSION_COOKIE} session cookie issued")
            status, location, body = client.get(app + "/")
            check(status < 400, f"GET {app}/ with the session -> HTTP {status} "
                                f"({len(body)} bytes, expected < 400, "
                                f"redirect {(location or '-')[:40]})")

        # ── 3. the group check is real ─────────────────────────────────────
        print("[3] an identity outside the required group is refused")
        label, host = ADMIN_NAMES[0]
        app = f"https://{host}"
        outsider = Client(cfg)
        try:
            # Two refusals are possible and either one is correct: Authentik can
            # decline to issue a code at all, or it issues one and the edge
            # rejects it with 403.
            kind, status, body = sso_login(outsider, cfg, app, OUTSIDER_USER,
                                           allow_idp_denial=True)
            if kind == "idp-denied":
                check("denied" in body.lower(),
                      f"{label}: Authentik refused the non-member's authorization")
            else:
                if status != 403:
                    status, _, _ = outsider.get(app + "/")
                check(status == 403, f"{label}: non-member -> HTTP {status} (expected 403)")
        except CheckFailed as err:
            print(f"  {BAD}  {label}: {err}")
            failures += 1
        except (urllib.error.URLError, OSError) as err:
            print(f"  {BAD}  {label}: {unreachable(err, host)}")
            failures += 1

        # ── 4. Vault's UI lands on OIDC ────────────────────────────────────
        print("[4] the Vault UI lands on OIDC, and its API stays closed")
        vault = Client(cfg)
        status, location, body = vault.get(f"https://{VAULT_HOST}/")
        check(status == 302, f"Vault / -> HTTP {status} (expected 302)")
        check((location or "").endswith("/ui/vault/auth?with=oidc"),
              f"Vault / redirects to the OIDC sign-in (got {(location or '-')[:72]})")
        # Also check the intermediate name, so the redirect cannot be bypassed by
        # opening /ui/ directly.
        status, location, _ = vault.get(f"https://{VAULT_HOST}/ui/")
        check(status == 302 and (location or "").endswith("/ui/vault/auth?with=oidc"),
              f"Vault /ui/ redirects too (got {status} {(location or '-')[:52]})")
        # Vault's auth_url endpoint is unauthenticated on purpose (the UI calls
        # it before anyone has a token), so it is the honest way to prove the
        # OIDC method and the role exist without a browser: a live answer names
        # the IdP and the client, and it can only be issued if the role's
        # allowed_redirect_uris already contain the callback we send.
        # The path really is `oidc/oidc/` — the auth method's mount, then the
        # JWT/OIDC backend's own `oidc` sub-path. Calling `auth/oidc/auth_url`
        # answers "permission denied" (Vault hides a missing path from an
        # unauthenticated caller), which is how this was found.
        status, _, raw = vault.post(
            f"https://{VAULT_HOST}/v1/auth/oidc/oidc/auth_url",
            {"role": cfg.vault_role, "redirect_uri": cfg.vault_redirect},
        )
        auth_url = ""
        if status == 200:
            try:
                auth_url = json.loads(raw).get("data", {}).get("auth_url", "")
            except ValueError:
                auth_url = ""
        check(bool(auth_url) and cfg.idp in auth_url and "client_id=vault" in auth_url,
              f"Vault's auth_url endpoint issues an Authentik URL for role "
              f"{cfg.vault_role!r} (HTTP {status}, {auth_url[:64] or 'no auth_url'})")
        status, _, _ = vault.get(f"https://{VAULT_HOST}/v1/sys/mounts")
        check(status in (403, 400), f"Vault refuses an unauthenticated /v1/sys/mounts "
                                    f"(HTTP {status})")

        # ── 5. the cerulean app keeps no password door ─────────────────────
        print("[5] the cerulean app's local password login is refused")
        app_client = Client(cfg)
        for path in LOCAL_LOGIN_PATHS:
            status, _, _ = app_client.post(f"https://{app_host}{path}",
                                           {"password": "irrelevant"})
            check(status in (403, 404, 405),
                  f"POST {path} -> HTTP {status} (expected 403 while BREAKGLASS_LOGIN is off)")

        # ── 6. the Technitium console is off the LAN ───────────────────────
        print("[6] the Technitium console answers off the LAN only")
        check(not port_state(cfg.lan_ip, CONSOLE_PORT),
              f"console: {cfg.lan_ip}:{CONSOLE_PORT} refused on the LAN "
              f"(the public door is dns.internal.innotel.us)")
        check(port_state("127.0.0.1", CONSOLE_PORT), "console: 127.0.0.1:5380 answers")
        check(port_state(cfg.session_store_host, CONSOLE_PORT),
              f"console: {cfg.session_store_host}:{CONSOLE_PORT} answers "
              f"(the address containers dial)")

        # ── 7. the console's own sign-in is Authentik, not a password ──────
        # Closing the port is only half of it. The console has a login of its own,
        # and a gateway in front of it cannot replace that login — it can only prove
        # that *someone* signed in, never *who*. Technitium speaks OIDC itself, so
        # the assertion is that its own sign-in button leaves for this IdP, with the
        # callback the provider has registered: a callback that is not registered
        # dies at the IdP after the person has already signed in.
        print("[7] the Technitium console signs in through Authentik")
        status, location, _ = Client(cfg).get(
            f"http://127.0.0.1:{CONSOLE_PORT}/sso/login",
            {
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": cfg.console_name,
            },
        )
        check(status == 302 and (location or "").startswith(cfg.idp),
              f"console /sso/login -> HTTP {status} to {(location or '-')[:64]}")
        check(f"client_id={cfg.console_client_id}" in (location or ""),
              f"console signs in as client_id={cfg.console_client_id} "
              f"(got {(location or '-')[:96]})")
        want_redirect = urllib.parse.quote(f"https://{cfg.console_name}/sso/callback", safe="")
        check(f"redirect_uri={want_redirect}" in (location or ""),
              f"console sends redirect_uri={urllib.parse.unquote(want_redirect)} "
              f"(the provider must have it registered)")

        # ── 8. the shared session store is shared, and password-protected ──
        # NOT "off the LAN". Every SSO gateway on every host shares ONE store, so a
        # gateway on another host has to be able to dial this one, and that is over
        # the LAN address — 172.17.0.1 is each host's own docker0. This check used
        # to assert the LAN bind was absent, which the deployment deliberately does
        # not do, so it failed on a correct install and would have been trained away.
        # The property that matters is the password: a LAN neighbour who can open
        # the port must still not be able to read a session.
        print("[8] the shared SSO session store is shared by design, and protected")
        check(port_state(cfg.session_store_host, SESSION_STORE_PORT),
              f"session store: {cfg.session_store_host}:{SESSION_STORE_PORT} answers "
              f"(the address this host's containers dial)")
        check(port_state(cfg.lan_ip, SESSION_STORE_PORT),
              f"session store: {cfg.lan_ip}:{SESSION_STORE_PORT} answers "
              f"(the sibling hosts' gateways dial this)")
        reply = redis_probe(cfg.session_store_host)
        check(reply.startswith("-NOAUTH") or reply.startswith("-ERR"),
              f"session store refuses an unauthenticated PING ({reply.strip()[:64] or 'no reply'})")

        if failures:
            print(f"\n{BAD} — {failures} target(s) did not pass", file=sys.stderr)
            return 1
        print("\nPASS — the trust layer is Authentik-only and its admin planes are closed")
        return 0
    except CannotRun as err:
        print(f"\nSKIP: {err}", file=sys.stderr)
        return 2
    except CheckFailed as err:
        print(f"\n{BAD} — {err}", file=sys.stderr)
        return 1
    finally:
        for username, pk in ((MEMBER_USER, member_pk), (OUTSIDER_USER, outsider_pk)):
            if not pk:
                continue
            try:
                api.call("POST", f"/core/users/{pk}/set_password/",
                         {"password": os.urandom(24).hex()})
                api.call("DELETE", f"/core/users/{pk}/")
                print(f"[cleanup] deleted temporary user {username} (pk={pk})")
            except CannotRun as err:
                print(f"[cleanup] WARNING: could not delete pk={pk}: {err}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
