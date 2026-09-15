#!/usr/bin/env python3
"""verify-forward-auth.py — prove the Authentik forward-auth gates actually gate.

NPM protects a host by `auth_request`-ing the Authentik embedded outpost, which
matches the request by `X-Forwarded-Host` against the five domain-level proxy
providers (one per zone: capstone, cerulean, monarch, olympus, zeus). A gate is
only working if BOTH halves hold:

  1. an anonymous request is bounced to
     `auth.<zone>.innotel.us/outpost.goauthentik.io/start`; and
  2. an authenticated request gets through to the app behind it.

A provider that is merely *attached to the outpost* satisfies (1) — the outpost
answers 401/302 to everyone — while (2) can still fail on a policy binding, a
missing application, or a wrong `cookie_domain` that stops the session cookie
from reaching the sibling host. That is exactly how the zone providers were
first created (as `forward_single` with an empty cookie domain), so this script
checks both halves against the live edge with a real Authentik login.

That login needs a real identity, so the script creates a temporary Authentik
user, adds it to the groups the gates require, drives Authentik's own
authentication flow per host, and deletes the user on the way out — including
when a check fails.

Config (environment, falling back to this repo's .env):

    FWD_AUTH_TARGETS_JSON    override the target table (JSON list of
                             [host, zone_auth_host, group_or_null])
    AUTHENTIK_PUBLIC_URL     the Authentik front used for the API + flow
    AUTHENTIK_BOOTSTRAP_TOKEN  Authentik API token. Required.

Exit codes: 0 = pass, 1 = a gate failed, 2 = cannot run (unconfigured or the
edge is unreachable).

When a new host is put behind the gate, add it to TARGETS below — one gated
host per zone is enough, but the one you add is the one that gets checked.

Usage:
    python3 scripts/verify-forward-auth.py
"""

import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# host, the zone's Authentik host, and the Authentik group the gate requires
# (None = no binding, any authenticated user passes).
TARGETS = [
    ("secrets.cerulean.innotel.us", "auth.cerulean.innotel.us", None),
    ("pbx.zeus.innotel.us", "auth.zeus.innotel.us", None),
    ("n8n.capstone.innotel.us", "auth.capstone.innotel.us", "Capstone"),
]

TEMP_USERNAME = "e2e-forward-auth"
OK = "\033[32mPASS\033[0m"
BAD = "\033[31mFAIL\033[0m"


class CannotRun(Exception):
    """Configuration or reachability problem — exit 2, not a test failure."""


class CheckFailed(Exception):
    """A gate did not behave — exit 1."""


# ── config ─────────────────────────────────────────────────────────────────


def read_env_file():
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


class Config:
    def __init__(self):
        env_file = read_env_file()

        def pick(name, default=""):
            return os.environ.get(name) or env_file.get(name) or default

        self.public = pick("AUTHENTIK_PUBLIC_URL", "https://auth.cerulean.innotel.us").rstrip("/")
        self.api = pick("AUTHENTIK_API_URL", self.public).rstrip("/") + "/api/v3"
        self.token = pick("AUTHENTIK_BOOTSTRAP_TOKEN")
        self.allowlist_email = pick("AUTHENTIK_ADMIN_EMAILS", "admin@innotel.us").split(",")[0].strip()
        if not self.token:
            raise CannotRun("no Authentik API token: set AUTHENTIK_BOOTSTRAP_TOKEN (env or .env)")
        override = os.environ.get("FWD_AUTH_TARGETS_JSON")
        self.targets = json.loads(override) if override else TARGETS


# ── HTTP ───────────────────────────────────────────────────────────────────


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Session:
    """Cookie-jar client that never follows redirects, so each hop of the
    outpost dance can be asserted on its own."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()

    def _open(self, req, timeout=30):
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())
        try:
            with op.open(req, timeout=timeout) as r:
                return r.status, r.headers.get("Location"), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location"), (e.read() or b"").decode("utf-8", "replace")

    def get(self, url):
        return self._open(urllib.request.Request(url))

    def cookie(self, name):
        for c in self.jar:
            if c.name == name:
                return c.value
        return None

    def post_json(self, url, payload):
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        # Authentik's flow executor requires the CSRF cookie echoed back.
        req.add_header("X-authentik-CSRF", self.cookie("authentik_csrf") or "")
        origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlparse(url))
        req.add_header("Referer", origin + "/")
        return self._open(req)


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
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raise CannotRun(f"{method} {path} -> HTTP {e.code}: {(e.read() or b'').decode()[:300]}")

    def group_pk(self, name):
        """`superuser_full_list` matters: the plain list is policy-filtered for
        service accounts, and the results are paginated — page one can hide
        real groups and applications."""
        page = 1
        while True:
            d = self.call(
                "GET",
                f"/core/groups/?superuser_full_list=true&page={page}&page_size=100&name="
                + urllib.parse.quote(name),
            )
            for group in d["results"]:
                if group.get("name") == name:
                    return group["pk"]
            if not d["pagination"]["next"]:
                return None
            page += 1


# ── the outpost dance ──────────────────────────────────────────────────────


def drive_flow(session, flow_url, username, password, hops=8):
    """Authentik served us an /if/flow/<slug>/ page: run that flow to the
    redirect it finishes with, and return where it wants to go next."""
    parsed = urllib.parse.urlparse(flow_url)
    slug = re.search(r"/if/flow/([^/]+)/", parsed.path).group(1)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    executor = origin + "/api/v3/flows/executor/" + slug + "/?" + urllib.parse.urlencode(
        {"query": parsed.query})

    def next_stage(url):
        for _ in range(hops):
            status, location, body = session.get(url)
            if status == 200:
                return json.loads(body)
            if status == 302 and location:
                url = urllib.parse.urljoin(url, location)
                continue
            raise CheckFailed(f"unexpected HTTP {status} inside Authentik's flow")
        raise CheckFailed("Authentik's flow did not settle")

    stage = next_stage(executor)
    for _ in range(6):
        component = stage.get("component")
        if component == "xak-flow-redirect":
            return urllib.parse.urljoin(origin, stage["to"])
        if component == "ak-stage-identification":
            payload, what = {"uid_field": username}, "username"
        elif component == "ak-stage-password":
            payload, what = {"password": password}, "password"
        else:
            raise CheckFailed(f"unexpected Authentik stage {component}")
        status, location, body = session.post_json(executor, payload)
        if status not in (200, 302):
            raise CheckFailed(f"{what} rejected (HTTP {status}): {body[:200]}")
        # The browser reloads the executor with the flow `query`; that GET is
        # what returns the next stage (or the final redirect).
        stage = next_stage(urllib.parse.urljoin(executor, location) if location else executor)
    raise CheckFailed("Authentik's flow never completed")


def login_and_fetch(session, host, username, password, hops=14):
    """Walk the whole gate for one host until we land somewhere that is not an
    Authentik redirect, driving any authentication flow we meet."""
    url = f"https://{host}/"
    for _ in range(hops):
        status, location, body = session.get(url)
        if status in (301, 302, 303, 307, 308) and location:
            nxt = urllib.parse.urljoin(url, location)
            if "/if/flow/" in urllib.parse.urlparse(nxt).path:
                url = drive_flow(session, nxt, username, password)
                continue
            url = nxt
            continue
        return status, url, body
    raise CheckFailed("too many redirects walking the gate")


def check(condition, message):
    if condition:
        print(f"  {OK}  {message}")
    else:
        raise CheckFailed(message)


def main():
    try:
        cfg = Config()
    except CannotRun as err:
        print(f"SKIP: {err}", file=sys.stderr)
        return 2
    api = AuthApi(cfg)
    print("Forward-auth gate verification")
    print(f"  authentik : {cfg.public}")
    print(f"  targets   : {len(cfg.targets)}")
    print()

    created_pk = None
    password = "E2e-Fwd-" + os.urandom(4).hex() + "!Aa1"
    try:
        print("[1] temporary Authentik identity")
        try:
            status, _, _ = Session().get(f"https://{cfg.targets[0][0]}/")
        except (urllib.error.URLError, OSError) as err:
            raise CannotRun(f"{cfg.targets[0][0]} is unreachable: {err}") from err
        if status >= 500:
            raise CannotRun(f"{cfg.targets[0][0]} answered HTTP {status}")

        for stale in api.call("GET", "/core/users/?username=" + urllib.parse.quote(TEMP_USERNAME))[
            "results"
        ]:
            api.call("DELETE", f"/core/users/{stale['pk']}/")
        user = api.call(
            "POST",
            "/core/users/",
            {
                "username": TEMP_USERNAME,
                "name": "Forward-auth verification",
                "email": cfg.allowlist_email,
                "is_active": True,
                "path": "users",
                "type": "internal",
            },
        )
        created_pk = user["pk"]
        api.call("POST", f"/core/users/{created_pk}/set_password/", {"password": password})
        groups = sorted({t[2] for t in cfg.targets if len(t) > 2 and t[2]})
        for name in groups:
            pk = api.group_pk(name)
            if not pk:
                raise CannotRun(f"Authentik group {name!r} not found (a gate requires it)")
            api.call("POST", f"/core/groups/{pk}/add_user/", {"pk": created_pk})
        print(f"  {OK}  created {TEMP_USERNAME} (pk={created_pk}) groups={groups or '-'}")
        print()

        failures = []
        for i, (host, zone, _group) in enumerate(cfg.targets, start=2):
            print(f"[{i}] {host}")
            try:
                status, location, _ = Session().get(f"https://{host}/")
                check(
                    status in (301, 302, 307, 308) and zone in (location or ""),
                    f"anonymous request is bounced to {zone} (got HTTP {status})",
                )

                session = Session()
                status, final, _ = login_and_fetch(session, host, TEMP_USERNAME, password)
                check(
                    not ("outpost" in final and zone in final),
                    f"authenticated request reaches the app, not the outpost (landed on {final})",
                )
                proxy_cookies = [c.name for c in session.jar if c.name.startswith("authentik_proxy")]
                check(bool(proxy_cookies), f"outpost session cookie issued ({proxy_cookies})")
                print(f"       -> HTTP {status} {final}")
            except CheckFailed as err:
                print(f"  {BAD}  {err}")
                failures.append(f"{host}: {err}")
            print()

        if failures:
            print("FAIL:", *failures, sep="\n  ")
            return 1
        print("PASS — every gated host is closed anonymously and open to an authenticated user")
        return 0
    except CannotRun as err:
        print(f"\nSKIP: {err}", file=sys.stderr)
        return 2
    except CheckFailed as err:
        print(f"\n{BAD} — {err}", file=sys.stderr)
        return 1
    finally:
        if created_pk:
            try:
                api.call(
                    "POST",
                    f"/core/users/{created_pk}/set_password/",
                    {"password": os.urandom(24).hex()},
                )
                api.call("DELETE", f"/core/users/{created_pk}/")
                print(f"[cleanup] deleted temporary user pk={created_pk}")
            except CannotRun as err:
                print(f"[cleanup] WARNING: could not delete pk={created_pk}: {err}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
