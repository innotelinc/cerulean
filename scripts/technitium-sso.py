#!/usr/bin/env python3
"""technitium-sso.py — sign in to the Technitium console with Cerulean's Authentik.

WHAT THIS IS FOR. The console is the DNS/DHCP admin plane: it can rewrite a zone,
move a lease, and turn on a block list for the whole LAN. It has its own login, and
an account with a password on it is a credential that lives outside Authentik —
never rotated with the others, and invisible to Authentik's own audit.

The console sits behind an oauth2-proxy gateway at `dns.<zone>` (compose service
`cerulean-technitium-sso`), and that gateway is not enough. It proves *someone*
signed in; it cannot tell the console *who*, so the console still has to ask for a
password of its own. Technitium speaks OIDC itself, and this script is what points
it at Authentik — the same sign-in, the same groups, and no password anywhere in
the browser path.

WHY THE GATEWAY STAYS. The console's OIDC also would not be reachable on its own:
the console binds loopback plus docker0 and answers nothing on the LAN, which is a
property worth keeping. So the gateway is the door and this is the identity.

WHAT `--check` CANNOT SEE. The console never returns the client secret (the API
masks it as `************`), so a secret that has drifted cannot be detected here —
only replaced. Everything else is compared: the authority, the discovery URL, the
client id, the scopes, the group map, and the three sign-up switches.

Config (real environment first, then this repo's `.env`):

    TECHNITIUM_URL                the console's API, as the host sees it
                                  (loopback or docker0 — never its LAN address)
    TECHNITIUM_TOKEN              a long-lived API token (preferred)
    TECHNITIUM_USER/_PASSWORD     or an admin login, in that order of preference
    SSO_AUTHENTIK_BASE            the IdP origin
    AUTHENTIK_TECHNITIUM_CLIENT_ID
    AUTHENTIK_TECHNITIUM_CLIENT_SECRET
    TECHNITIUM_SSO_APP_SLUG       Authentik application slug (default: technitium)
    TECHNITIUM_SSO_AUTHORITY      override the derived app-scoped issuer
    TECHNITIUM_SSO_ENABLED        default true
    TECHNITIUM_SSO_SCOPES         default openid,profile,email,groups
    TECHNITIUM_SSO_GROUP_MAP      remote:local pairs, comma-separated
    TECHNITIUM_SSO_ALLOW_SIGNUP   default false
    TECHNITIUM_SSO_SIGNUP_ONLY_FOR_MAPPED_USERS   default true
    AUTHENTIK_API_URL             used only to read the provider's callbacks back
    AUTHENTIK_BOOTSTRAP_TOKEN     the same, when it is set

Usage:
    python3 scripts/technitium-sso.py           # configure it (idempotent)
    python3 scripts/technitium-sso.py --check   # report drift, change nothing

Exit codes: 0 = in sync (or configured), 1 = drifted or the console refused,
2 = cannot judge (unconfigured, or the console/IdP is unreachable).
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

OK = "OK   "
DRIFT = "DRIFT"
FAIL = "FAIL "

# The group claim is what makes a group map work, and Authentik only emits it when
# the scope is asked for. Left out, a mapped user signs in without their groups —
# which for this console means without Administrators.
DEFAULT_SCOPES = "openid,profile,email,groups"


def env(key, default=""):
    value = os.environ.get(key)
    return value if value not in (None, "") else default


def load_env_file(path):
    """Load KEY=VALUE lines into the environment, without overwriting what is set.

    The same precedence every other provisioner here uses: an operator's own
    environment wins, and the file fills in the rest.
    """
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def http_json(url, *, params=None, headers=None, timeout=20):
    """A GET or POST that returns parsed JSON, or raises for the caller to judge."""
    data = urllib.parse.urlencode(params).encode() if params is not None else None
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    request.add_header("Accept", "application/json")
    if data:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read() or b"null")


def console(api, path, *, token="", params=None):
    """One console API call. Technitium takes both its token and its inputs as query
    parameters, and answers 200 with `{"status": "error"}` rather than an HTTP error
    — so the status field, not the status code, is what the caller checks.
    """
    query = {"token": token} if token else {}
    if params:
        query.update(params)
    body = http_json(f"{api.rstrip('/')}/{path.lstrip('/')}?{urllib.parse.urlencode(query)}")
    if not isinstance(body, dict):
        raise RuntimeError(f"{path} answered something that is not a Technitium response")
    if body.get("status") != "ok":
        raise RuntimeError(f"{path}: {body.get('errorMessage') or 'refused'}")
    return body.get("response") or {}


def console_token(api):
    """The API token to use, minting a session one when only a password is configured.

    The token is preferred over the password for the same reason it is preferred in
    `.env`: it survives a password change and it can be revoked on its own.
    """
    token = env("TECHNITIUM_TOKEN")
    if token:
        return token

    user = env("TECHNITIUM_USER", "admin")
    password = env("TECHNITIUM_PASSWORD")
    if not password:
        raise SystemExit(
            "TECHNITIUM_TOKEN is unset and there is no TECHNITIUM_PASSWORD — set one "
            "in .env (Technitium → Settings → API Tokens → Create)"
        )

    login = http_json(
        f"{api.rstrip('/')}/api/user/login?"
        + urllib.parse.urlencode({"user": user, "pass": password})
    )
    if login.get("status") != "ok":
        raise SystemExit(f"Technitium refused the login for {user}: {login.get('errorMessage')}")
    token = ((login.get("response") or {}).get("token")) or ""
    if not token:
        raise SystemExit("Technitium accepted the login but returned no token")
    return token


def desired_config():
    """The console's SSO settings as this deployment says they should be."""
    idp = env("SSO_AUTHENTIK_BASE").rstrip("/")
    client_id = env("AUTHENTIK_TECHNITIUM_CLIENT_ID", "technitium")
    client_secret = env("AUTHENTIK_TECHNITIUM_CLIENT_SECRET")
    slug = env("TECHNITIUM_SSO_APP_SLUG", "technitium").strip("/")

    # App-scoped, not the IdP root: Authentik advertises its own base URL as the
    # issuer while an application's endpoints live under /application/o/<slug>/, so
    # the authority has to be the application's.
    authority = env("TECHNITIUM_SSO_AUTHORITY", f"{idp}/application/o/{slug}/")
    metadata = env(
        "TECHNITIUM_SSO_METADATA_ADDRESS", f"{authority.rstrip('/')}/.well-known/openid-configuration"
    )

    scopes = [s.strip() for s in env("TECHNITIUM_SSO_SCOPES", DEFAULT_SCOPES).split(",") if s.strip()]
    if "openid" not in scopes:
        # The console adds openid itself, but a list that does not say so is a typo
        # worth naming rather than silently repairing.
        raise SystemExit(f"TECHNITIUM_SSO_SCOPES must include openid — got {','.join(scopes)}")

    groups = []
    for pair in env("TECHNITIUM_SSO_GROUP_MAP").split(","):
        pair = pair.strip()
        if not pair:
            continue
        remote, _, local = pair.partition(":")
        if not remote or not local:
            raise SystemExit(
                f"TECHNITIUM_SSO_GROUP_MAP entries are remote:local — {pair!r} is neither"
            )
        groups.append((remote.strip(), local.strip()))

    return {
        "enabled": env("TECHNITIUM_SSO_ENABLED", "true").lower() in ("1", "true", "yes"),
        "authority": authority,
        "client_id": client_id,
        "client_secret": client_secret,
        "metadata": metadata,
        "scopes": scopes,
        "group_map": groups,
        "allow_signup": env("TECHNITIUM_SSO_ALLOW_SIGNUP", "false").lower() in ("1", "true", "yes"),
        "signup_only_for_mapped": env(
            "TECHNITIUM_SSO_SIGNUP_ONLY_FOR_MAPPED_USERS", "true"
        ).lower()
        in ("1", "true", "yes"),
    }


def config_drift(want, have):
    """Every setting that differs, as (name, current, wanted) — the secret excluded.

    The secret is excluded because the console returns it masked, so a comparison
    would report drift on every run and be trained away. It is always sent, which is
    what makes a rotated secret take effect.
    """
    drift = []

    for name, key, current_key in (
        ("enabled", "enabled", "ssoEnabled"),
        ("authority", "authority", "ssoAuthority"),
        ("metadata", "metadata", "ssoMetadataAddress"),
        ("client id", "client_id", "ssoClientId"),
    ):
        current = have.get(current_key)
        if (bool(current) if key == "enabled" else (current or "").rstrip("/")) != (
            bool(want[key]) if key == "enabled" else (want[key] or "").rstrip("/")
        ):
            drift.append((name, current, want[key]))

    current_scopes = list(have.get("ssoScopes") or [])
    if sorted(current_scopes) != sorted(want["scopes"]):
        drift.append(("scopes", ",".join(current_scopes), ",".join(want["scopes"])))

    current_groups = [
        (row.get("remoteGroup"), row.get("localGroup")) for row in (have.get("ssoGroupMap") or [])
    ]
    if sorted(current_groups) != sorted(want["group_map"]):
        drift.append(
            (
                "group map",
                ",".join(f"{r}:{l}" for r, l in current_groups) or "(none)",
                ",".join(f"{r}:{l}" for r, l in want["group_map"]) or "(none)",
            )
        )

    for name, key, current_key in (
        ("allow sign up", "allow_signup", "ssoAllowSignup"),
        ("sign up only for mapped users", "signup_only_for_mapped", "ssoAllowSignupOnlyForMappedUsers"),
    ):
        if bool(have.get(current_key)) != bool(want[key]):
            drift.append((name, bool(have.get(current_key)), bool(want[key])))

    return drift


def set_payload(want):
    """The console's `admin/sso/set` body.

    Its own UI sends the scopes and the group map as pipe-separated tables
    (one field per row, `remote|local` for two columns) and the string `false` when
    no rows exist — so that is what is sent here, rather than a JSON shape the
    endpoint has never seen.
    """
    return {
        "ssoEnabled": "true" if want["enabled"] else "false",
        "ssoAuthority": want["authority"],
        "ssoClientId": want["client_id"],
        "ssoClientSecret": want["client_secret"],
        "ssoMetadataAddress": want["metadata"],
        "ssoScopes": "|".join(want["scopes"]) if want["scopes"] else "false",
        "ssoAllowSignup": "true" if want["allow_signup"] else "false",
        "ssoAllowSignupOnlyForMappedUsers": "true" if want["signup_only_for_mapped"] else "false",
        "ssoGroupMap": "|".join(f"{r}|{l}" for r, l in want["group_map"]) if want["group_map"] else "false",
    }


def provider_callbacks(client_id):
    """The redirect URIs registered for this client in Authentik, or None.

    Read back because the failure it prevents is silent: a callback the provider does
    not know about is refused at the IdP, after the person has already signed in, with
    `redirect_uri does not match` — which reads as a broken console rather than as a
    missing registration. None means "cannot judge", never "fine".
    """
    api = (env("AUTHENTIK_API_URL") or env("AUTHENTIK_ISSUER_URL")).rstrip("/")
    token = env("AUTHENTIK_BOOTSTRAP_TOKEN")
    if not api or not token:
        return None

    try:
        found = http_json(
            f"{api}/api/v3/providers/oauth2/?"
            + urllib.parse.urlencode({"client_id": client_id, "page_size": 50}),
            headers={"Authorization": f"Bearer {token}"},
        )
    except (urllib.error.URLError, OSError, ValueError):
        return None

    results = (found or {}).get("results") or []
    if not results:
        return []
    uris = results[0].get("redirect_uris") or []
    return [entry.get("url") if isinstance(entry, dict) else entry for entry in uris]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="report drift and change nothing")
    args = parser.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(here, "..", ".env"), ".env"):
        load_env_file(path)

    api = env("TECHNITIUM_URL")
    if not api:
        print(f"{FAIL} TECHNITIUM_URL is unset — the console's API address goes there", file=sys.stderr)
        return 2

    want = desired_config()
    missing = [k for k, v in (
        ("AUTHENTIK_TECHNITIUM_CLIENT_ID", want["client_id"]),
        ("AUTHENTIK_TECHNITIUM_CLIENT_SECRET", want["client_secret"]),
        ("SSO_AUTHENTIK_BASE or TECHNITIUM_SSO_AUTHORITY", want["authority"] if env("SSO_AUTHENTIK_BASE") else ""),
    ) if not v]
    if missing:
        print(f"{FAIL} not configured — missing: {', '.join(missing)}", file=sys.stderr)
        print("     create the provider with: python3 scripts/authentik-setup.py technitium", file=sys.stderr)
        return 2

    for label, url in (("authority", want["authority"]), ("metadata", want["metadata"])):
        if not want["enabled"] or url.startswith("https://"):
            continue
        # The console itself warns about this and asks for confirmation. The same
        # warning belongs here, as a refusal: an http authority puts the client
        # secret on the wire in clear text on every sign-in.
        print(f"{FAIL} {label} is not https: {url}", file=sys.stderr)
        print("     set TECHNITIUM_SSO_AUTHORITY with an https origin (or disable SSO)", file=sys.stderr)
        return 2

    print(f"Technitium console: {api}")
    print(f"IdP:               {want['authority']}")
    print(f"Client:            {want['client_id']}")
    print(f"Group map:         " + (", ".join(f"{r}:{l}" for r, l in want["group_map"]) or "(none)"))

    try:
        token = console_token(api)
        have = console(api, "api/admin/sso/get", token=token, params={"includeGroups": "true"})
    except (RuntimeError, urllib.error.URLError, OSError) as error:
        print(f"{FAIL} cannot read the console's SSO settings: {error}", file=sys.stderr)
        print("     the console is loopback + docker0 only — check TECHNITIUM_URL", file=sys.stderr)
        return 2

    callbacks = provider_callbacks(want["client_id"])
    if callbacks is None:
        print(f"{FAIL} cannot read the provider's callbacks from Authentik", file=sys.stderr)
        print("     set AUTHENTIK_API_URL + AUTHENTIK_BOOTSTRAP_TOKEN, or register the", file=sys.stderr)
        print(f"     callback by hand: {env('AUTHENTIK_TECHNITIUM_REDIRECT_URI', '<name>/sso/callback')}", file=sys.stderr)
        return 2
    if not callbacks:
        print(f"{FAIL} provider '{want['client_id']}' is not in Authentik", file=sys.stderr)
        print("     create it with: python3 scripts/authentik-setup.py technitium", file=sys.stderr)
        return 2

    expected_callback = env("AUTHENTIK_TECHNITIUM_REDIRECT_URI")
    if expected_callback and expected_callback not in callbacks:
        print(f"{FAIL} {expected_callback} is not registered on provider '{want['client_id']}'", file=sys.stderr)
        print(f"     registered: {', '.join(str(u) for u in callbacks)}", file=sys.stderr)
        print("     re-run: python3 scripts/authentik-setup.py technitium", file=sys.stderr)
        return 2

    drift = config_drift(want, have)
    local_groups = have.get("localGroups") or []
    for _, wanted_group in want["group_map"]:
        if wanted_group not in local_groups:
            print(f"{FAIL} local group '{wanted_group}' does not exist on the console", file=sys.stderr)
            print(f"     it has: {', '.join(local_groups) or '(none)'}", file=sys.stderr)
            return 2

    if args.check:
        if not drift:
            print(f"{OK} the console's SSO matches this deployment")
            print("     (the client secret is not compared — the console returns it masked)")
            return 0
        for name, current, wanted in drift:
            print(f"{DRIFT} {name}: {current!r} -> {wanted!r}")
        return 1

    if not drift:
        print(f"{OK} already configured; nothing to change")
        print("     (the client secret is re-sent, so a rotated one takes effect here)")
    else:
        for name, current, wanted in drift:
            print(f"{DRIFT} {name}: {current!r} -> {wanted!r}")

    try:
        console(api, "api/admin/sso/set", token=token, params=set_payload(want))
    except (RuntimeError, urllib.error.URLError, OSError) as error:
        print(f"{FAIL} the console refused the change: {error}", file=sys.stderr)
        return 1

    # Read back rather than trust the write: `set` answers `ok` for a body it stored
    # and one it silently dropped a field from, and the difference is a sign-in that
    # fails at the callback.
    after = console(api, "api/admin/sso/get", token=token, params={"includeGroups": "true"})
    remaining = config_drift(want, after)
    if remaining:
        for name, current, wanted in remaining:
            print(f"{FAIL} {name} did not take: {current!r} (wanted {wanted!r})", file=sys.stderr)
        return 1

    print(f"{OK} the console now signs in through {want['authority']}")
    print(f"     open {env('AUTHENTIK_TECHNITIUM_REDIRECT_URI', 'https://dns.internal.innotel.us/')}")
    print("     the local admin password still works — Technitium keeps its own form")
    print("     beside the OpenID Connect button, which is the way back in if DNS breaks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
