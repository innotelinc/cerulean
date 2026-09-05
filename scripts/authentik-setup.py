#!/usr/bin/env python3
"""authentik-setup.py — provision the Cerulean OIDC provider in Authentik.

Creates (or updates) an OIDC provider and application in Authentik so that
Cerulean can sign users in via the authorization-code flow. Idempotent: run it
any time after .env changes.

Reads .env (repo root) when run standalone, or the environment when run from
setup.sh.

Required (in .env):
    AUTHENTIK_API_URL          Authentik instance, e.g. http://localhost:9000
                               (defaults to AUTHENTIK_ISSUER_URL)
    AUTHENTIK_BOOTSTRAP_TOKEN  Authentik bootstrap API token (Bearer auth; the
                               admin-login endpoint was removed in Authentik
                               2024.12, so provisioning uses the bootstrap
                               token instead of AUTHENTIK_ADMIN_PASSWORD)
    AUTHENTIK_ADMIN_USER       Authentik admin username (default: akadmin)
    AUTHENTIK_ADMIN_PASSWORD   Authentik admin password (kept for docs)
    AUTHENTIK_CLIENT_ID        desired OIDC client id (default: cerulean)
    AUTHENTIK_CLIENT_SECRET    OIDC client secret (generate one)
    AUTHENTIK_REDIRECT_URI     Cerulean's OIDC callback URL

Optional:
    AUTHENTIK_APP_SLUG         application slug (default: cerulean)
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


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


# ── Authentik API client ────────────────────────────────────────────────────
class Authentik:
    def __init__(self, base_url, token):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _request(self, method, path, body=None):
        url = f"{self.base_url}/api/v3{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode()
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace") if err.fp else ""
            return err.code, (json.loads(detail) if detail else {})

    def list(self, path):
        _, data = self._request("GET", path)
        if not data:
            return []
        return data.get("results", data if isinstance(data, list) else [])

    def create(self, path, body):
        status, data = self._request("POST", path, body)
        if status not in (200, 201):
            raise RuntimeError(f"Authentik POST {path} failed (HTTP {status}): {json.dumps(data)}")
        return data

    def update(self, path, body):
        status, data = self._request("PUT", path, body)
        if status not in (200, 204):
            raise RuntimeError(f"Authentik PUT {path} failed (HTTP {status}): {json.dumps(data)}")
        return data


def login(base_url, username, password):
    body = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/v3/core/auth/admin/",
        data=body,
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as err:
        detail = err.read().decode(errors="replace") if err.fp else ""
        raise RuntimeError(
            f"Authentik admin login failed (HTTP {err.code}): {detail} — "
            "check AUTHENTIK_ADMIN_USER/AUTHENTIK_ADMIN_PASSWORD"
        ) from err
    token = data.get("token")
    if not token:
        raise RuntimeError("Authentik returned no admin token")
    return token


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(here, "..", ".env"), ".env"):
        load_env_file(path)

    issuer = env("AUTHENTIK_ISSUER_URL")
    api_url = env("AUTHENTIK_API_URL", issuer).rstrip("/")
    admin_user = env("AUTHENTIK_ADMIN_USER", "akadmin")
    admin_password = env("AUTHENTIK_ADMIN_PASSWORD")
    bootstrap_token = env("AUTHENTIK_BOOTSTRAP_TOKEN")
    client_id = env("AUTHENTIK_CLIENT_ID", "cerulean")
    client_secret = env("AUTHENTIK_CLIENT_SECRET")
    redirect_uri = env("AUTHENTIK_REDIRECT_URI")
    app_slug = env("AUTHENTIK_APP_SLUG", "cerulean")

    missing = [k for k, v in [
        ("AUTHENTIK_ISSUER_URL", api_url),
        ("AUTHENTIK_BOOTSTRAP_TOKEN", bootstrap_token),
        ("AUTHENTIK_CLIENT_SECRET", client_secret),
        ("AUTHENTIK_REDIRECT_URI", redirect_uri),
    ] if not v]
    if missing:
        print(f"Authentik is not fully configured — missing: {', '.join(missing)}", file=sys.stderr)
        return 2

    print(f"Authentik: {api_url}")
    print(f"Client: {client_id}   Redirect URI: {redirect_uri}")

    # Authentik 2024.12 removed the POST /api/v3/core/auth/admin/ endpoint, so
    # authenticate with the bootstrap API token instead of an admin password.
    ak = Authentik(api_url, bootstrap_token)

    # Authorization flow used by the provider (built-in "implicit consent" flow).
    flows = ak.list("/flows/instances/?ordering=-pk")
    auth_flow = next(
        (f for f in flows if f.get("slug") == "default-provider-authorization-implicit-consent"),
        flows[0] if flows else None,
    )
    if not auth_flow:
        print("No authorization flow found in Authentik — create one first.", file=sys.stderr)
        return 1
    auth_flow_pk = auth_flow["pk"]

    # Invalidation flow is required in Authentik 2024.12.
    invalidation_flow = next(
        (f for f in ak.list("/flows/instances/?slug=default-provider-invalidation-flow") if f.get("slug")),
        None,
    )
    if not invalidation_flow:
        print("No default-provider-invalidation-flow found in Authentik.", file=sys.stderr)
        return 1

    # Find the existing provider (by client_id) or create it.
    providers = ak.list(f"/providers/oauth2/?client_id={urllib.parse.quote(client_id)}")
    provider = providers[0] if providers else None
    provider_body = {
        "name": "Cerulean",
        "authorization_flow": auth_flow_pk,
        "invalidation_flow": invalidation_flow["pk"],
        "client_type": "confidential",
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uris": [{"matching_mode": "strict", "url": redirect_uri}],
        "sub_mode": "hashed_user_id",
        "issuer_mode": "global",
        "include_claims_in_id_token": True,
    }
    if provider:
        ak.update(f"/providers/oauth2/{provider['pk']}/", provider_body)
        provider_pk = provider["pk"]
        print(f"  ✓ updated OIDC provider (pk {provider_pk}) with redirect {redirect_uri}")
    else:
        created = ak.create("/providers/oauth2/", provider_body)
        provider_pk = created["pk"]
        print(f"  ✓ created OIDC provider (pk {provider_pk})")

    # Ensure the application is bound to the provider (URL key is the slug).
    apps = ak.list(f"/core/applications/?slug={urllib.parse.quote(app_slug)}")
    app_body = {"name": "Cerulean", "slug": app_slug, "provider": provider_pk}
    if apps:
        ak.update(f"/core/applications/{app_slug}/", app_body)
        print(f"  ✓ updated application '{app_slug}'")
    else:
        ak.create("/core/applications/", app_body)
        print(f"  ✓ created application '{app_slug}'")

    print()
    print("Done. Sign in to Authentik once as an admin, then open")
    print(f"  {redirect_uri}")
    print("— the Cerulean login page now offers 'Sign in with Authentik'.")
    print()
    print("Users/groups are managed in Authentik; the provider is 'Cerulean'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
