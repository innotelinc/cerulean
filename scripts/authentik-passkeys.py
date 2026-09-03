#!/usr/bin/env python3
"""authentik-passkeys.py — enable passkeys (WebAuthn) in Authentik (CE).

Binds an "Authenticator validation" stage that accepts WebAuthn devices into
the default authentication flow, so users who have enrolled a passkey
authenticate with it instead of (or in addition to) a password, while users
without one are skipped (nothing breaks).

Passkeys are fully supported by the Community Edition; this script only wires
the built-in stages together. Enrollment itself happens in the user's own
Authentik settings (User settings → MFA devices → Enroll WebAuthn device) or
through the default WebAuthn setup flow.

Idempotent: stages and bindings are created only when missing; re-running is
safe. Read .env (repo root) when run standalone, or the environment when run
from setup.sh.

Required (in .env):
    AUTHENTIK_API_URL          Authentik instance, e.g. http://localhost:9000
                               (defaults to AUTHENTIK_ISSUER_URL)
    AUTHENTIK_ADMIN_USER       Authentik admin username (default: akadmin)
    AUTHENTIK_ADMIN_PASSWORD   Authentik admin password

Optional:
    AUTHENTIK_PASSKEY_FLOW     authentication flow to bind into
                               (default: default-authentication-flow)

Notes:
  * Written against the bundled Authentik image (AUTHENTIK_IMAGE_TAG, 2024.12).
    The /api/v3 stage endpoints drift between releases — if a create call
    returns 400 with an unknown-field error, upgrade the bundled image or
    create the stage manually in the UI (Flows & Stages → Stages → New stage →
    Authenticator Validation → device classes: WebAuthn) and re-run the script
    — it will detect the existing stage by name and just add the binding.
  * For passwordless-first login (no password prompt at all), add a second
    stage binding of the same validation stage at order 0 in front of the
    identification stage instead — out of scope here, see Authentik docs.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

STAGE_NAME = "Cerulean — Passkeys (WebAuthn)"


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


# ── Authentik API client (same shape as authentik-setup.py) ─────────────────
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
            raise RuntimeError(
                f"Authentik POST {path} failed (HTTP {status}): {json.dumps(data)}"
            )
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
    flow_slug = env("AUTHENTIK_PASSKEY_FLOW", "default-authentication-flow")

    if not api_url or not admin_password:
        print(
            "Authentik is not fully configured — set AUTHENTIK_ISSUER_URL and "
            "AUTHENTIK_ADMIN_PASSWORD in .env",
            file=sys.stderr,
        )
        return 2

    print(f"Authentik: {api_url}   Flow: {flow_slug}")

    token = login(api_url, admin_user, admin_password)
    ak = Authentik(api_url, token)

    # The authentication flow to bind the passkey stage into.
    flows = ak.list(f"/flows/?slug={urllib.parse.quote(flow_slug)}")
    if not flows:
        print(
            f"Flow '{flow_slug}' not found — set AUTHENTIK_PASSKEY_FLOW to the "
            "slug of your authentication flow",
            file=sys.stderr,
        )
        return 1
    flow_pk = flows[0]["pk"]

    # 1. Ensure the WebAuthn validation stage exists (find by exact name).
    existing = ak.list(f"/stages/authenticator/validate/?name={urllib.parse.quote(STAGE_NAME)}")
    if existing:
        stage = existing[0]
        stage_pk = stage["pk"]
        print(f"  ✓ validation stage already exists (pk {stage_pk})")
    else:
        created = ak.create(
            "/stages/authenticator/validate/",
            {
                "name": STAGE_NAME,
                "friendly_name": "Sign in with a passkey",
                "device_classes": ["webauthn"],
                # Users without a passkey are not forced to enroll — passkey
                # login is an alternative, not a requirement.
                "not_configured_action": "skip",
            },
        )
        stage_pk = created["pk"]
        print(f"  ✓ created WebAuthn validation stage (pk {stage_pk})")

    # 2. Bind it into the flow (once) at the end of the current stage order,
    #    i.e. after the password step, acting as the WebAuthn factor.
    bindings = ak.list(f"/flows/bindings/?target={urllib.parse.quote(str(flow_pk))}")
    if any(b.get("stage") == stage_pk for b in bindings):
        print("  ✓ stage already bound to the flow")
    else:
        order = max([int(b.get("order", 0)) for b in bindings] or [0]) + 10
        ak.create(
            "/flows/bindings/",
            {
                "target": flow_pk,
                "stage": stage_pk,
                "order": order,
                "evaluate_on_plan": True,
            },
        )
        print(f"  ✓ bound validation stage into '{flow_slug}' at order {order}")

    print()
    print("Done. Passkeys are enabled in the Community Edition.")
    print()
    print("Next steps:")
    print(f"  1. Each user enrolls a passkey: sign in to {api_url}, then")
    print("     User settings → MFA devices → Enroll WebAuthn device (browser, platform key).")
    print("  2. From then on, that user signs in to the Cerulean portal with the")
    print("     passkey (validated at the Authentik flow) instead of a password.")
    print("  3. To make passkeys the ONLY factor, edit the flow in the UI and")
    print("     remove the password stage — see the script docstring.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
