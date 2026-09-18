#!/usr/bin/env python3
"""authentik-conform-providers.py — make every OIDC provider follow one standard.

Cerulean Authentik is the platform's only login. Every app that signs a user in
does it against an Authentik OAuth2 provider, either directly (Distro, Studio) or
through an oauth2-proxy gateway (the media apps, Grafana, Vault's UI). Those
providers were created over time and drifted, and the drift is not cosmetic:

  * Authentik's DEFAULT email mapping returns ``{"email": ..., "email_verified":
    False}``. oauth2-proxy refuses an id_token whose email is not verified — the
    callback dies with HTTP 500 — unless every gateway is told
    ``--insecure-oidc-allow-unverified-email``. That workaround lives in a dozen
    `.env` files and is a duplicate of a problem that belongs to one place.
  * Some providers were created without the groups mapping, so group-based
    authorization (`OAUTH2_PROXY_ALLOWED_GROUPS`, Distro entitlements, the
    Jellyfin `paid_users` filter) silently authorizes nobody or everybody.
  * Providers were split between the two issuer modes. A provider on `global`
    publishes the bare Authentik base as `iss`, but every relying party in the
    estate — every oauth2-proxy gateway, Distro, Magnate, Zeus — is configured
    with the app-scoped issuer, so those sign-ins die at the callback with
    HTTP 500. One mode, `per_provider`, is the standard.

This script is the one place that fixes both, for every provider at once:

    standard mappings = openid + profile + email(email_verified: true) + groups

It ADDS what is missing, REMOVES the default `email` mapping it replaces
(leaving another mapping with the same scope name is the bug, not the fix), and
keeps every other mapping a provider already carries — the NPM forward-auth
providers keep their Entitlements and Proxy-outpost mappings.

Idempotent. Dry-run by default; pass --apply to write.

    python3 scripts/authentik-conform-providers.py            # show the plan
    python3 scripts/authentik-conform-providers.py --apply    # write it
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

# The one issuer mode every provider uses. Authentik puts `iss` in the id_token,
# and every relying party in the estate is configured with the APP-SCOPED issuer
# (<base>/application/o/<app-slug>/). A provider left on `global` publishes the
# bare base instead, and the client then refuses the token — oauth2-proxy turns
# that into HTTP 500 on /oauth2/callback:
#
#   oidc: id token issued by a different provider,
#   expected "https://auth.cerulean.innotel.us/application/o/npm-edge/"
#   got      "https://auth.cerulean.innotel.us/"
#
# Measured on oauth2-proxy v7.8.2. The same mismatch closes Distro's, Magnate's
# and Zeus's OIDC sign-in, whose configured issuers are already app-scoped.
ISSUER_MODE = "per_provider"

GROUPS_MAPPING_NAME = "Innotel OAuth Mapping: OpenID 'groups'"
EMAIL_MAPPING_NAME = "Innotel OAuth Mapping: OpenID 'email'"
DEFAULT_EMAIL_NAME = "authentik default OAuth Mapping: OpenID 'email'"
DEFAULT_OPENID_NAME = "authentik default OAuth Mapping: OpenID 'openid'"
DEFAULT_PROFILE_NAME = "authentik default OAuth Mapping: OpenID 'profile'"

GROUPS_EXPRESSION = (
    "return {\n"
    '    "groups": [g.name for g in user.ak_groups.all()],\n'
    '    "is_superuser": user.is_superuser,\n'
    "}"
)
# Every account on this stack is created and verified through Authentik itself,
# so its email IS verified. Reporting False (Authentik's default) makes every
# OIDC relying party reject the token; this is the claim that fixes that for all
# of them at once.
EMAIL_EXPRESSION = (
    "return {\n"
    '    "email": request.user.email,\n'
    '    "email_verified": True,\n'
    "}"
)


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def load_env_file(path: str) -> None:
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
            key, value = key.strip(), value.strip().strip("\"'")
            if key and key not in os.environ:
                os.environ[key] = value


class Authentik:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(self, method: str, path: str, body=None, params=None):
        url = f"{self.base_url}/api/v3{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode()
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace") if err.fp else ""
            return err.code, detail

    def list(self, path: str, **params):
        status, data = self.request("GET", path, params={"page_size": 200, **params})
        if status != 200 or not isinstance(data, dict):
            return []
        return data.get("results", [])

    def ensure_scope_mapping(self, name: str, scope_name: str, expression: str, apply: bool):
        found = next((m for m in self.list("/propertymappings/provider/scope/") if m.get("name") == name), None)
        body = {"name": name, "scope_name": scope_name, "expression": expression}
        if found:
            if apply:
                self.request("PUT", f"/propertymappings/provider/scope/{found['pk']}/", body)
            return found["pk"], "updated"
        if not apply:
            return None, "would create"
        status, created = self.request("POST", "/propertymappings/provider/scope/", body)
        if status not in (200, 201) or not isinstance(created, dict):
            raise RuntimeError(f"creating scope mapping {name!r} failed (HTTP {status}): {created}")
        return created["pk"], "created"


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    load_env_file(os.path.join(here, "..", ".env"))

    parser = argparse.ArgumentParser(description="Conform every Authentik OAuth2 provider to the standard scope mappings.")
    parser.add_argument("--apply", action="store_true", help="write the changes (default: print the plan)")
    args = parser.parse_args()

    api_url = env("AUTHENTIK_API_URL", env("AUTHENTIK_ISSUER_URL")).rstrip("/")
    token = env("AUTHENTIK_BOOTSTRAP_TOKEN")
    if not api_url or not token:
        print("AUTHENTIK_API_URL and AUTHENTIK_BOOTSTRAP_TOKEN are required (set them in .env or the environment).", file=sys.stderr)
        return 2

    ak = Authentik(api_url, token)
    print(f"Authentik: {api_url}   mode: {'APPLY' if args.apply else 'dry-run'}")

    mappings = {m.get("name"): m for m in ak.list("/propertymappings/provider/scope/")}
    groups_pk, groups_state = ak.ensure_scope_mapping(
        GROUPS_MAPPING_NAME, "groups", GROUPS_EXPRESSION, args.apply)
    email_pk, email_state = ak.ensure_scope_mapping(
        EMAIL_MAPPING_NAME, "email", EMAIL_EXPRESSION, args.apply)
    print(f"  groups mapping: {groups_state}")
    print(f"  email  mapping: {email_state}")

    # Look up the standard mappings again when this is a dry run (they may not
    # exist yet) so the per-provider plan still names the pks it would use.
    if not args.apply:
        mappings = {m.get("name"): m for m in ak.list("/propertymappings/provider/scope/")}
        groups_pk = groups_pk or (mappings.get(GROUPS_MAPPING_NAME) or {}).get("pk")
        email_pk = email_pk or (mappings.get(EMAIL_MAPPING_NAME) or {}).get("pk")
    mappings = {m.get("name"): m for m in ak.list("/propertymappings/provider/scope/")}
    default_email_pk = (mappings.get(DEFAULT_EMAIL_NAME) or {}).get("pk")
    openid_pk = (mappings.get(DEFAULT_OPENID_NAME) or {}).get("pk")
    profile_pk = (mappings.get(DEFAULT_PROFILE_NAME) or {}).get("pk")

    providers = ak.list("/providers/oauth2/")
    changed = 0
    for provider in providers:
        pk = provider.get("pk")
        name = provider.get("name")
        current = list(provider.get("property_mappings") or [])
        want = set(current)
        # Add the standard set (openid/profile may already be present).
        for value in (openid_pk, profile_pk, email_pk, groups_pk):
            if value:
                want.add(value)
        # Drop the default email mapping we replace — two mappings on one scope
        # is the drift this exists to remove.
        if default_email_pk and default_email_pk != email_pk:
            want.discard(default_email_pk)

        mode = provider.get("issuer_mode")
        body = {}
        if want != set(current):
            body["property_mappings"] = sorted(want)
        if mode != ISSUER_MODE:
            body["issuer_mode"] = ISSUER_MODE

        if not body:
            print(f"  ok       {name} (pk {pk})")
            continue

        notes = []
        if "property_mappings" in body:
            notes.append("+%s" % [mappings_by_pk(mappings, p) for p in sorted(want - set(current))]
                         if want - set(current) else "")
            removed = [mappings_by_pk(mappings, p) for p in sorted(set(current) - want)]
            if removed:
                notes.append("-%s" % removed)
        if "issuer_mode" in body:
            notes.append(f"issuer_mode {mode} -> {ISSUER_MODE}")

        print(f"  {'update' if args.apply else 'would fix'}   {name} (pk {pk})"
              + ("  " + " ".join(n for n in notes if n) if notes else ""))
        if args.apply:
            status, _ = ak.request("PATCH", f"/providers/oauth2/{pk}/", body)
            if status not in (200, 204):
                print(f"      PATCH failed (HTTP {status})", file=sys.stderr)
                continue
        changed += 1

    print()
    print(f"{changed} provider(s) {'updated' if args.apply else 'to update'}.")
    if not args.apply and changed:
        print("re-run with --apply to write it.")
    elif args.apply:
        # Re-read rather than trust the writes. Both halves are checked: an
        # earlier version verified only the issuer mode, so six providers whose
        # mapping PATCH had not taken were still reported as conforming — which
        # is precisely the drift this script exists to remove.
        after = ak.list("/providers/oauth2/")
        live = {m.get("pk"): m.get("name") for m in ak.list("/propertymappings/provider/scope/")}
        standard = {openid_pk, profile_pk, email_pk, groups_pk} - {None}
        off_mode, off_mappings = [], []
        for provider in after:
            if provider.get("issuer_mode") != ISSUER_MODE:
                off_mode.append(provider.get("name"))
            current = set(provider.get("property_mappings") or [])
            if not standard <= current or (default_email_pk and default_email_pk in current):
                missing = [live.get(pk, pk) for pk in sorted(standard - current)]
                extra = [live.get(pk, pk) for pk in sorted(current - (current - {default_email_pk}))]
                off_mappings.append(f"{provider.get('name')} (missing {missing or '-'}; default email {extra or '-'})")
        if off_mode:
            print(f"still not on issuer_mode={ISSUER_MODE}: {', '.join(off_mode)}", file=sys.stderr)
        if off_mappings:
            print("still not carrying the standard mappings:", file=sys.stderr)
            for line in off_mappings:
                print(f"  {line}", file=sys.stderr)
        if off_mode or off_mappings:
            return 1
        print(f"verified: all {len(after)} provider(s) publish issuer_mode={ISSUER_MODE} "
              "and carry openid + profile + the Innotel email/groups mappings")
    return 0


def mappings_by_pk(mappings: dict, pk) -> str:
    for name, mapping in mappings.items():
        if mapping.get("pk") == pk:
            return name
    return str(pk)


if __name__ == "__main__":
    sys.exit(main())
