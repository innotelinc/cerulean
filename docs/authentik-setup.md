# Authentik setup (SSO / user management)

Cerulean authenticates users against **Authentik** with an OIDC
authorization-code + PKCE flow. Users and groups are managed in Authentik; the
portal just consumes identity (subject, email, name, groups) from the
userinfo endpoint.

## Start Authentik

Authentik is bundled as an opt-in compose profile (server + worker +
PostgreSQL + Redis):

```bash
# First: set AUTHENTIK_SECRET_KEY and AUTHENTIK_POSTGRESQL_PASSWORD in .env
docker compose --profile authentik up -d
```

The web UI is at `http://<host>:9000` (HTTPS on 9443). With nginx proxy
manager provisioned, `auth.cerulean.innotel.us` fronts it on port 9000.

On the very first boot, create the admin account:

```bash
docker compose --profile authentik exec authentik-server ak createsuperuser
```

or set `AUTHENTIK_BOOTSTRAP_PASSWORD` in `.env` *before* the first start, which
creates the `akadmin` superuser automatically.

## Provision the OIDC provider

`scripts/authentik-setup.py` creates (or updates) an OIDC provider and
application named **Cerulean**, using these `.env` values:

```dotenv
AUTHENTIK_ISSUER_URL=https://auth.cerulean.innotel.us
AUTHENTIK_CLIENT_ID=cerulean
AUTHENTIK_CLIENT_SECRET=<long random string>
AUTHENTIK_REDIRECT_URI=http://cerulean.innotel.us/api/auth/oidc/callback
AUTHENTIK_ADMIN_USER=akadmin
AUTHENTIK_ADMIN_PASSWORD=<the admin password>
```

Then run:

```bash
./scripts/setup.sh --with-authentik
# or, if the stack is already up:
python3 scripts/authentik-setup.py
```

The script logs into Authentik's API, finds (or creates) the authorization
flow, the OIDC provider with the configured `redirect_uris`, and the
application bound to it. It is idempotent — re-run after any `.env` change.

`setup.sh --with-authentik` also generates a client secret if
`AUTHENTIK_CLIENT_SECRET` is unset and writes the values into `.env`.

### Other applications (one provider each)

The same script takes a slug as its first argument and then reads
`AUTHENTIK_<SLUG-UPPER>_*` instead of the unprefixed names, so every relying
party gets its own client in one `.env`:

```bash
python3 scripts/authentik-setup.py technitium   # the DNS/DHCP console
python3 scripts/authentik-setup.py dograh       # a product's own app
```

`setup.sh --with-authentik` does this for the Technitium console too
(`AUTHENTIK_TECHNITIUM_*`), and then points the console's own sign-in at it —
the console is a relying party, not just a host behind a gateway. See
[The Technitium console's own sign-in](#the-technitium-consoles-own-sign-in)
below.

## The Technitium console's own sign-in

The console is behind an `oauth2-proxy` gateway at `dns.internal.innotel.us`,
which is what keeps it off the LAN (it binds loopback + docker0 only). A gateway
is not enough by itself: it proves *someone* signed in and can never tell the
console *who*, so the console would keep an admin password of its own — the DNS
and DHCP admin plane with a credential that Authentik does not know about.

Technitium speaks OIDC itself (Settings → Single Sign-On), and
`scripts/technitium-sso.py` is what configures it:

```dotenv
TECHNITIUM_SSO_ENABLED=true
TECHNITIUM_SSO_SCOPES=openid,profile,email,groups
TECHNITIUM_SSO_GROUP_MAP=cerulean-platform:Administrators
TECHNITIUM_SSO_ALLOW_SIGNUP=false
TECHNITIUM_SSO_SIGNUP_ONLY_FOR_MAPPED_USERS=true
```

```bash
python3 scripts/technitium-sso.py           # configure it (idempotent)
python3 scripts/technitium-sso.py --check   # report drift, change nothing
```

The authority is the *application-scoped* issuer
(`<SSO_AUTHENTIK_BASE>/application/o/technitium/`), not the IdP root:
Authentik advertises its base URL as the issuer while an application's endpoints
live under `/application/o/<slug>/`. The script also reads the provider back
from Authentik and refuses to write a configuration whose callback is not
registered — that failure is otherwise a sign-in that dies at the IdP *after*
the password has been entered.

Two things worth knowing:

- **The local admin login stays.** Technitium shows its own form beside the
  OpenID Connect button, and that is deliberate: DNS is what resolves the IdP, so
  an SSO-only console is a console nobody can reach when DNS is the thing that
  broke. The password is the break-glass, and the group map is what makes the
  SSO path an *administrator* rather than a read-only account.
- **The client secret is never compared.** The console returns it masked
  (`************`), so `--check` cannot see a rotated one; every run re-sends it,
  which is what makes a rotation take effect.

## Sign in

Open the Cerulean dashboard. The login page shows **Sign in with Authentik**
next to the admin-password fallback. After the redirect round-trip you are
signed in; the sidebar shows your name and email from Authentik.

To make Authentik the *only* way in, set `AUTH_LOCAL_ENABLED=0` in `.env`
(the admin password is still required in `.env` — the server refuses to start
without it — it just stops being a login option).

## Groups

The provider includes the `groups` claim in userinfo by default, so Cerulean
can see which Authentik groups a user belongs to (`GET /api/auth/me`). Group
checks can be added to the server routes later; Authentik remains the single
source of truth for who is who.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Login page has no Authentik button | `AUTHENTIK_ISSUER_URL`/`CLIENT_ID`/`CLIENT_SECRET` not all set |
| Redirect URI error in Authentik | `AUTHENTIK_REDIRECT_URI` doesn't match the registered value exactly |
| "Invalid or expired OIDC state" | PKCE state timed out (10 min) or the callback was replayed |
| `authentik-setup.py` fails | `AUTHENTIK_ADMIN_PASSWORD` wrong, or Authentik not up yet |
