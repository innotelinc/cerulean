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
AUTHENTIK_ISSUER_URL=http://auth.cerulean.innotel.us
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
