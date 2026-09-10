# Zeus → Cerulean Authentik migration

Zeus PBX was pointed at a standalone Authentik env. Its OIDC config now lives
here: this repo's bundled Authentik (ghcr.io/goauthentik with postgres+redis).

* Provider 23 `zeus` (confidential, client_id `zeus`) backs application
  `zeus` / `Zeus PBX` (group `Zeus`). NPM proxy host `auth.zeus` already
  routes https://auth.zeus.innotel.us → 192.168.1.46:9000 — Same instance that handles
  cerulean, capstone, magnate, oasis, onyx, rizz etc. No new realm or
  postgres cluster.

* Zeus uses `ZEUS_*` env vars in this repo's .env (issuer, client_id,
  provider id). The old standalone .env on 192.168.1.80/zeus-pbx-platform
  should be removed.

* All `zeus.innotel.us`, `app/api/portal/ws` hosts share ssl=135 (wildcard)
  and forward at 192.168.1.46; no NPM change needed.
