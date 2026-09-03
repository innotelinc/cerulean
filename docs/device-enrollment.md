# Device enrollment & mTLS auto-allow

Cerulean's internal PKI (`PKI & Devices` in the dashboard, `/api/pki/*`) exists
to answer one question at the reverse proxy:

> *Is this device one of ours?*

The answer — "yes" — is a TLS **client certificate** signed by Cerulean's
internal root CA. This guide covers how devices get those certificates and how
nginx proxy manager uses them to let trusted devices straight through
(**auto-allow**) while rejecting everything else, with no application changes.

```
                    ┌──────────────┐   client cert    ┌──────────────┐
   managed device ─▶│ nginx proxy  │◀─────────────────│  Cerulean CA │
   (Mac, laptop)    │ manager      │   (SCEP / CSR)   │  (internal)  │
                    └──────┬───────┘                  └──────────────┘
                           │ valid cert → proxied (auto-allowed)
                           │ no/invalid cert → rejected at TLS
                           ▼
                      your service
```

## Pieces

| Piece | Where | What it does |
| --- | --- | --- |
| Root CA | Cerulean (`POST /api/pki/init`, or lazily) | Signs every device certificate. Its PEM is the trust anchor. |
| Device certificate | Cerulean (`/api/pki/certificates`) | Per device, `clientAuth` EKU. Issued by the portal (key held by Cerulean) **or** enrolled from a CSR (key never leaves the device). |
| Enrollment profile | Cerulean (`GET /api/pki/enrollment/profile?name=…`) | Apple `.mobileconfig`: installs the root CA + asks the device for a certificate via SCEP. Push through your MDM. |
| Auto-allow gate | nginx proxy manager (`POST /api/npm/mtls`) | Demands a client cert signed by the Cerulean CA on a proxy host. |

## 1. Initialize the CA and issue certificates

Either in the dashboard (**PKI & Devices**) or:

```bash
TOKEN=$(curl -s -X POST localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"password":"your-admin-password"}' | jq -r .token)

# Generate the root CA (idempotent)
curl -s -X POST localhost:3000/api/pki/init -H "Authorization: Bearer $TOKEN"

# Portal-issued (Cerulean generates and holds the key) — for servers/services:
curl -s -X POST localhost:3000/api/pki/certificates \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"db-server-1"}'

# CSR-enrolled (the device keeps its key) — the standard for laptops/MDM:
openssl ecparam -name prime256v1 -genkey -noout -out laptop-1.key
openssl req -new -key laptop-1.key -subj "/CN=laptop-1" -out laptop-1.csr
CSR=$(sed ':a;N;$!ba;s/\n/\\n/g' laptop-1.csr)
curl -s -X POST localhost:3000/api/pki/enroll/csr \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"csr\": \"$CSR\"}"
```

CSR-enrolled certificates are stored **without** the private key — the key stays
on the machine that generated the CSR. Revocation, listing, and re-issue work
exactly like portal-issued ones (a name can have only one active certificate;
revoke first to re-issue under the same name).

Supported CSR keys: ECDSA P-256/P-384/P-521 and RSA ≥ 2048.

## 2. Install the CA as a trust anchor

Download the CA once and install it everywhere a device certificate must be
accepted (the reverse proxy, your apps):

```bash
curl -s localhost:3000/api/pki/ca -H "Authorization: Bearer $TOKEN" | jq -r .certificate > cerulean-ca.pem
```

## 3. Enroll devices through MDM (SCEP)

The dashboard's **PKI & Devices → Enroll devices through MDM (SCEP)** panel
downloads an Apple configuration profile for a device. The profile:

1. installs the Cerulean root CA as a **trust anchor** (`com.apple.security.root`), and
2. contains a **SCEP payload** (`com.apple.security.scep`) pointing at the SCEP
   endpoint in `PKI_SCEP_URL` (`PKI_SCEP_CA_NAME` / `PKI_SCEP_CHALLENGE` are
   optional and embedded too).

Push the profile to a managed Mac through **fleet**, **MicroMDM**, or any MDM —
or install it manually. The device generates a keypair, sends its CSR to the
SCEP endpoint, and installs the certificate it gets back. nginx then recognizes
the device.

### Running an SCEP server

Cerulean does not bundle an SCEP server; it provides the CA operation SCEP
fronts perform (`POST /api/pki/enroll/csr`) and the profile that points devices
at your SCEP URL. Set `PKI_SCEP_URL` to whichever SCEP server you run:

- **Cert-manager / smallstep step-ca** — the actively maintained SCEP server the
  ecosystem recommends (micromdm/scep explicitly points here). It issues under
  its own CA; to keep "signed by the Cerulean CA" semantics end-to-end, wire its
  RA/CSR flow to Cerulean's `/api/pki/enroll/csr`, or trust step-ca's root in
  nginx *in addition to* Cerulean's.
- **Microsoft NDES** — for Windows/Intune estates, point `PKI_SCEP_URL` at the
  NDES `/certsrv/mscep` endpoint.
- Scripted enrollment needs no SCEP at all: generate a keypair + CSR on the
  device and call `/api/pki/enroll/csr` (see §1) — e.g. from a setup script or
  MDM `Exec` payload.

Whichever SCEP server signs, the auto-allow gate in §4 must trust *that* CA's
certificate. Cerulean's own endpoint materializes **its** CA automatically in
local mode.

## 4. Auto-allow at nginx proxy manager

Once a device holds a certificate, enable the TLS gate on the proxy host(s)
that should accept it. With the bundled NPM (`NPM_MODE=local`):

```bash
curl -s -X POST localhost:3000/api/npm/mtls \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"mode":"on","hosts":["app.cerulean.innotel.us","auth.cerulean.innotel.us"]}'
```

What this does:

1. Writes the current root CA to the shared data dir
   (`./data/npm/cerulean-client-ca.pem` → `/data/cerulean-client-ca.pem` inside
   NPM) — **local mode only**.
2. Adds to each host's custom nginx config a marker-delimited block:

```nginx
# cerulean-mtls
ssl_client_certificate /data/cerulean-client-ca.pem;
ssl_verify_client on;
# /cerulean-mtls
```

With `ssl_verify_client on`, nginx **auto-allows** any request presenting a
valid Cerulean-signed certificate and rejects everything else at the TLS layer —
the app behind the proxy never sees unauthenticated traffic. `{"mode":"off"}`
strips the block (your own custom nginx config is preserved; the block is
idempotent and marker-delimited).

Prerequisites:

- The host must already have an SSL certificate of its own (`certificate_id`),
  since client certificates ride on the same TLS session. Issue one for its
  domain (Cerulean attaches it automatically) first.
- **Remote NPM** (`NPM_MODE=remote`): place the CA PEM on the NPM host at
  `/data/cerulean-client-ca.pem` (its data dir), then add the snippet above to
  each host's *Custom Nginx Configuration* in the NPM UI. The endpoint
  deliberately refuses remote mode so you never get a host with a dangling
  file reference.

## 5. Passkeys in Authentik

Passkeys are supported in Authentik Community Edition. Provision them
idempotently:

```bash
./scripts/authentik-passkeys.py          # run from repo root (reads .env)
```

It creates a WebAuthn **authenticator validation** stage ("Cerulean — Passkeys
(WebAuthn)") and binds it at the end of the `default-authentication-flow`, after
the password step: users who enrolled a passkey authenticate with it; users who
haven't are skipped (nothing breaks). Users enroll their passkey once under
their own Authentik account (User settings → MFA devices → Enroll WebAuthn
device).

## Operational notes

- **Revocation is the kill switch.** Revoke a device's certificate in the
  dashboard (or `POST /api/pki/certificates/:id/revoke`); the gate rejects its
  future requests as soon as nginx reloads. Material stops being downloadable.
- **Renewal/re-issue**: revoke the old certificate first — one active
  certificate per name — then re-enroll. MDM-pushed SCEP profiles renew
  automatically when the SCEP server supports it.
- **Key custody**: portal-issued certificates keep a copy of the key in the
  Cerulean database (mirrored to Vault when configured). CSR-enrolled
  certificates store no key at all — only the device has it.
- **Monitoring**: the Dashboard shows CA state; expiring device certificates
  surface under PKI & Devices (30-day warning) so the same
  no-expiration-outages rule applies to your private PKI as to public certs.
