# acme-dns setup (delegated DNS-01)

The `acme-dns` strategy works by delegating a small zone (`auth.innotel.us`)
to the acme-dns server. When Let's Encrypt needs to validate a certificate,
it resolves `_acme-challenge.innotel.us`, follows the CNAME to
`<uuid>.auth.innotel.us`, and reads the TXT record the acme-dns server serves.

## What needs to exist

1. **The acme-dns container is reachable on UDP/TCP 53 from the internet.**
   Your router must forward port 53 to the host running the container, and
   that host must have a public IP (static or dynamic — it just needs to be
   reachable at validation time).

2. **Delegation records in your public DNS** (the BIND server serving
   `innotel.us`, or wherever the zone lives):

   ```dns
   auth.innotel.us.   IN   NS   auth.innotel.us.
   auth.innotel.us.   IN   A    <public IP of the acme-dns host>
   ```

   The NS record pointing at itself is deliberate: acme-dns is authoritative
   for everything under `auth.innotel.us`.

3. **`acme-dns/config.cfg`** has the right domain and the same `A` record:

   ```ini
   domain = "auth.innotel.us"
   records = [
       "auth.innotel.us. A <public IP>",
       "auth.innotel.us. NS auth.innotel.us.",
   ]
   ```

4. **`.env`** has `ACMEDNS_PUBLIC_IP` set (used for display/delegation checks)
   and, optionally, `ACMEDNS_ALLOW_FROM` to restrict which IPs may update TXT
   records (set it to the portal's egress IP in CIDR form).

## What Cerulean does automatically

- When you **add a domain** with the `acme-dns` strategy, Cerulean registers a
  fresh subdomain on acme-dns (`POST /register`) and stores the credentials.
- The first time it issues a certificate for that domain, it creates the
  CNAME in BIND via nsupdate:

  ```
  _acme-challenge.innotel.us. 300 IN CNAME <uuid>.auth.innotel.us.
  ```

- During issuance it pushes the challenge TXT value to acme-dns
  (`POST /update`), and clears it afterwards.

## Verifying it works

```bash
# On the BIND server (or any resolver):
dig +short _acme-challenge.innotel.us CNAME
# → <uuid>.auth.innotel.us.

dig @<public-ip> <uuid>.auth.innotel.us TXT
# → should return the challenge value while issuance is in progress
```

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `dig +short _acme-challenge... CNAME` empty | CNAME not created — check BIND `allow-update` and `BIND_TSIG_*` in `.env` |
| Validation fails with "no TXT record" | acme-dns port 53 not reachable from the internet; delegation records missing; wrong public IP in `config.cfg` |
| `nsupdate` errors with `not authoritative` | `allow-update` missing from the zone block, or the TSIG key not referenced in the zone |
| acme-dns `/register` refused | `disable_registration` is `true` in `config.cfg` |

> Tip: switch `ACME_DIRECTORY_URL` to the Let's Encrypt **staging** endpoint
> while testing to avoid burning rate limits on failed attempts.
