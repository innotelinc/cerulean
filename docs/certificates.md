# Certificates

Cerulean issues the estate's TLS certificates and pushes them to the edge. This is
the shape of that pipeline, what the estate's certificates looked like when it was
audited (2026-09-23), and the three names that **cannot** be issued from here —
with the measurement behind each one, so the next person does not re-derive it.

## The pipeline

1. **Cerulean issues.** ACME (Let's Encrypt) with **DNS-01 through Technitium**,
   for a name whose zone is registered under `Domains`. The zone list matters: a
   request for a name no registered zone covers is refused
   (`Domain <name> not covered by a registered zone`) — that is what registers the
   zone as the place the challenge TXT goes.
2. **Cerulean pushes.** Each issued certificate is uploaded to Nginx Proxy Manager
   as a custom (`other`) certificate and the host that serves the name is bound to
   it (`server/src/services/npm.ts`). Measured: issuing `media.innotel.us` through
   the service bridge created NPM certificate 60 and bound host 97 to it with
   `ssl_forced`, without touching either by hand.
3. **Cerulean is the source of truth for names.** NPM's upload route rewrites a
   custom certificate's `domain_names` to just its CN, so a `*.innotel.us`
   wildcard is listed in NPM as `innotel.us`; anything matching on NPM metadata
   instead of Cerulean's `domains_json` silently finds nothing.
4. **Cerulean renews** on a timer (`auto_renew`), for `issued` rows. A row in
   `error` is never retried, so a certificate that cannot validate does not keep
   spending Let's Encrypt's failure budget.

The edge is not the only consumer: anything that terminates TLS with our
certificate holds its **own copy**, and a renewal pushed to NPM does not update
it. The media host's Jellyfin is the live example — see
`3-media/monarch/docs/operations.md` §"The certificate Jellyfin serves".

## Audited 2026-09-23

| | Before | After |
|---|---|---|
| NPM certificates | 33 | 28 |
| Unused certificates | 1 | 0 |
| Hosts with a covering certificate | 174 of 186 | 176 of 186 |
| Names with no covering certificate | 14 | 10 (all on the three domains below) |

Eight certificates were retired: `studio.olympus` ×3, `ontrak` ×6 collapsed to
one wildcard (plus the non-wildcard duplicate the reassignment left behind), and
an unused Let's Encrypt `movies.innotel.us`. Eleven hosts that pointed at a
certificate which did not cover them were reassigned. Three were issued for names
that had none or wanted their own: `media.innotel.us` (which the `*.innotel.us`
wildcard covered, but is now its own certificate — it is the media host's, and
`3-media/monarch` installs the same material in Jellyfin),
`backend.api.capstone.innotel.us` (no `*.capstone.innotel.us` wildcard covers two
labels below `capstone`) and `pi.denovocredit.com`. The remaining ten are the
three domains below, and no amount of reissuing fixes them.

## Names that cannot be issued from here

All three resolve the same way: Let's Encrypt validates DNS-01 by asking the
**parent delegation** who is authoritative, and for these three that is not this
estate's Technitium. The TXT record Cerulean writes is therefore never seen, and
the error is the same each time (`No TXT record found at _acme-challenge.<name>`).

| Name | What the parent says | Evidence |
|---|---|---|
| `rizzaura.net` | `ns1/ns2.hosting.businessidentity.llc` (TTL 172800) | `dig +trace NS rizzaura.net`; our own zone lists `ns1/ns2.innotel.us`, but those are the *child* records and are not what a validator follows. The apex also still answers `66.223.49.89` publicly rather than the edge. |
| `cattape.us` | no NS at all | `dig +trace cattape.us` returns the `.us` registry SOA and no delegation; nothing under the name can be validated. |
| `fomocoin.one` | `ns1/ns2.fomocoin.one`, **no A records** | the nameserver names resolve nowhere, so the lookup times out; the delegation would have to be republished with resolvable servers (or glue) first. |

What each needs, in the order they are worth doing:

- **`rizzaura.net`** — move the delegation at the registrar to this estate's
  nameservers; then issuance is a single request and the eight NPM hosts
  (`rizzaura.net`, `admin.`, `api.`, `app.`, `auth.`, `community.`,
  `rankings.`, `subscribe.`) become publishable. Until then those names serve
  NPM's default self-signed certificate, and the records in Cerulean stay in
  `error`.
- **`cattape.us`** / **`fomocoin.one`** — republish the delegation (or retire the
  names). Neither can be fixed from inside the estate: the parent zone is the
  one being asked.

Until a delegation changes, do not re-attempt these: the outcome is fixed and each
attempt spends Let's Encrypt's per-hostname failure allowance.

## The tool: `scripts/cert-rebuild.py`

Reassigns every NPM proxy host to the certificate that actually covers it, then
deletes the superseded ones. Dry run by default; `--apply` writes.

```bash
python3 scripts/cert-rebuild.py            # the plan
python3 scripts/cert-rebuild.py --apply    # do it
```

Its own bug is worth knowing because it aborted the first apply four hosts in:
NPM returns `locations: null` for a host with no location blocks and its update
route rejects that (`data/locations must be array`). The failure was **not**
harmless — the run stopped part-way, so hosts after it kept pointing at a
certificate that was about to be deleted. `put_body()` now sends `[]`, and
`scripts/tests/test_cert_rebuild.py` pins that (with the rest of the update body:
only fields NPM returned, and never the host record the caller re-reads).
