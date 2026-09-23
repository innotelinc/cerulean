# DNS NOTIFY on a one-server estate

A warning that says "notify failed" on a DNS server with **no second server** is
not a DNS problem. It is a configuration that can never succeed, retried every
five minutes, and the honest fix is to stop asking for it. This is that story,
the tool that clears it, and the gate that keeps a deploy from starting into it.

## The alarm

Technitium's console flags a zone `notifyFailed` and logs, every five minutes:

```
DNS Server failed to notify name server 'ns1.innotel.us' (RCODE=Refused) for zone: innotel.us
```

The zone's notify mode is *the zone's name servers*, and on this estate every NS
name a zone lists (`ns1/ns2.innotel.us`, `ns1.cattape.us`, …) resolves back to
**this same box**. So the server sends itself a NOTIFY and, being the primary for
the zone, refuses it. There is no other server to transfer to: the NOTIFY cannot
ever succeed, and the flag cannot ever clear. `lab.innotel.us` was the one green
zone precisely because its NS is the server's own name, which Technitium excludes
from the notify targets.

The correct configuration is `notify = None` — the zone has no secondaries.

## Clearing it

```bash
# the zones Technitium has already flagged
./scripts/zone-notify-reconcile.py
./scripts/zone-notify-reconcile.py --apply      # set notify=None, print the undo

# the same judgement, read before the flag exists — this is the deploy gate
./scripts/zone-notify-reconcile.py --preflight
```

The tool is **narrow by construction**. The default path only looks at zones
Technitium already reports `notifyFailed`, and it only writes when **every**
notify target resolves to an address this server answers on. A zone that fails to
notify a genuine second server is reported and left alone — that is a real
problem, not a false alarm. A target that resolves nowhere counts as a different
problem too, not as a self-notify, which is what keeps the tool from writing over
a broken delegation.

Exit codes are three-valued on purpose, because a deploy has to tell them apart:

| code | meaning |
| --- | --- |
| `0` | nothing armed, nothing to do |
| `1` | a zone can only ever fail to notify (or was just fixed) — **a finding** |
| `2` | the check could not run: no token, server unreachable — **not** a finding |

## The deploy gate

Nothing in this repo chooses a zone's notify mode — Technitium's own default for
a new Primary zone is the zone's name servers — so a zone created later (through
the console, or by a tenant's own provider) regresses silently. That is why the
preflight reads **every enabled Primary zone**, not just the flagged ones, and
why two deploy paths call it:

| path | behaviour |
| --- | --- |
| `scripts/setup.sh` (this host's own setup) | step **1b**, before `npm install` and the stack start. `--skip-dns-preflight` bypasses it |
| `ips/stack.sh up 1` (the estate deploy) | after the component check, when a `cerulean` checkout and `.env` are present. `STACK_SKIP_VERIFY=1` bypasses it, and exit 2 only warns — a host running part of a stack is not a drifted host |

Both call the same script, so there is one implementation of the judgement.

```bash
./scripts/setup.sh                      # fails if a zone is armed to notify only this server
./scripts/setup.sh --skip-dns-preflight # …unless you say not to look
```

## What it deliberately is not

Not a change to how zones are created. The estate's DNS server is an operator's
console, tenants can create their own zones, and Technitium owns that default —
so the reconcile run is the re-converge step and the preflight is the gate, not a
patch to the product. The rules and the exit codes are covered by
`scripts/tests/test_zone_notify_reconcile.py`, against a fake Technitium: no
server, no DNS, no network.
