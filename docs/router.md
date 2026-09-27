# Router — the estate's edge device

Everything public arrives here first. The device is a **Netgear Orbi RBR750P**
(satellites `Orbi-1`/`Orbi-2` at `192.168.1.201`/`.202`), firmware
`V6.3.8.5_1.4.80NA`, admin UI at <http://192.168.1.1>. Its UI is served by the
firmware's `lighttpd`, and the pages talk to `/dniapi/` (form-encoded,
`csrfToken` header + `Bearer` token after login). The admin password is **not in
this repository** — read it from the password manager, or ask whoever holds it.

This file is the reference for the three things the router decides on its own:
**DNS**, **port forwarding**, and **LAN reservations**. All three have to agree
with what is actually provisioned, and the failure mode when they drift is
asymmetric — a stale forward is loudly broken, a stale *reservation* is silent.

---

## 1. DNS — the router resolves through the estate's own server

| Setting | Value |
|---|---|
| WAN DNS mode | Use These DNS Servers |
| DNS server 1 | `192.168.1.71` (Cerulean's Technitium) |
| DNS server 2 | `1.1.1.1` (fallback) |

The estate runs its own authoritative DNS — Technitium on `192.168.1.71`, in the
Cerulean stack. It is **primary** for six zones:

    innotel.us   lab.innotel.us   rizzaura.net   cattape.us   fomocoin.one   denovocredit.com

Those zones are not delegated publicly, so nobody outside this LAN can resolve
them to the estate. That makes the router's DNS setting load-bearing in a way
that is easy to miss: with the firmware's default ("Get Automatically from ISP")
LAN clients ask the ISP's resolver, get public/NXDOMAIN answers for the estate's
own zones, and *appear to work* for every name that happens to have a public
record. The names that break are the ones that only exist here.

`1.1.1.1` is the second entry so that losing `192.168.1.71` degrades the estate's
own zones instead of stopping name resolution entirely. Technitium's own
forwarders are `1.1.1.1`/`8.8.8.8` and its recursion is
`AllowOnlyForPrivateNetworks`, so there is no query loop back into the router.

Time is set the same way: NTP mode `default`, timezone `GMT-05:00@Eastern`,
daylight saving **on** — `America/New_York`, which the whole estate uses.

---

## 2. Port forwarding

The router forwards exactly what must be reached from outside. Everything else
— admin UIs, databases, object stores, control planes — is reachable only
through Nginx Proxy Manager on `443`, with auth in front of it.

| Ext port | Proto | → Host | Purpose |
|---|---|---|---|
| `80` | TCP/UDP | `192.168.1.71` | NPM — HTTP (redirects to HTTPS) |
| `443` | TCP/UDP | `192.168.1.71` | NPM — HTTPS, every public name |
| `53` | TCP/UDP | `192.168.1.71` | Technitium — authoritative DNS |
| `5060, 5062-5080` | UDP | `192.168.1.30` | Asterisk SIP signalling |
| `5061` | TCP | `192.168.1.30` | Asterisk SIP over TLS |
| `10101-10120` | UDP | `192.168.1.30` | Asterisk RTP (≈10 concurrent calls) |
| `8089` | TCP | `192.168.1.30` | PJSIP WebSocket / WSS (WebRTC softphones) |
| `3478` | TCP/UDP | `192.168.1.30` | Coturn TURN listener |
| `5349` | TCP/UDP | `192.168.1.30` | Coturn TURN over TLS |
| `49152-49251` | UDP | `192.168.1.30` | Coturn media relay range |
| `8088, 5038` | TCP | `192.168.1.30` | Asterisk ARI + AMI (Proxmox/ops only) |
| `51820` | TCP/UDP | `192.168.1.43` | WireGuard VPN |
| `3389` | TCP/UDP | `192.168.1.24` | RDP (operator workstation) |
| `10000` | TCP | `192.168.1.46` | Webmin on the development host |

Where each port is *published* is what the rule has to match, not where the
project's repository happens to live. `80`/`443`/`53` moved from `192.168.1.46`
to `192.168.1.71` when the Cerulean edge consolidated onto the proxy host, and a
rule left behind points at a closed port: every public name goes dark at once.
**Treat `192.168.1.71` for `80`/`443`/`53` as load-bearing.**

The raw forwards are telephony-only. What must *not* be forwarded is as
important as what must: `5432` (postgres), `6379` (redis), `9000`/`9001`
(minio/onyx objectstore), `3306` (NPM's database), `8200` (Vault), `81`
(NPM admin), `9000`/`9443` (Authentik) are reachable on the LAN only, or
through NPM with authentication.

The telephony side is written up in detail — including which side is
host-only — in `2-voice/capstone/docs/networking.md`.

---

## 3. LAN reservations

DHCP serves `192.168.1.2-209` with a 24-hour lease. Every host that another
host dials by address has a **reservation**, so an address is a name that
survives a reboot:

| IP | Name | IP | Name | IP | Name |
|---|---|---|---|---|---|
| `.3` | PM3 | `.35` | ANSIBLE | `.56` | MONARCH |
| `.8` | SUBSCRIBE | `.38` | ONTRAK-GW | `.59` | ATHENIQ |
| `.9` | VOICE | `.40` | IRC | `.60` | ONYX |
| `.11` | SIGN | `.42` | ONTRAK | `.61` | DISTRO |
| `.15` | MAIL | `.43` | VPN | `.63` | VIA |
| `.16` | AUTH | `.44` | SIGNARA | `.70` | PI |
| `.22` | TERMINAL | `.46` | DEVELOPMENT | `.71` | PROXY |
| `.24` | SURFACE | `.47` | CAPSTONE | `.73` | VAULT |
| `.28` | SLOTS | `.49` | ACME | `.80` | WWW |
| `.30` | ZEUS | `.50` | OLYMPUS | `.90` | GIT |
| `.33` | SLACK | `.51`–`.53` | I1–I3 | `.100` | ZIMAOS |
| `.54`/`.55` | INCUS-MACBOOK / MACBOOK | `.106` | PEGAPROX | `.108` | PATCHMON |
| `.110` | — | `.125` | DOCS | `.146` | CLOUD |
| `.168` | AI | `.172` | — | `.201`/`.202` | Orbi-1 / Orbi-2 |

The reservations that carry services other hosts dial are the important ones:
`.71` (NPM, Authentik, Technitium, Vault), `.30` (Zeus/capstone telephony),
`.44` (Signara), `.60` (Onyx), `.56` (Monarch media), `.46` (development), `.50`
(Olympus) and `.43` (VPN). A service configured against a *reserved* address and
then moved keeps answering on the old one until the lease turns over, so the
reservation is the first thing worth checking when "it worked yesterday".

---

## Changing any of this

The UI is the supported path: **Advanced → Advanced Setup → Port Forwarding**
for rules, **Advanced → Setup → LAN Setup** for reservations, **Internet Setup**
for the DNS servers. A forwarded *range* has to be one rule; the firmware
rejects a second entry that overlaps it.

Read the current state back before changing it, so the old value is captured
rather than remembered:

```bash
dig +short @192.168.1.1 rizzaura.net     # must be the estate's WAN address
dig +short @192.168.1.71 innotel.us      # authoritative answer
ss -lntup | grep -E ':(80|443|53)\b'     # on 192.168.1.71: is the listener there?
```

A forward is only correct if the listening port is on the host the rule names.
Check that pair, not the rule alone.
