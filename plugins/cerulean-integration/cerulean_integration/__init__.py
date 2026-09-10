"""cerulean-integration — provision NPM hosts + Technitium DNS + Cerulean certs.

A project-agnostic client for the Cerulean DNS/certificate platform
(cerulean-dns-platform). Given a hosts file and a base domain it:

  1. writes an A record for every subdomain (Technitium via Cerulean's DNS API),
  2. creates/updates the matching Nginx Proxy Manager proxy hosts, and
  3. issues a wildcard Let's Encrypt certificate through Cerulean (DNS-01
     via Technitium HTTP API), which Cerulean auto-attaches to the proxy hosts.
"""

__version__ = "0.1.0"