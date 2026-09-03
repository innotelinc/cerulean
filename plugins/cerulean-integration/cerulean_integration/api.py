"""Minimal client for the Cerulean DNS/certificate platform REST API.

Drives the endpoints the Cerulean server exposes (see server/src/routes.ts):

    auth          POST /api/auth/login
    domains       GET/POST /api/domains, GET/POST/DELETE /api/domains/:id/records
    certificates  GET/POST /api/certificates, GET /api/certificates/:id,
                  POST /api/certificates/:id/renew
    npm hosts     GET/POST /api/npm/hosts, PUT /api/npm/hosts/:id

All mutation happens server-side against Cerulean's own NPM + BIND
connections, so projects using this plugin never need NPM or TSIG secrets.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime


class CeruleanError(Exception):
    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


def _iso_to_ts(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


class CeruleanClient:
    def __init__(
        self,
        base_url: str,
        password: str,
        timeout: int = 30,
        dry_run: bool = False,
    ):
        self.base = base_url.rstrip("/")
        self.password = password
        self.timeout = timeout
        self.dry_run = dry_run
        self.token: str | None = None
        self.planned: list[str] = []

    # ── transport ────────────────────────────────────────────────────────
    def _request(self, method: str, path: str, body: dict | None = None):
        url = f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            text = err.read().decode("utf-8", "replace")
            if err.code in (401, 403) and self.token:
                # Token may have expired — re-login once and retry.
                self.token = None
                self.login()
                return self._request(method, path, body)
            raise CeruleanError(
                f"HTTP {err.code} {method} {path}: {text[:400]}", code=err.code
            ) from None
        except urllib.error.URLError as err:
            raise CeruleanError(
                f"Cannot reach Cerulean at {self.base} ({err.reason})"
            ) from None
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}

    def _mutate(self, description: str, method: str, path: str, body: dict | None = None):
        """Run a mutating request, or record it when in dry-run mode."""
        if self.dry_run:
            self.planned.append(description)
            return {"dry_run": True}
        return self._request(method, path, body)

    def login(self) -> None:
        data = self._request("POST", "/api/auth/login", {"password": self.password})
        token = data.get("token") if isinstance(data, dict) else None
        if not token:
            raise CeruleanError("Cerulean login failed: no token returned")
        self.token = token

    # ── domains / records ────────────────────────────────────────────────
    def list_domains(self) -> list[dict]:
        return self._request("GET", "/api/domains") or []

    def resolve_zone(self, base_domain: str, configured_zone: str = "") -> str:
        """Resolve the BIND zone that hosts `base_domain`'s records: the
        longest registered-zone suffix, else the configured zone, else
        base_domain itself."""
        base = base_domain.strip().lower().rstrip(".")
        candidates = [d.get("name", "") for d in self.list_domains()]
        if configured_zone:
            candidates.append(configured_zone)
        best: str | None = None
        for zone_raw in candidates:
            z = zone_raw.strip().lower().rstrip(".")
            if not z:
                continue
            if base == z or base.endswith(f".{z}"):
                if best is None or len(z) > len(best):
                    best = z
        return best or base

    def create_domain(self, name: str) -> dict:
        return self._mutate(
            f"register zone {name}",
            "POST",
            "/api/domains",
            {"name": name},
        )

    def ensure_domain(self, name: str) -> dict:
        name = name.strip().lower().rstrip(".")
        for d in self.list_domains():
            if (d.get("name") or "").strip().lower().rstrip(".") == name:
                return d
        if self.dry_run:
            return {"id": None, "name": name}
        try:
            return self.create_domain(name)
        except CeruleanError as err:
            if err.code == 409:  # created concurrently — return the existing row
                for d in self.list_domains():
                    if (d.get("name") or "").strip().lower().rstrip(".") == name:
                        return d
            raise

    def list_records(self, domain_id: int) -> list[dict]:
        return self._request("GET", f"/api/domains/{domain_id}/records") or []

    def add_record(
        self, domain_id: int, rtype: str, name: str, value: str, ttl: int = 300
    ) -> dict:
        return self._mutate(
            f"add {rtype} {name} -> {value}",
            "POST",
            f"/api/domains/{domain_id}/records",
            {"type": rtype, "name": name, "value": value, "ttl": ttl},
        )

    def delete_record(
        self, domain_id: int, rtype: str, name: str, value: str
    ) -> dict:
        return self._mutate(
            f"delete {rtype} {name} ({value})",
            "DELETE",
            f"/api/domains/{domain_id}/records",
            {"type": rtype, "name": name, "value": value},
        )

    def upsert_a_record(
        self,
        domain_id: int,
        relative_name: str,
        expected_full: str,
        value: str,
        ttl: int = 300,
    ) -> str:
        """Ensure an A record exists at `expected_full` -> value in the zone
        identified by `domain_id`. `relative_name` is the record name relative
        to the zone ("@" for the apex). Returns the action taken:
        'added' | 'updated' | 'unchanged'."""
        def norm(n: str) -> str:
            return (n or "").strip().lower().rstrip(".")

        for rec in self.list_records(domain_id):
            if rec.get("type") != "A" or norm(rec.get("name", "")) != norm(expected_full):
                continue
            if (rec.get("value") or "").strip() == value:
                return "unchanged"
            self.delete_record(
                domain_id, "A", relative_name, rec.get("value") or value
            )
            self.add_record(domain_id, "A", relative_name, value, ttl)
            return "updated"
        self.add_record(domain_id, "A", relative_name, value, ttl)
        return "added"

    # ── certificates ─────────────────────────────────────────────────────
    def list_certificates(self) -> list[dict]:
        return self._request("GET", "/api/certificates") or []

    def create_certificate(self, domain: str, wildcard: bool = True) -> dict:
        return self._mutate(
            f"issue certificate for {('*.' if wildcard else '')}{domain}",
            "POST",
            "/api/certificates",
            {"domain": domain, "wildcard": wildcard},
        )

    def renew_certificate(self, cert_id: int) -> dict:
        return self._mutate(
            f"renew certificate {cert_id}", "POST", f"/api/certificates/{cert_id}/renew"
        )

    def get_certificate(self, cert_id: int) -> dict:
        return self._request("GET", f"/api/certificates/{cert_id}")

    def wait_for_certificate(self, cert_id: int, timeout: int) -> dict:
        deadline = time.time() + timeout
        last: dict = {}
        while time.time() < deadline:
            cert = self.get_certificate(cert_id)
            last = cert
            status = cert.get("status")
            if status == "issued" and cert.get("hasMaterial"):
                return cert
            if status == "error":
                raise CeruleanError(
                    f"Certificate issuance failed: {cert.get('error')}"
                )
            time.sleep(5)
        raise CeruleanError(
            f"Timed out after {timeout}s waiting for certificate {cert_id} "
            f"(last status: {last.get('status')})"
        )

    def ensure_wildcard_cert(
        self,
        base_domain: str,
        renew_days: int,
        timeout: int,
    ):
        """Reuse a valid wildcard cert for base_domain, else issue one via
        Cerulean (BIND/TSIG DNS-01). Returns (cert, action)."""
        base_domain = base_domain.strip().lower().rstrip(".")
        now = time.time()
        for cert in self.list_certificates():
            if (cert.get("domain") or "").lower() != base_domain or not cert.get(
                "wildcard"
            ):
                continue
            status = cert.get("status")
            if status == "issued" and cert.get("hasMaterial"):
                if _iso_to_ts(cert.get("expiresAt")) > now + renew_days * 86400:
                    return cert, "reuse"
                self.renew_certificate(cert["id"])
                return (
                    self.wait_for_certificate(cert["id"], timeout),
                    "renewed",
                )
            if status == "issuing":
                return self.wait_for_certificate(cert["id"], timeout), "waiting"
            if status == "error":
                break  # re-issue below
        if self.dry_run:
            return (
                {"status": "dry-run", "expiresAt": None},
                "would-issue (dry-run)",
            )
        created = self.create_certificate(base_domain, wildcard=True)
        return self.wait_for_certificate(created["id"], timeout), "issued"

    # ── NPM proxy hosts ──────────────────────────────────────────────────
    def list_npm_hosts(self) -> list[dict]:
        return self._request("GET", "/api/npm/hosts") or []

    def create_npm_host(
        self,
        domain: str,
        forward_host: str,
        forward_port: int,
        forward_scheme: str = "http",
        ssl_forced: bool = True,
        http2_support: bool = True,
        websocket_support: bool = False,
    ) -> dict:
        return self._mutate(
            f"create NPM host {domain} -> {forward_host}:{forward_port}",
            "POST",
            "/api/npm/hosts",
            {
                "domain": domain,
                "forward_host": forward_host,
                "forward_port": forward_port,
                "forward_scheme": forward_scheme,
                "ssl_forced": ssl_forced,
                "http2_support": http2_support,
                "websocket_support": websocket_support,
            },
        )

    def update_npm_host(
        self,
        host_id: int,
        forward_host: str,
        forward_port: int,
        forward_scheme: str = "http",
        ssl_forced: bool = True,
        http2_support: bool = True,
        websocket_support: bool = False,
    ) -> dict:
        return self._mutate(
            f"update NPM host {host_id} -> {forward_host}:{forward_port}",
            "PUT",
            f"/api/npm/hosts/{host_id}",
            {
                "forward_host": forward_host,
                "forward_port": forward_port,
                "forward_scheme": forward_scheme,
                "ssl_forced": ssl_forced,
                "http2_support": http2_support,
                "websocket_support": websocket_support,
            },
        )

    def upsert_npm_host(
        self,
        domain: str,
        forward_host: str,
        forward_port: int,
        forward_scheme: str = "http",
        websocket_support: bool = False,
        ssl_forced: bool = True,
        http2_support: bool = True,
    ) -> str:
        """Ensure an NPM proxy host exists for `domain`. Returns the action
        taken: 'added' | 'updated' | 'unchanged'."""
        domain = domain.strip().lower()
        for host in self.list_npm_hosts():
            names = [n.lower() for n in (host.get("domain_names") or [])]
            if domain not in names:
                continue
            drift = []
            if str(host.get("forward_host") or "") != forward_host:
                drift.append(
                    f"forward_host {host.get('forward_host')} -> {forward_host}"
                )
            if int(host.get("forward_port") or 0) != forward_port:
                drift.append(
                    f"forward_port {host.get('forward_port')} -> {forward_port}"
                )
            if (host.get("forward_scheme") or "http") != forward_scheme:
                drift.append(
                    f"forward_scheme {host.get('forward_scheme')} -> {forward_scheme}"
                )
            if self.dry_run and drift:
                for d in drift:
                    self.planned.append(f"update NPM host {domain}: {d}")
                return "updated (dry-run)"
            if drift:
                self.update_npm_host(
                    host["id"],
                    forward_host,
                    forward_port,
                    forward_scheme,
                    ssl_forced,
                    http2_support,
                    websocket_support,
                )
                return "updated"
            return "unchanged"
        self.create_npm_host(
            domain,
            forward_host,
            forward_port,
            forward_scheme,
            ssl_forced,
            http2_support,
            websocket_support,
        )
        return "added"