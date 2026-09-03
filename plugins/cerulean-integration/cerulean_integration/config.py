"""Configuration loading: environment variables, an optional repo ``.env``,
and CLI overrides. Values in ``.env`` never override the environment."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path


def load_dotenv(path: str | os.PathLike | None = None) -> dict[str, str]:
    """Minimal dependency-free .env loader (quotes stripped, no interpolation)."""
    p = Path(path) if path else Path.cwd() / ".env"
    if not p.is_file():
        return {}
    env: dict[str, str] = {}
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            env[key] = val
    return env


def detect_lan_ip() -> str | None:
    """Best-effort local LAN IP via a UDP connect (sends no packets)."""
    for target in ("8.8.8.8", "1.1.1.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((target, 53))
                return s.getsockname()[0]
            finally:
                s.close()
        except OSError:
            continue
    return None


@dataclass
class Config:
    api_url: str = "http://localhost:3003"
    password: str = ""
    base_domain: str = "innotel.us"
    # BIND zone that hosts the A records. Optional: when empty, the zone is
    # resolved as the longest registered-zone suffix of base_domain (falling
    # back to base_domain itself). Set it when subdomains live under a parent
    # zone, e.g. base_domain=monarch.innotel.us with CERULEAN_ZONE=innotel.us.
    zone: str = ""
    forward_host: str = ""
    hosts_file: str = ""
    dry_run: bool = False
    skip_certs: bool = False
    skip_dns: bool = False
    skip_hosts: bool = False
    renew_days: int = 30
    timeout: int = 30
    cert_timeout: int = 900
    dotenv_path: str | None = None
    _warnings: list[str] = field(default_factory=list)

    @property
    def warnings(self) -> list[str]:
        return self._warnings


def load_config(
    dotenv_path: str | os.PathLike | None = None,
    overrides: dict | None = None,
) -> Config:
    """Merge defaults < .env < environment < overrides (CLI flags)."""
    overrides = overrides or {}
    env = load_dotenv(dotenv_path)
    merged: dict[str, str] = {}
    merged.update(env)
    merged.update({k: v for k, v in os.environ.items() if v})

    def get(*names: str, default: str = "") -> str:
        for n in names:
            if n in merged and merged[n] != "":
                return merged[n]
        return default

    cfg = Config()
    cfg.dotenv_path = str(dotenv_path) if dotenv_path else None
    cfg.api_url = get("CERULEAN_API_URL", "CERULEAN_BASE_URL", default="http://localhost:3003")
    cfg.password = get("CERULEAN_ADMIN_PASSWORD")
    cfg.base_domain = get("CERULEAN_BASE_DOMAIN", default="innotel.us")
    cfg.zone = get("CERULEAN_ZONE")
    cfg.forward_host = get("NPM_FORWARD_HOST", "CERULEAN_FORWARD_HOST")
    cfg.renew_days = int(get("CERULEAN_RENEW_DAYS", default="30") or 30)
    cfg.timeout = int(get("CERULEAN_API_TIMEOUT", default="30") or 30)
    cfg.cert_timeout = int(get("CERULEAN_CERT_TIMEOUT", default="900") or 900)

    for key, value in overrides.items():
        if value is None:
            continue
        setattr(cfg, key, value)

    if not cfg.forward_host:
        detected = detect_lan_ip()
        if detected:
            cfg.forward_host = detected
            cfg._warnings.append(
                f"NPM_FORWARD_HOST not set — using detected LAN IP {detected}"
            )
        else:
            cfg._warnings.append(
                "NPM_FORWARD_HOST not set and LAN IP detection failed — "
                "proxy hosts will not forward correctly"
            )
    return cfg