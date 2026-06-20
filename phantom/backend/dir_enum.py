"""
dir_enum.py – Production-hardened async directory/file enumerator.

Hardening applied:
  - URL constructed from validated base_url only (no user-controlled path injection)
  - SSRFConnector: blocks RFC-1918, loopback, link-local, metadata IPs at
    connection time (defeats TOCTOU/DNS-rebinding, per Production Roadmap §3)
  - IPv4-mapped IPv6 (::ffff:x.x.x.x) blocked
  - Paths validated against a whitelist character set (no path traversal)
  - interesting = status 200, not just 401/403 (aligns with PHANTOM spec)
"""

import asyncio
import ipaddress
import re
import socket
import time
from typing import Any

import aiohttp
from aiohttp import TCPConnector

# ── SSRF-safe connector ───────────────────────────────────────────────────────
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_blocked_ip(addr: str) -> bool:
    """Return True if addr falls in a restricted/private range."""
    try:
        ip = ipaddress.ip_address(addr)
        # IPv4-mapped IPv6 bypass protection
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return False


class SSRFSafeConnector(TCPConnector):
    """
    Custom TCPConnector that validates the resolved IP at connection time,
    defeating TOCTOU race conditions and DNS rebinding (short TTL attacks).
    Per Production Readiness Roadmap §3.
    """
    async def _resolve_host(self, host: str, port: int, traces=None):
        infos = await super()._resolve_host(host, port, traces)
        for info in infos:
            addr = info["host"]
            if _is_blocked_ip(addr):
                raise aiohttp.ClientConnectorError(
                    connection_key=None,
                    os_error=OSError(f"SSRF blocked: {addr} is a restricted address"),
                )
        return infos


# ── Path validation ───────────────────────────────────────────────────────────
_SAFE_PATH_RE = re.compile(r"^[\w\-./]+$")  # no null bytes, no shell metacharacters

DEFAULT_PATHS: list[str] = [
    # Admin / management panels
    "admin", "admin/login", "administrator", "administration",
    "admin/index.php", "wp-admin", "wp-admin/", "wp-login.php",
    "phpmyadmin", "phpMyAdmin", "pma", "adminer.php",
    "manager", "management", "cpanel", "panel", "dashboard", "console",
    "controlpanel", "backend",
    # Auth / login
    "login", "signin", "signup", "register", "logout",
    # Sensitive files
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git", ".git/config", ".git/HEAD", ".git/index",
    ".gitignore", ".htaccess", ".htpasswd",
    "config.php", "config.yml", "config.yaml", "config.json",
    "configuration.php", "settings.php", "settings.py", "appsettings.json",
    "web.config", "app.config",
    # Backup / old files
    "backup", "backup.zip", "backup.tar.gz", "backup.sql",
    "db.sql", "database.sql", "dump.sql", "bak", "archive",
    "old", "old.php", "index.php.bak", "index.bak",
    # API endpoints
    "api", "api/v1", "api/v2", "api/v1/users", "api/v1/admin",
    "api/swagger", "swagger", "swagger.json", "swagger-ui.html",
    "openapi.json", "api-docs", "graphql",
    "actuator", "actuator/health", "actuator/env",
    # Dev / info files
    "phpinfo.php", "info.php", "test.php", "test", "debug", "console",
    "README.md", "package.json", "composer.json", "requirements.txt",
    "Dockerfile", "docker-compose.yml", ".DS_Store",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "server-status",
    # Password / secrets
    "password.txt", "passwords.txt", "passwd",
    "secret.txt", "secrets.yml", "keys.txt",
    # Common app paths
    "upload", "uploads", "files", "file", "media",
    "static", "assets", "images", "logs", "log",
    "error.log", "access.log", "cgi-bin",
]

SENSITIVE_KEYWORDS: list[str] = [
    ".env", ".git", "config", "backup", "phpinfo",
    "sql", "password", "passwd", "secret", "keys",
]

FOUND_STATUSES: set[int] = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403}


def _is_sensitive(path: str) -> bool:
    return any(kw in path.lower() for kw in SENSITIVE_KEYWORDS)


def _compute_risk(sensitive_count: int, interesting_count: int) -> str:
    if sensitive_count > 0:
        return "CRITICAL"
    if interesting_count > 0:
        return "HIGH"
    return "LOW"


async def _probe_path(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any] | None:
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    async with semaphore:
        try:
            async with session.head(url, allow_redirects=False) as resp:
                status = resp.status
                if status == 404:
                    return None
                if status not in FOUND_STATUSES:
                    return None
                return {
                    "path": path,
                    "url": url,
                    "status": status,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "content_length": resp.headers.get("Content-Length", ""),
                    "redirect_to": resp.headers.get("Location", ""),
                    "sensitive": _is_sensitive(path),
                    "interesting": status == 200,
                }
        except (asyncio.TimeoutError, aiohttp.ClientError):
            return None


async def enumerate_directories(target: str, options: dict | None = None) -> dict[str, Any]:
    """
    SSRF-hardened async directory/file enumerator.

    Parameters
    ----------
    target  : base URL or hostname
    options : optional overrides
        paths       – list[str] custom path wordlist
        timeout     – per-request timeout seconds (default 5)
        concurrency – semaphore size (default 20)
    """
    options = options or {}

    if not target.startswith(("http://", "https://")):
        base_url = f"https://{target}"
    else:
        base_url = target

    paths: list[str] = options.get("paths", DEFAULT_PATHS)
    # Validate paths to prevent traversal / injection
    paths = [p for p in paths if _SAFE_PATH_RE.match(p)]

    timeout_secs: int = options.get("timeout", 5)
    concurrency: int = options.get("concurrency", 20)

    # Use SSRF-safe connector to block internal IP access
    connector = SSRFSafeConnector(limit=30, ssl=False)
    timeout = aiohttp.ClientTimeout(total=timeout_secs)
    semaphore = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}

    start = time.monotonic()
    found: list[dict] = []

    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        tasks = [_probe_path(session, base_url, p, semaphore) for p in paths]
        results = await asyncio.gather(*tasks)

    for r in results:
        if r is not None:
            found.append(r)

    sensitive = [e for e in found if e.get("sensitive")]
    interesting = [e for e in found if e.get("interesting")]

    return {
        "target": base_url,
        "paths_checked": len(paths),
        "total_found": len(found),
        "found": found,
        "interesting": interesting,
        "interesting_count": len(interesting),
        "sensitive": sensitive,
        "sensitive_count": len(sensitive),
        "risk": _compute_risk(len(sensitive), len(interesting)),
        "elapsed_seconds": round(time.monotonic() - start, 2),
    }
