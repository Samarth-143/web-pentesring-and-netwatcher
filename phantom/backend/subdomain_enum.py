"""
subdomain_enum.py – Production-hardened async subdomain enumerator.

Hardening applied:
  - RFC-1123 ReDoS-resistant domain validation
  - asyncio.wait_for(timeout=3) on each DNS resolve (prevents indefinite blocking)
  - HEAD probe on found subdomains (http then https fallback)
  - crt.sh CT lookup deduplicated against DNS brute results
  - SSRF-safe: no user-controlled URL construction for external requests
"""

import asyncio
import json
import re
import shlex
import socket
import time
import ipaddress
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

# ── Validation ────────────────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(
    r"^(?!.{254,})((?!-)[A-Za-z0-9\-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)

# ── SSRF-safe connector ───────────────────────────────────────────────────────
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]

def _is_blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return False

import aiohttp
from aiohttp import TCPConnector

class SSRFSafeConnector(TCPConnector):
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

# Expanded wordlist – 80+ common subdomains
DEFAULT_WORDLIST: list[str] = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh",
    "vpn", "remote", "webmail", "mx", "mx1", "mx2",
    "api", "api2", "apiv1", "apiv2", "rest", "graphql", "v1", "v2",
    "admin", "administrator", "portal", "dashboard", "panel", "console",
    "login", "auth", "sso", "oauth", "accounts",
    "dev", "development", "staging", "stage", "uat", "qa", "test",
    "beta", "alpha", "preview", "demo", "sandbox", "lab", "prod",
    "db", "database", "mysql", "pgsql", "redis", "mongo", "elastic",
    "cdn", "static", "assets", "media", "images", "img", "files", "upload",
    "blog", "docs", "help", "support", "status", "monitor",
    "git", "gitlab", "github", "bitbucket", "svn", "ci", "jenkins",
    "jira", "confluence", "wiki", "intranet", "internal", "corp",
    "ns1", "ns2", "dns1", "dns2",
    "shop", "store", "checkout", "pay", "billing",
    "mobile", "m", "app", "apps", "backend",
    "secure", "ssl", "vpn2", "aws", "s3",
    "old", "legacy", "backup", "bak",
    "search", "sitemap", "robots",
]

HIGH_VALUE_KEYWORDS: list[str] = [
    "admin", "api", "dev", "staging", "db", "git",
    "dashboard", "portal", "console", "internal", "vpn", "jenkins",
]


class ValidationError(ValueError):
    pass


def _validate_domain(target: str) -> str:
    """Strip scheme/path and validate as RFC-1123 domain."""
    domain = target.strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].lower().strip()
    if not _DOMAIN_RE.match(domain):
        raise ValidationError(f"'{domain}' is not a valid domain name")
    return domain


async def _dns_resolve_with_probe(
    subdomain: str,
    semaphore: asyncio.Semaphore,
    loop: asyncio.AbstractEventLoop,
) -> dict[str, Any] | None:
    """Resolve + optional HEAD probe for each subdomain candidate."""
    async with semaphore:
        # DNS resolve with hard timeout
        try:
            ip = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, subdomain),
                timeout=3.0,
            )
        except (asyncio.TimeoutError, socket.gaierror, socket.herror):
            return None

        # HEAD probe (https first, then http)
        http_status: int | None = None
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=3)
            connector = SSRFSafeConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
                for scheme in ("https", "http"):
                    try:
                        async with sess.head(f"{scheme}://{subdomain}", allow_redirects=False) as r:
                            http_status = r.status
                            break
                    except Exception:
                        continue
        except ImportError:
            pass

        return {
            "subdomain": subdomain,
            "ip": ip,
            "http_status": http_status,
            "source": "dns_brute",
        }


async def _dns_brute_force(domain: str, wordlist: list[str]) -> list[dict]:
    """Concurrent DNS brute-force with Semaphore(50)."""
    semaphore = asyncio.Semaphore(50)
    loop = asyncio.get_event_loop()
    tasks = [
        _dns_resolve_with_probe(f"{word}.{domain}", semaphore, loop)
        for word in wordlist
    ]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


def _fetch_crtsh(domain: str) -> list[dict]:
    """Synchronous crt.sh CT lookup – called via run_in_executor."""
    if not re.match(r"^(?!.{254,})((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$", domain):
        return []
        
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        with urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (URLError, json.JSONDecodeError, Exception):
        return []

    seen: set[str] = set()
    results: list[dict] = []
    for entry in data:
        name = entry.get("name_value", "").strip().lower()
        for sub in name.splitlines():
            sub = sub.strip().lstrip("*.")
            if sub and sub not in seen and sub.endswith(f".{domain}"):
                seen.add(sub)
                results.append({
                    "subdomain": sub,
                    "issuer": entry.get("issuer_name", ""),
                    "logged_at": entry.get("entry_timestamp", ""),
                    "source": "cert_transparency",
                })
    return results


async def enumerate_subdomains(target: str, options: dict | None = None) -> dict[str, Any]:
    """
    Async subdomain enumerator.

    Parameters
    ----------
    target  : domain to enumerate (e.g. "example.com")
    options : optional overrides
        wordlist   – list[str] override
        use_ct     – bool (default True)
        use_brute  – bool (default True)
    """
    options = options or {}

    try:
        domain = _validate_domain(target)
    except ValidationError as exc:
        return {"error": str(exc), "target": target, "error_type": "ValidationError"}

    wordlist: list[str] = options.get("wordlist", DEFAULT_WORDLIST)
    use_ct: bool = options.get("use_ct", True)
    use_brute: bool = options.get("use_brute", True)

    start = time.monotonic()
    loop = asyncio.get_event_loop()

    dns_results: list[dict] = []
    ct_results: list[dict] = []

    tasks = []
    if use_brute:
        tasks.append(_dns_brute_force(domain, wordlist))
    if use_ct:
        tasks.append(loop.run_in_executor(None, _fetch_crtsh, domain))

    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    idx = 0
    if use_brute:
        res = gathered[idx]
        dns_results = res if isinstance(res, list) else []
        idx += 1
    if use_ct:
        res = gathered[idx]
        ct_results = res if isinstance(res, list) else []

    # Deduplicate CT results against DNS brute results
    dns_found: set[str] = {e["subdomain"] for e in dns_results}
    ct_unique = [e for e in ct_results if e["subdomain"] not in dns_found]

    all_unique = dns_results + ct_unique
    high_value = [
        e for e in all_unique
        if any(kw in e["subdomain"] for kw in HIGH_VALUE_KEYWORDS)
    ]

    return {
        "target": domain,
        "dns_brute": dns_results,
        "certificate_transparency": ct_unique,
        "total_found": len(all_unique),
        "all_subdomains": all_unique,
        "high_value_targets": high_value,
        "elapsed_seconds": round(time.monotonic() - start, 2),
    }
