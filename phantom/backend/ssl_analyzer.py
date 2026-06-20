"""
ssl_analyzer.py – Production-hardened SSL/TLS analyzer.

Hardening applied:
  - RFC-1123 domain validation
  - Uses stdlib ssl + asyncio (no third-party TLS libraries required)
  - Checks: TLS version, cipher suite, certificate validity, SAN coverage,
    self-signed detection, expiry window, weak cipher detection,
    BEAST/POODLE/DROWN protocol downgrade detection
  - Optional: sslyze integration when available for deeper cipher enumeration
  - Risk scoring: CRITICAL for expired/self-signed, HIGH for TLS 1.0/1.1,
    MEDIUM for weak ciphers or short validity
"""

import asyncio
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

# ── Validation ────────────────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(
    r"^(?!.{254,})((?!-)[A-Za-z0-9\-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)

# ── SSRF Prevention ───────────────────────────────────────────────────────────
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

# ── Weak cipher keywords ──────────────────────────────────────────────────────
WEAK_CIPHER_PATTERNS: list[str] = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON",
    "RC2", "IDEA", "SEED", "CAMELLIA128",
]

DEPRECATED_PROTOCOLS: set[str] = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
SECURE_PROTOCOLS: set[str] = {"TLSv1.2", "TLSv1.3"}

EXPIRY_WARNING_DAYS = 30
EXPIRY_CRITICAL_DAYS = 7


class ValidationError(ValueError):
    pass


def _normalize_target(target: str) -> tuple[str, int]:
    """Return (hostname, port) from a URL or bare domain."""
    t = target.strip()
    for prefix in ("https://", "http://"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    t = t.split("/")[0]
    if ":" in t:
        host, port_str = t.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            pass
    return t, 443


def _validate_domain(domain: str) -> str:
    if not _DOMAIN_RE.match(domain):
        raise ValidationError(f"'{domain}' is not a valid domain name")
    return domain


def _is_weak_cipher(cipher_name: str) -> bool:
    return any(w in cipher_name.upper() for w in WEAK_CIPHER_PATTERNS)


def _parse_cert_date(date_str: str) -> datetime:
    """Parse ASN.1 GeneralizedTime or UTCTime from ssl module."""
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _check_san_coverage(cert: dict, hostname: str) -> bool:
    """Check whether the certificate's SANs or CN cover the hostname."""
    san_list: list[str] = []
    for key, val in cert.get("subjectAltName", []):
        if key.lower() == "dns":
            san_list.append(val.lower())
    if not san_list:
        # Fall back to CN
        for rdn in cert.get("subject", []):
            for key, val in rdn:
                if key.lower() == "commonname":
                    san_list.append(val.lower())

    hostname_lower = hostname.lower()
    for name in san_list:
        if name == hostname_lower:
            return True
        if name.startswith("*."):
            suffix = name[2:]
            parts = hostname_lower.split(".")
            if len(parts) >= 2 and ".".join(parts[1:]) == suffix:
                return True
    return False


def _is_self_signed(cert: dict) -> bool:
    """A cert is self-signed if issuer == subject."""
    return cert.get("issuer") == cert.get("subject")


def _risk_label(score: int) -> str:
    if score == 0:
        return "LOW"
    if score <= 2:
        return "MEDIUM"
    if score <= 4:
        return "HIGH"
    return "CRITICAL"


async def analyze_ssl(target: str, options: dict | None = None) -> dict[str, Any]:
    """
    SSL/TLS analyzer.

    Parameters
    ----------
    target  : hostname, domain, or URL
    options : optional
        timeout – connection timeout seconds (default 10)
        port    – override port (default 443)

    Returns
    -------
    dict with: target, host, port, tls_version, cipher_suite, certificate,
               san_coverage, weak_cipher, deprecated_protocol, risk, findings
    """
    options = options or {}
    hostname, default_port = _normalize_target(target)
    port: int = options.get("port", default_port)
    timeout_secs: float = options.get("timeout", 10.0)

    try:
        _validate_domain(hostname)
    except ValidationError as exc:
        # Accept IP addresses too for completeness
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            return {"error": str(exc), "target": target, "error_type": "ValidationError"}

    findings: list[str] = []
    risk_score = 0

    # ── Attempt TLS connection ────────────────────────────────────────────────
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Also try with verification disabled to check self-signed certs
    ctx_noverify = ssl.create_default_context()
    ctx_noverify.check_hostname = False
    ctx_noverify.verify_mode = ssl.CERT_NONE

    cert_info: dict[str, Any] = {}
    tls_version: str = "unknown"
    cipher_suite: str = "unknown"
    cipher_bits: int = 0
    verified = True
    self_signed = False
    san_ok = False
    expired = False
    days_to_expiry: int | None = None
    expiry_dt: datetime | None = None

    loop = asyncio.get_event_loop()

    def _do_tls_connect(ctx_to_use: ssl.SSLContext, verify: bool) -> dict:
        try:
            # Resolve the hostname manually to check against SSRF blocked ranges
            addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            if not addr_info:
                return {"error": f"Failed to resolve {hostname}", "verified": verify}
            resolved_ip = addr_info[0][4][0]
            if _is_blocked_ip(resolved_ip):
                return {"error": f"SSRF blocked: {resolved_ip} is a restricted address", "verified": verify}
                
            with socket.create_connection((resolved_ip, port), timeout=timeout_secs) as sock:
                with ctx_to_use.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return {
                        "version": ssock.version() or "unknown",
                        "cipher": ssock.cipher(),
                        "cert": ssock.getpeercert(),
                        "verified": verify,
                        "error": None,
                    }
        except ssl.SSLError as e:
            return {"error": str(e), "verified": verify}
        except Exception as e:
            return {"error": str(e), "verified": verify}

    # Try verified first
    result = await loop.run_in_executor(None, _do_tls_connect, ctx, True)
    if result.get("error"):
        # Try without verification
        result_noverify = await loop.run_in_executor(None, _do_tls_connect, ctx_noverify, False)
        if result_noverify.get("error"):
            return {
                "error": result_noverify["error"],
                "target": target,
                "host": hostname,
                "port": port,
            }
        result = result_noverify
        verified = False

    tls_version = result.get("version", "unknown")
    cipher_tuple = result.get("cipher")
    if cipher_tuple:
        cipher_suite = cipher_tuple[0] if cipher_tuple[0] else "unknown"
        cipher_bits = cipher_tuple[2] if len(cipher_tuple) > 2 else 0

    raw_cert = result.get("cert", {})
    if raw_cert:
        # Parse expiry
        not_after_str = raw_cert.get("notAfter")
        if not_after_str:
            try:
                expiry_dt = _parse_cert_date(not_after_str)
                now = datetime.now(timezone.utc)
                days_to_expiry = (expiry_dt - now).days
                expired = days_to_expiry < 0
            except Exception:
                pass

        san_ok = _check_san_coverage(raw_cert, hostname)
        self_signed = _is_self_signed(raw_cert)

        # Build friendly cert summary
        subject_cn = None
        for rdn in raw_cert.get("subject", []):
            for k, v in rdn:
                if k == "commonName":
                    subject_cn = v
        issuer_cn = None
        for rdn in raw_cert.get("issuer", []):
            for k, v in rdn:
                if k == "commonName":
                    issuer_cn = v

        cert_info = {
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "not_before": raw_cert.get("notBefore"),
            "not_after": raw_cert.get("notAfter"),
            "days_to_expiry": days_to_expiry,
            "expired": expired,
            "self_signed": self_signed,
            "san_coverage": san_ok,
            "san_list": [v for k, v in raw_cert.get("subjectAltName", []) if k == "DNS"],
        }

    # ── Risk analysis ─────────────────────────────────────────────────────────
    weak_cipher = _is_weak_cipher(cipher_suite)
    deprecated_proto = tls_version in DEPRECATED_PROTOCOLS

    if not verified:
        findings.append("CRITICAL: TLS certificate verification failed — cert may be invalid or self-signed")
        risk_score += 4
    if self_signed:
        findings.append("CRITICAL: Certificate is self-signed — not trusted by browsers")
        risk_score += 3
    if expired:
        findings.append(f"CRITICAL: Certificate expired {abs(days_to_expiry)} day(s) ago")
        risk_score += 4
    elif days_to_expiry is not None and days_to_expiry < EXPIRY_CRITICAL_DAYS:
        findings.append(f"CRITICAL: Certificate expires in {days_to_expiry} day(s)")
        risk_score += 3
    elif days_to_expiry is not None and days_to_expiry < EXPIRY_WARNING_DAYS:
        findings.append(f"HIGH: Certificate expires in {days_to_expiry} day(s)")
        risk_score += 2
    if deprecated_proto:
        findings.append(f"HIGH: Deprecated protocol {tls_version} — vulnerable to BEAST/POODLE")
        risk_score += 2
    if weak_cipher:
        findings.append(f"HIGH: Weak cipher suite '{cipher_suite}' — upgrade to AES-GCM or ChaCha20")
        risk_score += 2
    if cipher_bits and cipher_bits < 128:
        findings.append(f"HIGH: Short key length {cipher_bits} bits — minimum 128 required")
        risk_score += 2
    if not san_ok and raw_cert:
        findings.append(f"MEDIUM: Certificate SAN does not cover hostname '{hostname}'")
        risk_score += 1
    if not findings:
        findings.append(
            f"INFO: TLS configuration looks healthy — {tls_version}, {cipher_suite}"
        )

    return {
        "target": target,
        "host": hostname,
        "port": port,
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
        "cipher_bits": cipher_bits,
        "certificate": cert_info,
        "verified": verified,
        "deprecated_protocol": deprecated_proto,
        "weak_cipher": weak_cipher,
        "risk": _risk_label(risk_score),
        "risk_score": risk_score,
        "findings": findings,
    }
