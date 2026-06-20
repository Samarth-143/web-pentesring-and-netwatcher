"""
whois_lookup.py – Production-hardened async WHOIS lookup.

Hardening applied:
  - RFC-1123 domain validation before any external call
  - safe_str() helper normalises list/single values (per PHANTOM spec)
  - Expiry calculation: handles list expiration_date (takes first element)
  - days_to_expire uses datetime.utcnow() for consistency
  - Graceful error return on any exception
"""

import asyncio
import re
from datetime import datetime, timezone
from typing import Any

try:
    import whois as _whois
except ImportError:
    _whois = None  # type: ignore

_DOMAIN_RE = re.compile(
    r"^(?!.{254,})((?!-)[A-Za-z0-9\-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)


class ValidationError(ValueError):
    pass


def _normalize_domain(target: str) -> str:
    domain = target.strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.split("/")[0].lower().strip()


def _validate_domain(domain: str) -> str:
    if not _DOMAIN_RE.match(domain):
        raise ValidationError(f"'{domain}' is not a valid domain name")
    return domain


def safe_str(val: Any) -> list[str] | str | None:
    """
    Normalise list vs. scalar WHOIS fields.
    Lists → [str(v) for v in val]
    Scalar → str(val)
    None → None
    """
    if val is None:
        return None
    if isinstance(val, list):
        return [str(v).strip() for v in val if v]
    return str(val).strip() or None


def _first_date(value: Any) -> datetime | None:
    """Extract first datetime from list-or-scalar field."""
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value
    return None


def _scalar(val: Any) -> str | None:
    if isinstance(val, list):
        val = val[0] if val else None
    return str(val).strip() if val else None


async def whois_lookup(target: str) -> dict[str, Any]:
    """
    Async WHOIS lookup with field normalisation and expiry computation.

    Parameters
    ----------
    target : domain or URL (scheme is stripped automatically)

    Returns
    -------
    dict with registrar, creation_date, expiration_date, updated_date,
         days_to_expire, expiring_soon, name_servers, status, emails,
         country, org, name, dnssec
    On error: {error: str, domain: str}
    """
    if _whois is None:
        return {"error": "python-whois is not installed", "domain": target}

    raw_domain = _normalize_domain(target)
    try:
        domain = _validate_domain(raw_domain)
    except ValidationError as exc:
        return {"error": str(exc), "domain": raw_domain, "error_type": "ValidationError"}

    def _run() -> Any:
        return _whois.whois(domain)

    try:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, _run)
    except Exception as exc:
        return {"error": str(exc), "domain": domain}

    # ── Dates ──────────────────────────────────────────────────────────────
    creation_date = _first_date(w.creation_date)
    expiration_date = _first_date(w.expiration_date)
    updated_date = _first_date(w.updated_date)

    # ── Expiry calc (per PHANTOM spec: uses datetime.utcnow) ───────────────
    days_to_expire: int | None = None
    expiring_soon: bool = False
    if expiration_date:
        now = datetime.utcnow()
        exp = expiration_date.replace(tzinfo=None) if expiration_date.tzinfo else expiration_date
        days_to_expire = (exp - now).days
        expiring_soon = days_to_expire < 30

    # ── Normalise fields ───────────────────────────────────────────────────
    name_servers_raw = safe_str(w.name_servers)
    if isinstance(name_servers_raw, list):
        name_servers = sorted({ns.lower() for ns in name_servers_raw if ns})
    elif name_servers_raw:
        name_servers = [name_servers_raw.lower()]
    else:
        name_servers = []

    status_raw = safe_str(w.status)
    status = status_raw if isinstance(status_raw, list) else ([status_raw] if status_raw else [])

    emails_raw = safe_str(w.emails)
    emails = emails_raw if isinstance(emails_raw, list) else ([emails_raw] if emails_raw else [])

    return {
        "domain": domain,
        "registrar": _scalar(w.registrar),
        "creation_date": creation_date.isoformat() if creation_date else None,
        "expiration_date": expiration_date.isoformat() if expiration_date else None,
        "updated_date": updated_date.isoformat() if updated_date else None,
        "days_to_expire": days_to_expire,
        "expiring_soon": expiring_soon,
        "name_servers": name_servers,
        "status": status,
        "emails": emails,
        "country": _scalar(w.country),
        "org": _scalar(w.org),
        "name": _scalar(w.name),
        "dnssec": _scalar(w.dnssec),
    }
