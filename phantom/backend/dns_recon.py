"""
dns_recon.py – Production-hardened async DNS reconnaissance.

Hardening applied:
  - RFC-1123 domain validation
  - AXFR timeout reduced to 3s per spec
  - AXFR records capped at 20 node names per spec
  - findings list: collects human-readable non-null warnings
  - email_security.mx_records is bool (per PHANTOM spec, not list)
  - Fully parallel record resolution via asyncio.gather + run_in_executor
"""

import asyncio
import re
import socket
from typing import Any

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.rdatatype
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

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
    return domain.split("/")[0].lower().strip().rstrip(".")


def _validate_domain(domain: str) -> str:
    if not _DOMAIN_RE.match(domain):
        raise ValidationError(f"'{domain}' is not a valid domain name")
    return domain


def _records_to_list(answer) -> list[str]:
    try:
        return [r.to_text() for r in answer]
    except Exception:
        return []


async def _resolve_record(
    resolver: "dns.resolver.Resolver",
    domain: str,
    rtype: str,
    loop: asyncio.AbstractEventLoop,
) -> tuple[str, list[str]]:
    def _query():
        try:
            answer = resolver.resolve(domain, rtype)
            return _records_to_list(answer)
        except Exception:
            return []

    records = await loop.run_in_executor(None, _query)
    return rtype, records


def _attempt_axfr(ns_host: str, domain: str) -> dict[str, Any]:
    """Attempt AXFR zone transfer with 3s timeout. Return up to 20 node names."""
    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=3))
        nodes = [str(name) for name in z.nodes.keys()][:20]
        return {"ns": ns_host, "vulnerable": True, "record_count": len(z.nodes), "records": nodes}
    except dns.exception.FormError:
        return {"ns": ns_host, "vulnerable": False, "reason": "AXFR refused"}
    except Exception as exc:
        return {"ns": ns_host, "vulnerable": False, "reason": str(exc)}


async def dns_recon(target: str) -> dict[str, Any]:
    """
    Async DNS reconnaissance.

    Returns
    -------
    dict with: target, records (per-type lists), email_security,
               zone_transfer_vulnerable, zone_transfer_data, risk, findings
    On validation error: {error, target, error_type}
    """
    if not _DNS_AVAILABLE:
        return {"error": "dnspython is not installed", "target": target}

    raw = _normalize_domain(target)
    try:
        domain = _validate_domain(raw)
    except ValidationError as exc:
        return {"error": str(exc), "target": raw, "error_type": "ValidationError"}

    loop = asyncio.get_event_loop()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    # ── Parallel record resolution ─────────────────────────────────────────
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    tasks = [_resolve_record(resolver, domain, rt, loop) for rt in record_types]
    results = await asyncio.gather(*tasks)
    records: dict[str, list[str]] = {rt: recs for rt, recs in results}

    # ── Email security analysis ────────────────────────────────────────────
    txt_records = records.get("TXT", [])
    mx_records = records.get("MX", [])

    spf_configured = any("v=spf1" in t.lower() for t in txt_records)
    spf_record = next((t for t in txt_records if "v=spf1" in t.lower()), None)

    def _get_dmarc():
        try:
            ans = resolver.resolve(f"_dmarc.{domain}", "TXT")
            return _records_to_list(ans)
        except Exception:
            return []

    dmarc_records = await loop.run_in_executor(None, _get_dmarc)
    dmarc_configured = any("v=dmarc1" in r.lower() for r in dmarc_records)

    email_spoofing_risk = not spf_configured or not dmarc_configured

    email_security: dict[str, Any] = {
        "spf_configured": spf_configured,
        "spf_record": spf_record,
        "dmarc_configured": dmarc_configured,
        "dmarc_record": dmarc_records[0] if dmarc_records else None,
        "mx_records": bool(mx_records),       # bool per PHANTOM spec
        "email_spoofing_risk": email_spoofing_risk,
    }

    # ── Zone transfer attempts (up to 2 NS servers, 3s timeout each) ──────
    ns_hosts: list[str] = []
    for ns_record in records.get("NS", [])[:2]:
        ns_name = ns_record.rstrip(".")
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, ns_name)
            ns_hosts.append(ip)
        except Exception:
            ns_hosts.append(ns_name)

    zone_transfer_data: list[dict] = []
    if ns_hosts:
        axfr_tasks = [loop.run_in_executor(None, _attempt_axfr, ns, domain) for ns in ns_hosts]
        axfr_results = await asyncio.gather(*axfr_tasks, return_exceptions=True)
        for r in axfr_results:
            if isinstance(r, dict):
                zone_transfer_data.append(r)

    zone_transfer_vulnerable = any(r.get("vulnerable") for r in zone_transfer_data)

    # ── Findings: human-readable warnings ─────────────────────────────────
    findings: list[str] = []
    if zone_transfer_vulnerable:
        findings.append("CRITICAL: Zone transfer (AXFR) succeeded — full DNS zone exposed")
    if not spf_configured:
        findings.append("HIGH: No SPF record found — domain vulnerable to email spoofing")
    if not dmarc_configured:
        findings.append("HIGH: No DMARC record found — phishing/spoofing risk")
    if not mx_records:
        findings.append("INFO: No MX records found — domain may not receive email")

    # ── Risk assessment ────────────────────────────────────────────────────
    if zone_transfer_vulnerable:
        risk = "CRITICAL"
    elif email_spoofing_risk:
        risk = "HIGH"
    else:
        risk = "LOW"

    return {
        "target": domain,
        "records": records,
        "email_security": email_security,
        "zone_transfer_vulnerable": zone_transfer_vulnerable,
        "zone_transfer_data": zone_transfer_data,
        "risk": risk,
        "findings": findings,
    }
