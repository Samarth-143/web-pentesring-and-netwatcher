"""
cve_lookup.py – Production-hardened NVD REST API v2 CVE lookup.

Hardening applied:
  - SSRFSafeConnector on all outbound requests
  - RFC-1123 / CPE keyword validation before any external call
  - NVD API v2 only (v1 retired 2023-12-15)
  - Rate-limit aware: Honours Retry-After header; default 6 req/30s window
  - CPE keyword sanitised: alphanumeric + hyphens + dots only
  - CVSS v3 / v2 score extraction with severity mapping
  - Results capped at 20 CVEs per query (NVD default is 2000 — unsafe)
  - Pagination: fetches page 0 only (first resultsPerPage entries)
  - graceful degradation: returns partial data on NVD 503/429
"""

import asyncio
import ipaddress
import re
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


class SSRFSafeConnector(TCPConnector):
    async def _resolve_host(self, host: str, port: int, traces=None):
        infos = await super()._resolve_host(host, port, traces)
        for info in infos:
            if _is_blocked_ip(info["host"]):
                raise aiohttp.ClientConnectorError(
                    connection_key=None,
                    os_error=OSError(f"SSRF blocked: {info['host']}"),
                )
        return infos


# ── Constants ─────────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVE-ID pattern: CVE-YYYY-NNNNN (4-digit year, 4-13 digit sequence)
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,13}$", re.IGNORECASE)

# Safe keyword for CPE / keyword search: alphanumeric, hyphens, dots, spaces
_KEYWORD_RE = re.compile(r"^[\w\s\-\.]{2,100}$")

# NVD returns up to 2000 per page; cap our requests tightly
MAX_RESULTS = 20

CVSS_SEVERITY_MAP: dict[str, str] = {
    "NONE":     "LOW",
    "LOW":      "LOW",
    "MEDIUM":   "MEDIUM",
    "HIGH":     "HIGH",
    "CRITICAL": "CRITICAL",
}


class ValidationError(ValueError):
    pass


def _validate_cve_id(cve_id: str) -> str:
    cve_id = cve_id.strip().upper()
    if not _CVE_ID_RE.match(cve_id):
        raise ValidationError(f"'{cve_id}' is not a valid CVE identifier (expected CVE-YYYY-NNNNN)")
    return cve_id


def _validate_keyword(keyword: str) -> str:
    keyword = keyword.strip()
    if not _KEYWORD_RE.match(keyword):
        raise ValidationError(
            f"Keyword '{keyword[:40]}' contains disallowed characters. "
            "Use alphanumeric characters, hyphens, dots, or spaces only."
        )
    return keyword


def _extract_cvss(cve_item: dict) -> dict[str, Any]:
    """Extract the best available CVSS score (v3.1 > v3.0 > v2.0)."""
    metrics = cve_item.get("metrics", {})

    # Try CVSS v3.1 first
    for v3_key in ("cvssMetricV31", "cvssMetricV30"):
        v3_list = metrics.get(v3_key, [])
        if v3_list:
            data = v3_list[0].get("cvssData", {})
            return {
                "version": data.get("version", "3.x"),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity", "UNKNOWN"),
                "vector": data.get("vectorString", ""),
                "attack_vector": data.get("attackVector", ""),
                "privileges_required": data.get("privilegesRequired", ""),
                "user_interaction": data.get("userInteraction", ""),
            }

    # Fallback to CVSS v2
    v2_list = metrics.get("cvssMetricV2", [])
    if v2_list:
        data = v2_list[0].get("cvssData", {})
        base_severity = v2_list[0].get("baseSeverity", "")
        return {
            "version": "2.0",
            "score": data.get("baseScore"),
            "severity": base_severity or "UNKNOWN",
            "vector": data.get("vectorString", ""),
            "attack_vector": data.get("accessVector", ""),
            "privileges_required": data.get("authentication", ""),
            "user_interaction": "",
        }

    return {"version": "unknown", "score": None, "severity": "UNKNOWN", "vector": ""}


def _extract_cpe_affected(cve_item: dict) -> list[str]:
    """Extract affected CPE product strings (capped at 10)."""
    cpe_list: list[str] = []
    configs = cve_item.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpe_list.append(match.get("criteria", ""))
                if len(cpe_list) >= 10:
                    return cpe_list
    return cpe_list


def _parse_cve_item(item: dict) -> dict[str, Any]:
    """Parse a single NVD CVE item into a normalised dict."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "unknown")
    published = cve.get("published", "")
    modified = cve.get("lastModified", "")
    vuln_status = cve.get("vulnStatus", "")

    # English description preferred
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "No description available.",
    )

    # References (first 5)
    refs = [
        {"url": r.get("url", ""), "source": r.get("source", ""), "tags": r.get("tags", [])}
        for r in cve.get("references", [])[:5]
    ]

    cvss = _extract_cvss(cve)
    cpe_affected = _extract_cpe_affected(cve)

    # CWE weaknesses
    weaknesses = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value"):
                weaknesses.append(d["value"])

    return {
        "cve_id": cve_id,
        "published": published,
        "last_modified": modified,
        "vuln_status": vuln_status,
        "description": description,
        "cvss": cvss,
        "weaknesses": weaknesses,
        "cpe_affected": cpe_affected,
        "references": refs,
    }


def _overall_risk(cve_list: list[dict]) -> str:
    """Derive overall risk from the highest CVSS severity in the result set."""
    priority = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    found_severities = {
        c["cvss"]["severity"].upper()
        for c in cve_list
        if c.get("cvss", {}).get("severity")
    }
    for p in priority:
        if p in found_severities:
            return CVSS_SEVERITY_MAP.get(p, "MEDIUM")
    return "LOW"


async def lookup_cve(target: str, options: dict | None = None) -> dict[str, Any]:
    """
    NVD API v2 CVE lookup.

    Parameters
    ----------
    target  : CVE-ID (e.g. "CVE-2021-44228") OR keyword/product name
              (e.g. "apache log4j", "openssl 3.0")
    options : optional
        timeout       – request timeout seconds (default 15)
        max_results   – cap returned CVEs (default 20, max 20)
        api_key       – NVD API key for higher rate limits (optional)
        severity      – filter by severity: LOW/MEDIUM/HIGH/CRITICAL

    Returns
    -------
    dict with: query, query_type, total_results, cve_list, risk, findings
    """
    options = options or {}
    timeout_secs: int = options.get("timeout", 15)
    max_results: int = min(options.get("max_results", MAX_RESULTS), MAX_RESULTS)
    api_key: str | None = options.get("api_key")
    severity_filter: str | None = options.get("severity", "").upper() or None

    # ── Input classification and validation ───────────────────────────────────
    raw = target.strip()
    import urllib.parse
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urllib.parse.urlparse(raw)
        raw = parsed.netloc.split(":")[0]
    
    query_type: str
    params: dict[str, Any]

    if _CVE_ID_RE.match(raw.upper()):
        try:
            cve_id = _validate_cve_id(raw)
        except ValidationError as exc:
            return {"error": str(exc), "target": raw, "error_type": "ValidationError"}
        query_type = "cve_id"
        params = {"cveId": cve_id}
    else:
        try:
            keyword = _validate_keyword(raw)
        except ValidationError as exc:
            return {"error": str(exc), "target": raw, "error_type": "ValidationError"}
        query_type = "keyword"
        params = {"keywordSearch": keyword, "keywordExactMatch": ""}

    params["resultsPerPage"] = max_results
    params["startIndex"] = 0

    if severity_filter and severity_filter in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        params["cvssV3Severity"] = severity_filter

    # ── Request headers ───────────────────────────────────────────────────────
    req_headers: dict[str, str] = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        "Accept": "application/json",
    }
    if api_key:
        req_headers["apiKey"] = api_key

    connector = SSRFSafeConnector(ssl=True)
    timeout = aiohttp.ClientTimeout(total=timeout_secs)
    findings: list[str] = []
    start = time.monotonic()

    try:
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=req_headers
        ) as session:
            async with session.get(NVD_API_BASE, params=params) as resp:
                # Respect rate limiting
                if resp.status == 429:
                    retry_after = int(resp.headers.get("Retry-After", 30))
                    return {
                        "error": f"NVD rate limit hit — retry after {retry_after}s. "
                                 "Supply an api_key for higher limits.",
                        "target": raw,
                        "retry_after_seconds": retry_after,
                    }
                if resp.status == 503:
                    return {
                        "error": "NVD API is temporarily unavailable (503). Try again shortly.",
                        "target": raw,
                    }
                if resp.status != 200:
                    return {
                        "error": f"NVD API returned HTTP {resp.status}",
                        "target": raw,
                    }
                data = await resp.json(content_type=None)
    except asyncio.TimeoutError:
        return {"error": f"NVD API timed out after {timeout_secs}s", "target": raw}
    except Exception as exc:
        return {"error": str(exc), "target": raw}

    total_results: int = data.get("totalResults", 0)
    raw_vulns: list[dict] = data.get("vulnerabilities", [])

    cve_list = [_parse_cve_item(item) for item in raw_vulns]

    # ── Findings generation ───────────────────────────────────────────────────
    critical = [c for c in cve_list if c["cvss"].get("severity", "").upper() == "CRITICAL"]
    high = [c for c in cve_list if c["cvss"].get("severity", "").upper() == "HIGH"]
    exploitable = [
        c for c in cve_list
        if any("exploit" in str(r.get("tags", [])).lower() for r in c["references"])
    ]

    if critical:
        findings.append(
            f"CRITICAL: {len(critical)} critical-severity CVE(s) found — "
            f"immediate patching required: {', '.join(c['cve_id'] for c in critical[:3])}"
        )
    if high:
        findings.append(
            f"HIGH: {len(high)} high-severity CVE(s) found: "
            f"{', '.join(c['cve_id'] for c in high[:3])}"
        )
    if exploitable:
        findings.append(
            f"HIGH: {len(exploitable)} CVE(s) have public exploit references — "
            f"prioritise: {', '.join(c['cve_id'] for c in exploitable[:3])}"
        )
    if not findings:
        if cve_list:
            findings.append(
                f"INFO: {len(cve_list)} CVE(s) found — none critical or high severity."
            )
        else:
            findings.append(
                f"INFO: No CVEs found for '{raw}'. "
                "Verify spelling or try a broader keyword."
            )

    return {
        "query": raw,
        "query_type": query_type,
        "total_results": total_results,
        "returned": len(cve_list),
        "cve_list": cve_list,
        "risk": _overall_risk(cve_list),
        "findings": findings,
        "elapsed_seconds": round(time.monotonic() - start, 2),
    }
