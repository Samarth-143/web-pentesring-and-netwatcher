# Phantom Module Reference

This document provides technical details on the 16 scanning modules available in the Phantom automation suite.

## Reconnaissance Modules

### 1. Port Scanner (`port_scanner.py`)
- **Purpose**: Identifies open TCP ports on a target host.
- **Methodology**: Uses `asyncio.open_connection` to asynchronously attempt TCP handshakes against a predefined list of 1000 common ports.
- **Output**: List of open ports with the associated service names (e.g., `80: HTTP`, `443: HTTPS`).

### 2. DNS Recon (`dns_recon.py`)
- **Purpose**: Extracts DNS records for a target domain.
- **Methodology**: Utilizes the `dnspython` library to query `A`, `AAAA`, `MX`, `NS`, and `TXT` records.
- **Output**: JSON dictionary categorizing records by type.

### 3. WHOIS Lookup (`whois_lookup.py`)
- **Purpose**: Retrieves domain registration and ownership details.
- **Methodology**: Uses the `python-whois` library.
- **Output**: Registrar details, creation/expiration dates, and name servers.

### 4. Subdomain Enumeration (`subdomain_enum.py`)
- **Purpose**: Discovers active subdomains for a given root domain.
- **Methodology**: Uses a predefined wordlist of common subdomains (e.g., `www`, `mail`, `admin`, `api`) and attempts to resolve them asynchronously using `socket.gethostbyname`.
- **Output**: List of resolvable subdomains and their corresponding IP addresses.

### 5. Directory Enumeration (`dir_enum.py`)
- **Purpose**: Finds hidden or unlinked directories on a web server.
- **Methodology**: Sends HTTP GET requests to common paths (`/admin`, `/backup`, `/api`) and records responses with status codes `200`, `301`, `302`, or `403`.
- **Output**: List of discovered URL paths and their HTTP status codes.

---

## Exploitation Modules

### 6. SQLi Tester (`sqli_tester.py`)
- **Purpose**: Detects potential SQL Injection vulnerabilities in URL parameters.
- **Methodology**: Appends common SQLi payloads (e.g., `' OR '1'='1`) to the URL and analyzes the HTTP response for database error signatures (e.g., "syntax error", "mysql_fetch").
- **Output**: Vulnerability status and the specific payload that triggered an error.

### 7. XSS Detector (`xss_detector.py`)
- **Purpose**: Identifies Reflected Cross-Site Scripting vulnerabilities.
- **Methodology**: Injects benign polyglot XSS payloads into URL parameters and checks if the exact payload is reflected unescaped in the raw HTML response body.
- **Output**: Boolean flag indicating vulnerability and the reflected payload.

### 8. SSRF Detector (`ssrf_detector.py`)
- **Purpose**: Tests for Server-Side Request Forgery.
- **Methodology**: Injects local loopback URLs (`http://127.0.0.1`, `http://localhost`) into parameters that might be fetched by the backend (e.g., `url=`). 
- **Output**: Warnings if the application responds favorably to internal resource requests.

### 9. XXE Detector (`xxe_detector.py`)
- **Purpose**: Detects XML External Entity injection vulnerabilities.
- **Methodology**: Sends a crafted XML payload containing an external entity definition (attempting to read `/etc/passwd` or `c:/windows/win.ini`) via `POST` requests with `Content-Type: application/xml`.
- **Output**: Flags vulnerability if root/system file contents are reflected in the response.

### 10. CSRF Detector (`csrf_detector.py`)
- **Purpose**: Identifies missing Cross-Site Request Forgery protections.
- **Methodology**: Parses HTML forms on the target page and checks for the absence of common anti-CSRF tokens (e.g., hidden inputs named `csrf_token`, `authenticity_token`).
- **Output**: List of vulnerable form endpoints.

### 11. Open Redirect (`open_redirect.py`)
- **Purpose**: Tests if URL parameters can be used to redirect users to malicious external sites.
- **Methodology**: Fuzzes parameters with payloads like `http://evil.com` and checks if the HTTP response is a `301/302` redirect pointing to the payload.
- **Output**: Boolean flag and the vulnerable parameter.

---

## Auditing Modules

### 12. CVE Lookup (`cve_lookup.py`)
- **Purpose**: Searches for known vulnerabilities associated with the target's technologies.
- **Methodology**: Queries the public CIRCL CVE API (or local NVD mirror) using keywords extracted from the server headers.
- **Output**: List of matching CVEs with CVSS scores and summaries.

### 13. SSL Analyzer (`ssl_analyzer.py`)
- **Purpose**: Evaluates the strength of the target's TLS/SSL configuration.
- **Methodology**: Uses Python's native `ssl` module to fetch the server certificate, parse the issuer, expiration date, and check for weak protocol support.
- **Output**: Certificate details and warnings for expiring certs.

### 14. Header Analyzer (`header_analyzer.py`)
- **Purpose**: Checks for missing or misconfigured security headers.
- **Methodology**: Fetches the HTTP response headers and verifies the presence of `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, etc.
- **Output**: A score out of 100 and a list of missing critical headers.

### 15. Auth Tester (`auth_tester.py`)
- **Purpose**: Detects weak authentication implementations or default credentials.
- **Methodology**: Attempts login against common endpoints (`/login`, `/admin`) using a small list of default credentials (e.g., `admin:admin`, `root:root`).
- **Output**: Flags if default credentials successfully authenticate.

### 16. WAF Detect (`waf_detect.py`)
- **Purpose**: Identifies the presence of a Web Application Firewall.
- **Methodology**: Sends intentionally malicious requests (e.g., directory traversal `../../../etc/passwd`) and analyzes the response headers (`Server`, `X-Powered-By`) and blocking behavior (e.g., `406 Not Acceptable`, Cloudflare blocks) to fingerprint the WAF.
- **Output**: Name of the detected WAF (if any).
