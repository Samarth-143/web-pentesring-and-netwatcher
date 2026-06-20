# PHANTOM v3.0 – Project Requirements

## 1. Project Overview

PHANTOM v3.0 is a full‑stack web application penetration‑testing and monitoring framework that provides automated security assessments, real‑time network anomaly detection (Net‑Watch), professional PDF reporting, scan history, authentication, and scheduling, built on a FastAPI backend and a React/Vite frontend.

Goals:
- Enable repeatable, automated web app and network security testing via 18+ focused modules.
- Provide an operator‑friendly dashboard for running scans, monitoring Net‑Watch, reviewing history, and exporting reports.
- Meet production‑grade security and reliability standards using the hardening blueprint (input validation, privilege separation, SSRF defense, Celery/Redis, and API gateway controls).

---

## 2. Functional Requirements

### 2.1 Core Backend & API

- Implement a FastAPI application named `PHANTOM` (`backend/main.py`) that exposes JSON REST APIs and a WebSocket endpoint.
- Enable CORS only for configured frontend origins (local dev and production domains via environment variable).
- All scanning endpoints accept a common request body schema: `target: str`, `options: Optional[dict]` with module‑specific options.
- Provide a root `GET /` endpoint returning framework metadata (name, version, total module count, WebSocket URL).
- Provide a `POST /api/full-scan` endpoint that orchestrates multiple modules concurrently and returns an aggregated result object keyed by module ID.

### 2.2 Security Testing Modules (Reconnaissance)

Implement the following modules under `backend/modules/` and expose them via corresponding POST API routes:

1. **Port Scanner (`port_scanner.py`)**  
   - Use Nmap via `python-nmap` or subprocess wrapper.  
   - Accept configurable port ranges and scan arguments from a controlled allow‑list.  
   - Identify high‑risk ports and return per‑port metadata (service, product, version, CPE), OS guess, scan stats, and module risk rating.

2. **Subdomain Enumerator (`subdomain_enum.py`)**  
   - Implement DNS brute‑force using a fixed 80‑entry wordlist and concurrency controls.  
   - Integrate Certificate Transparency lookup (`crt.sh`) as a second discovery method.  
   - Return discovered subdomains with IPs, HTTP status probes, high‑value labels, and summary counts.

3. **Directory Enumerator (`dir_enum.py`)**  
   - Use `aiohttp` with connection limits and timeouts for path brute‑force.  
   - Probe a curated 80‑entry path wordlist (admin, backups, config, debug, API endpoints).  
   - Flag sensitive resources (e.g., `.env`, `.git`, `config.php`, SQL dumps) and compute module risk based on findings.

4. **WAF Detector (`waf_detect.py`)**  
   - Fingerprint common WAF vendors via headers, cookies, and response behavior (Cloudflare, CloudFront, Akamai, Sucuri, ModSecurity, F5 BIG‑IP, Imperva, Barracuda, FortiWeb).  
   - Use benign and attack‑like probes to infer behavior and confidence score.

5. **WHOIS Lookup (`whois_lookup.py`)**  
   - Use `python-whois` to fetch WHOIS records and compute days to expiry and expiring‑soon flag.  
   - Normalize list fields and return registrar, dates, status, contact hints, and DNSSEC status.

6. **DNS Recon (`dns_recon.py`)**  
   - Query A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records using `dnspython`.  
   - Evaluate SPF/DMARC for email spoofing risk.  
   - Attempt limited AXFR zone transfers and flag success as critical.

### 2.3 Exploit & Vulnerability Detection Modules

7. **SQL Injection Tester (`sqli_tester.py`)**  
   - Test multiple payload classes (error‑based, boolean‑based, time‑based, union, auth bypass, command‑like) against common query parameters.  
   - Use timing thresholds, error signatures, and response length differences to infer SQLi; compute CVSS‑style score and module risk.

8. **XSS Detector (`xss_detector.py`)**  
   - Inject reflected XSS payloads into GET/POST parameters and detect confirmed vs possible reflection.  
   - Take into account CSP headers and assign severity and remediation guidance.

9. **CVE Lookup (`cve_lookup.py`)**  
   - Integrate with NVD REST API v2, query by keyword or software name, handle rate limits/timeouts.  
   - Normalize CVSS v3.x/v2 metrics, sort by score, compute counts of critical/high CVEs and module risk level.

10. **CSRF Detector (`csrf_detector.py`)**  
   - Discover forms and CSRF token patterns, evaluate SameSite cookie flags and basic CORS behavior.  
   - Attempt test submissions when safe and flag missing tokens, weak SameSite, or wildcard CORS.

11. **SSRF Detector (`ssrf_detector.py`)**  
   - Probe common SSRF parameters with internal IPs, metadata endpoints, alternative encodings, and dangerous schemes.  
   - Detect behavior differences and metadata leakage, compute criticality if cloud metadata is exposed.

12. **XXE Detector (`xxe_detector.py`)**  
   - Test for XXE file disclosure and SSRF via XML payloads and multiple content types.  
   - Identify parser errors and behavior that indicate XXE processing; provide specific remediation actions.

13. **Broken Auth Tester (`auth_tester.py`)**  
   - Check for default credentials, username enumeration, missing brute‑force protections, weak session cookies, and weak password policies.  
   - Detect JWT misconfigurations (e.g., `alg=none`) where applicable.

14. **Open Redirect Tester (`open_redirect.py`)**  
   - Test typical redirect parameters with safe and malicious URLs, confusion tricks, and CRLF injection patterns.  
   - Flag confirmed redirects to attacker‑controlled origins and potential CRLF vulnerabilities.

### 2.4 Audit Modules

15. **HTTP Header Analyzer (`header_analyzer.py`)**  
   - Evaluate presence/absence of key security headers (HSTS, CSP, XFO, XCTO, Referrer‑Policy, Permissions‑Policy, X‑XSS‑Protection, Cache‑Control).  
   - Compute a percentage score, grade (A–F), list dangerous headers leaking stack details, and suggest fixes.

16. **SSL/TLS Analyzer (`ssl_analyzer.py`)**  
   - Inspect certificate validity, dates, SANs, protocol version, cipher suite, and key size for a TCP endpoint.  
   - Flag expired/soon‑to‑expire certs, weak protocols (SSLv2/3, TLS 1.0/1.1), and known weak cipher families.

### 2.5 Monitoring Module – Net‑Watch

17. **Net‑Watch Traffic Monitor (`traffic_monitor.py`)**  
   - Capture packets via Scapy and maintain per‑IP baselines for packets‑per‑second and bytes‑per‑second over rolling windows.  
   - Compute z‑scores and classify anomalies (`DDOS_SUSPECTED`, `TRAFFIC_SPIKE`, `ELEVATED_TRAFFIC`, `PORT_SCAN`, `TRAFFIC_DROP`, `LOW_TRAFFIC`, `learning`, `normal`).  
   - Stream periodic JSON snapshots to clients over `WS /wstraffic?interface=...` and provide `GET /api/traffic/snapshot` for polling.

### 2.6 Reporting Module

18. **PDF Report Generator (`report_gen.py`)**  
   - Generate an A4 penetration‑test report via ReportLab with an executive summary, metrics table, and per‑module findings using color‑coded risk sections.  
   - Take `scan_results` from the backend and embed key metrics, issues, and remediation snippets; return base64 PDF and meta data.

### 2.7 Authentication & Authorization

- Implement JWT‑based authentication (`backend/auth/auth.py`) with:
  - Secure password hashing (bcrypt via passlib) and configurable `SECRET_KEY`, algorithm, and token expiry.
  - Login endpoint (`POST /auth/login`) returning access token and user role.  
  - `GET /auth/me` for token introspection and optional API‑key management for admin users.
- Provide `get_current_user` and `require_admin` dependencies to gate all sensitive API routes.  
- Ensure all `/api/*` routes require valid authentication tokens in production, with only explicitly allowed public endpoints (e.g., limited stats) exposed anonymously.

### 2.8 Database & Scan History

- Use SQLAlchemy 2.x with async engine and SQLite (`phantom.db`) or Postgres via `DATABASE_URL` for:
  - `ScanSession` table: session metadata, target, timestamps, status, modules run, overall risk.  
  - `ScanResult` table: per‑module results (risk, vulnerable flag, duration, JSON payload, errors).  
  - `Alert` table: normalized, cross‑module alerts with severity and acknowledgment flag.
- Provide CRUD services for creating/completing sessions, storing results, computing platform statistics, and searching scan history.
- API routes:
  - `GET /api/history` with pagination.  
  - `GET /api/history/{session_id}` for full detail.  
  - `DELETE /api/history/{session_id}` for cleanup.  
  - `GET /api/stats` for summary metrics (total scans, critical findings, targets, scans today, top risky targets, module usage).

### 2.9 Scan Scheduling

- Integrate APScheduler with a SQLAlchemy job store to support scheduled scans.
- Implement job operations:
  - Add recurring interval scans, cron‑style schedules, and one‑time runs for a set of modules and a target.  
  - List, pause, resume, and delete jobs via `/api/schedule` endpoints.
- Ensure scheduled scans create `ScanSession` and `ScanResult` records and integrate with alerting.

### 2.10 Frontend Requirements

- Build a single‑page React/Vite application (`frontend/src/App.jsx`) implementing the PHANTOM v3.0 dashboard with:
  - Fixed header containing logo, target input, run‑scan button, export PDF button, and auth controls.  
  - Left sidebar for module selection and navigation (Recon, Exploit, Audit, Monitoring, Assessment, History, Schedule).  
  - Main content area for per‑module results and full‑scan aggregation view using reusable components (RiskPill, ResultNode, NetWatchPanel, ScanProgress, EmptyState, summary cards).  
  - Right activity/log panel and scan status bar.
- Implement Net‑Watch UI using `useTrafficAnomalies` hook and `AnomalyDetector` component powered by WebSocket data.
- Implement dedicated pages for:
  - **Login** (token storage, error handling, logout).  
  - **History** (scan list, filters, detail drawer, PDF generation).  
  - **Schedule** (new schedule form, jobs table, actions).

- All API calls must go through a centralized `api.js` helper that automatically injects JWT bearer tokens and handles 401 by redirecting to login.

---

## 3. Non‑Functional Requirements

### 3.1 Security & Hardening

- Enforce strict input validation for targets and options using ReDoS‑safe regexes for IPv4, IPv6, FQDNs, and URLs.
- Eliminate command and argument injection by:
  - Never using `shell=True` in subprocess calls.  
  - Passing structured argument lists with double‑dash separators and allow‑listed flags only.
- Isolate Scapy raw socket operations in a dedicated daemon/process with Linux capabilities (`CAP_NET_RAW`, optional `CAP_NET_ADMIN`) and communicate via Unix domain sockets.
- Defend against SSRF and DNS rebinding by:
  - Using a custom `aiohttp` connector that blocks private, loopback, metadata, and special ranges at connection time.  
  - Routing outbound HTTP through a hardened egress proxy with allow‑lists.
- Harden the HTTP interface:
  - Run FastAPI behind Nginx/Envoy/HAProxy; never expose Uvicorn directly to the internet.  
  - Enforce TLS 1.2+ and strong ciphers at the proxy.  
  - Disable or protect OpenAPI/Swagger docs in production.
- Implement distributed rate limiting using a Redis‑backed token‑bucket algorithm, keyed by authenticated user/API key rather than IP.
- Run all application containers as non‑root users, drop unneeded capabilities, and avoid `--privileged` mode.

### 3.2 Performance & Scalability

- Offload long‑running scans and report generation to Celery workers with Redis as broker and result backend; avoid FastAPI `BackgroundTasks` for heavy work.
- Design tasks to be idempotent, support progress updates (`PROGRESS` states), and scale horizontally by adding workers.
- UI should remain responsive under concurrent scans, using asynchronous calls, background polling, or WebSockets for progress.

### 3.3 Reliability & Observability

- Persist all scan sessions and results to the database; avoid in‑memory‑only state so that restarts do not lose work.
- Implement structured JSON logging for API, workers, and anomaly engine including user, target, modules, risk, and timing where relevant.
- Provide health checks for backend and frontend components.

### 3.4 Usability & UX

- Adhere to the “cyberpunk luxury” design system: consistent typography (Syne, DM Sans, JetBrains Mono), dark theme, semantic color usage for risk and module types.
- Keep high‑density data (ports, CVEs, headers, Net‑Watch telemetry) readable via clear hierarchy, spacing, and interactive components rather than raw JSON dumps.
- Provide clear remediation guidance per module so findings are actionable, not just detection results.

### 3.5 Legal & Ethical

- Include a clear legal disclaimer in README and UI stating the tool must only be used on systems the user owns or is explicitly authorized to test.
- Provide a curated list of safe practice targets (DVWA, WebGoat, public test sites, HTB/THM via VPN) in the README and documentation.

---

## 4. Technology Stack & Dependencies

### 4.1 Backend

- Language: Python 3.11+.
- Framework: FastAPI, Uvicorn (ASGI server).
- Key libraries:
  - Core: `pydantic`, `python-multipart`, `websockets`.  
  - Pentest: `python-nmap`, `requests`, `aiohttp`, `beautifulsoup4`, `dnspython`, `python-whois`, `scapy`, `reportlab`.  
  - Database: `sqlalchemy`, `alembic`, `aiosqlite` (or driver for selected DB).  
  - Auth: `python-jose[cryptography]`, `passlib[bcrypt]`.  
  - Scheduling: `apscheduler`.  
  - Optional: `redis`, `celery` for distributed task queues.

### 4.2 Frontend

- Language: TypeScript/JavaScript (ESNext).
- Framework: React 18 + Vite bundler.
- Libraries: `recharts` for charts, `lucide-react` for icons, Tailwind or equivalent utility CSS (or custom CSS implementing the design tokens).

### 4.3 Infrastructure

- Running Environment: Windows with Python 3.11+ and Node.js 20+, using the included PowerShell script for local deployments.
- Reverse proxy: Nginx (or equivalent) for static serving of frontend, API/WebSocket proxying, security headers, gzip, and SPA routing.
- OS‑level requirements: Nmap binary, libpcap, and Npcap equivalent on Windows for Scapy.

---

## 5. Environment & Configuration Requirements

- Use environment variables (or secrets manager) for all sensitive configuration:
  - `PHANTOM_SECRET`, `DATABASE_URL`, `NVD_API_KEY`, CORS origins, Redis URL, scheduler DB URL, proxy configuration.
- Provide `.env.example` files for backend and frontend showing non‑secret defaults and configuration fields.
- Ensure cloud deployments lock down metadata service access (IMDS hardening) as part of SSRF defense.

---

## 6. Deployment Requirements

- Provide a `start_phantom.ps1` PowerShell script to run the full stack.
- Expose backend on 8000 (internal) and frontend on 5173 (public or behind proxy), with WebSocket proxying configured for `/wstraffic`.
- Document commands for:
  - Starting the stack manually or via script.  
  - Viewing logs and status.

---

## 7. Testing & CI/CD Requirements

- Implement pytest test suites for key modules and API endpoints using `pytest-asyncio` and `httpx.AsyncClient`, with external calls mocked.
- Add GitHub Actions (or equivalent) CI workflow to:
  - Run backend tests and collect coverage.  
  - Build frontend and optionally run frontend tests.  
  - Run security tooling (`bandit`, `safety`, `npm audit`).
- Add a final verification checklist (imports, API health, frontend build, tests, security scan) to be completed before tagging a release.

---

## 8. Operational Requirements

- Maintain up‑to‑date documentation (README, REQUIREMENTS, module reference, and safe target list) in the repo root.
- Provide resume‑ready bullet points summarizing PHANTOM’s capabilities and architecture for use in portfolio and case studies.
- Keep a changelog reflecting major feature additions (modules, Net‑Watch, auth, scheduler, deployment).