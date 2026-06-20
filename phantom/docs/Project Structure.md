# PHANTOM v3.0 – Recommended Project Structure

> This file describes a production‑oriented file and directory layout for the PHANTOM v3.0 full‑stack penetration testing and Net‑Watch platform.

```text
phantom/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   ├── config.py           # Pydantic settings (env vars, DB URL, CORS, secrets)
│   │   │   ├── security.py         # Auth helpers, JWT utilities, password hashing
│   │   │   ├── celery_app.py       # Celery+Redis initialization and configuration
│   │   │   ├── logging.py          # Structured logging configuration
│   │   │   └── rate_limit.py       # Redis token‑bucket limiter helpers
│   │   ├── api/
│   │   │   ├── dependencies.py     # Common FastAPI dependencies (DB session, auth)
│   │   │   └── routes/
│   │   │       ├── auth.py         # Login, token refresh, /auth/me
│   │   │       ├── scans.py        # /api/full-scan, per‑module scan orchestration
│   │   │       ├── history.py      # /api/history, /api/history/{id}
│   │   │       ├── schedule.py     # /api/schedule* endpoints
│   │   │       ├── stats.py        # /api/stats, platform metrics
│   │   │       └── traffic.py      # /wstraffic, /api/traffic/snapshot
│   │   ├── models/
│   │   │   ├── user.py             # User, role, API key models
│   │   │   ├── scan_session.py     # ScanSession ORM model
│   │   │   ├── scan_result.py      # ScanResult ORM model
│   │   │   ├── alert.py            # Normalized alert model (cross‑module)
│   │   │   └── schedule.py         # Scheduled job metadata model
│   │   ├── schemas/
│   │   │   ├── auth.py             # Pydantic schemas for login, tokens, user
│   │   │   ├── scan.py             # Request/response schemas for scans
│   │   │   ├── module_results.py   # Typed module result envelopes
│   │   │   └── schedule.py         # Schedule create/list/update schemas
│   │   ├── tasks/
│   │   │   ├── __init__.py
│   │   │   ├── scans.py            # Celery tasks that run Nmap, HTTP modules, Net‑Watch exports
│   │   │   ├── reports.py          # Celery tasks that generate PDF reports
│   │   │   └── maintenance.py      # Housekeeping tasks (old scan cleanup, stats refresh)
│   │   ├── modules/
│   │   │   ├── __init__.py
│   │   │   ├── port_scanner.py     # Nmap wrapper (recon)
│   │   │   ├── subdomain_enum.py   # Subdomain enumeration (DNS+CT)
│   │   │   ├── dir_enum.py         # Directory brute‑force via aiohttp
│   │   │   ├── waf_detect.py       # WAF fingerprinting engine
│   │   │   ├── whois_lookup.py     # WHOIS client
│   │   │   ├── dns_recon.py        # DNS+email security recon
│   │   │   ├── sqli_tester.py      # SQL injection testing engine
│   │   │   ├── xss_detector.py     # XSS detection
│   │   │   ├── cve_lookup.py       # NVD CVE lookup client
│   │   │   ├── header_analyzer.py  # HTTP security header audit
│   │   │   ├── ssl_analyzer.py     # TLS/SSL certificate and cipher analysis
│   │   │   ├── csrf_detector.py    # CSRF token, SameSite, and CORS checks
│   │   │   ├── ssrf_detector.py    # SSRF detection logic and payloads
│   │   │   ├── xxe_detector.py     # XXE detection
│   │   │   ├── auth_tester.py      # Broken authentication tester
│   │   │   ├── open_redirect.py    # Open redirect and CRLF tests
│   │   │   ├── traffic_monitor.py  # Net‑Watch Scapy anomaly engine
│   │   │   └── report_gen.py       # ReportLab PDF generator
│   │   ├── main.py                 # FastAPI app factory, route include, docs config
│   │   └── celery_worker.py        # Celery worker entrypoint
│   ├── tests/
│   │   ├── test_api_auth.py
│   │   ├── test_api_scans.py
│   │   ├── test_modules_recon.py
│   │   ├── test_modules_exploit.py
│   │   ├── test_modules_audit.py
│   │   └── test_traffic_monitor.py
│   ├── alembic/                    # DB migrations (if using Postgres)
│   ├── alembic.ini
│   ├── requirements.txt
│   ├── pyproject.toml              # Optional: modern dependency/development config
│   ├── .env.example                # Sample backend environment variables
│   └── README-backend.md
│
├── frontend/
│   ├── src/
│   │   ├── main.jsx                # React/Vite entrypoint
│   │   ├── App.jsx                 # PHANTOM dashboard shell
│   │   ├── api/
│   │   │   └── client.ts           # Centralized HTTP client (base URL, auth headers)
│   │   ├── hooks/
│   │   │   ├── useTrafficAnomalies.ts  # Net‑Watch WebSocket hook
│   │   │   └── useScanRunner.ts        # Helper hook to run scans and track progress
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── HeaderBar.tsx
│   │   │   │   ├── SidebarNav.tsx
│   │   │   │   └── ActivityLog.tsx
│   │   │   ├── dashboard/
│   │   │   │   ├── ModuleTabs.tsx
│   │   │   │   ├── ResultSummaryCards.tsx
│   │   │   │   └── NetWatchPanel.tsx
│   │   │   ├── netwatch/
│   │   │   │   └── AnomalyDetector.tsx
│   │   │   ├── common/
│   │   │   │   ├── RiskPill.tsx
│   │   │   │   ├── TagBadge.tsx
│   │   │   │   ├── ResultNode.tsx
│   │   │   │   ├── ScanProgress.tsx
│   │   │   │   └── EmptyState.tsx
│   │   ├── pages/
│   │   │   ├── DashboardPage.tsx
│   │   │   ├── LoginPage.tsx
│   │   │   ├── HistoryPage.tsx
│   │   │   └── SchedulePage.tsx
│   │   ├── styles/
│   │   │   ├── index.css
│   │   │   └── tailwind.css        # If using Tailwind utility classes
│   │   └── config/
│   │       └── theme.ts            # Design tokens (colors, fonts) for "cyberpunk luxury" UI
│   ├── public/
│   │   └── index.html
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.cjs         # If using Tailwind
│   ├── postcss.config.cjs
│   ├── .env.example                # Frontend API base URL, WebSocket URL
│   └── README-frontend.md
│
├── docs/
│   ├── PHANTOM-Requirements.md     # Project requirements document
│   ├── ARCHITECTURE.md             # High‑level diagrams, data flow, trust boundaries
│   ├── API-Reference.md            # Documented endpoints and schemas
│   └── MODULES.md                  # Per‑module behavior, risk logic, and payload notes
│
├── .github/
│   └── workflows/
│       └── ci.yml                  # Tests, linting, security scans
│
├── .gitignore
├── LICENSE
├── README.md                       # Main project README
└── CHANGELOG.md
```

## Notes

- The `backend/app` layout follows an application‑factory pattern that cleanly separates routing, business logic, tasks, and infrastructure concerns to support Celery workers, migrations, and API gateway hardening.
- The `modules/` folder contains the 18 security and monitoring modules defined in the PHANTOM v3.0 blueprint (recon, exploit, audit, Net‑Watch, and reporting).
- The project is configured to run natively on Windows using the included PowerShell start script.