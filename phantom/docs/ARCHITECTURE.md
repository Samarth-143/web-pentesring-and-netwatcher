# PHANTOM v3.0 – Architecture Documentation

This document describes the high-level system architecture, data flows, trust boundaries, and security hardening measures implemented in the PHANTOM v3.0 platform.

---

## 1. High-Level Architecture Flowchart

Below is a detailed representation of the system components and their interactions:

```mermaid
flowchart TB
    %% === USERS ===
    U[Browser<br/>Operator] -->|HTTPS| FE

    %% === FRONTEND ===
    subgraph FRONTEND[React / Vite Frontend (PHANTOM UI)]
        FE[Dashboard Shell<br/>App.jsx]
        P_LOGIN[Login Page]
        P_DASH[Pentest Mode Page]
        P_NETW[Net‑Watch Mode Page]
        P_HIST[History Page]
        P_SCHED[Schedule Page]

        FE --- P_LOGIN
        FE --- P_DASH
        FE --- P_NETW
        FE --- P_HIST
        FE --- P_SCHED

        FE -->|REST / JSON| API
        P_NETW -->|WebSocket| WS
    end

    %% === API GATEWAY / BACKEND APP ===
    subgraph BACKEND[FastAPI API Layer (unprivileged)]
        API[FastAPI app<br/>/api/* /auth/*]
        WS[/ws/traffic<br/>(WebSocket)]
        AUTH[Auth Router<br/>JWT, login, /auth/me]
        R_SCANS[Scans Router<br/>per‑module & full‑scan]
        R_HIST[History Router<br/>/api/history*]
        R_SCHED[Schedule Router<br/>/api/schedule*]
        R_STATS[Stats Router<br/>/api/stats]
        RL[Rate‑Limit Middleware<br/>Redis token bucket]
        SSRF_GW[Safe HTTP Client<br/>Custom SSRF‑safe connector]

        API --> AUTH
        API --> R_SCANS
        API --> R_HIST
        API --> R_SCHED
        API --> R_STATS
        API --> WS

        RL --> API
        API --> SSRF_GW
    end

    %% === TASK QUEUE & WORKERS ===
    API -->|enqueue jobs| CEL

    subgraph TASKS[Task Processing Layer]
        CEL[Celery Worker Pool]
        RB[(Redis<br/>Broker + Result backend)]

        CEL <--> RB
        API <--> RB

        subgraph MODS[Security Modules (18)]
            direction LR
            %% Recon
            M_PORT[Port scan]
            M_SUBD[Subdomain enum]
            M_DIR[Dir enum]
            M_WAF[WAF detect]
            M_WHOIS[WHOIS lookup]
            M_DNS[DNS recon]

            %% Exploit
            M_SQLI[SQL injection tester]
            M_XSS[XSS detector]
            M_CSRF[CSRF detector]
            M_SSRF[SSRF detector]
            M_XXE[XXE detector]
            M_AUTH[Broken auth tester]
            M_OR[Open redirect tester]

            %% Audit / Intel / Reporting
            M_HDR[Header analyzer]
            M_SSL[SSL/TLS analyzer]
            M_CVE[CVE lookup (NVD)]
            M_NETW[Net‑Watch integration]
            M_REP[PDF report generator]
        end

        CEL --> MODS
    end

    %% === NET-WATCH DAEMON (PRIVILEGED) ===
    subgraph NETWATCH[Net‑Watch Packet Engine]
        NW_D[Scapy Daemon<br/>(CAP_NET_RAW)]
        NW_IPC[(Unix Domain Socket<br/>netwatch.sock)]
    end

    %% API / workers talk to daemon via local IPC, not HTTP
    M_NETW <-->|sanitized commands| NW_IPC
    NW_IPC --> NW_D

    %% === DATA & PERSISTENCE ===
    subgraph DATA[Persistence Layer]
        DB[(DB: SQLite/Postgres)<br/>ScanSession, ScanResult, User, Alert, Job]
        API --> DB
        CEL --> DB
    end

    %% === SCHEDULER ===
    subgraph SCHED[APScheduler]
        JOBS[Scheduled Scan Jobs]
    end

    R_SCHED --> JOBS
    JOBS -->|trigger tasks| CEL

    %% === EXTERNAL TARGETS / SERVICES USED BY MODULES ===
    subgraph EXT[External Systems]
        TGT[Target Web Apps / Hosts]
        NMAP[Nmap Binary]
        DNS_SRV[DNS / CT servers]
        WHOIS_SRV[WHOIS servers]
        NVD[NVD API v2]
        EGRESS[Hardened Egress Proxy<br/>(e.g. Smokescreen)]
    end

    %% HTTP out always goes through SSRF-safe client + proxy
    SSRF_GW -->|HTTP(S)| EGRESS
    EGRESS --> TGT
    EGRESS --> DNS_SRV
    EGRESS --> WHOIS_SRV
    EGRESS --> NVD

    %% Nmap & local tools
    M_PORT --> NMAP
    MODS --> TGT
    M_SUBD --> DNS_SRV
    M_DNS --> DNS_SRV
    M_WHOIS --> WHOIS_SRV
    M_CVE --> NVD

    %% NET-WATCH traffic source
    NW_D -->|raw packets| IFACE[Host NICs]

    %% === OBSERVABILITY ===
    subgraph OBS[Observability]
        LOGS[Structured JSON Logs]
        METRICS[Platform Stats / Dashboards]
    end

    API --> LOGS
    CEL --> LOGS
    API --> METRICS
    CEL --> METRICS
```

---

## 2. Key Architecture Components

### 2.1 User Interface (React / Vite Frontend)
*   **Aesthetics**: Follows a dark "cyberpunk luxury" theme (utilizing specific fonts and layout configurations).
*   **State Management & Utilities**: Centralized API helper (`client.ts`) that intercepts and appends JWT authorization tokens and redirects the user on token expiration.
*   **WebSockets**: Uses `useTrafficAnomalies` hook to listen on `ws/traffic` for real-time packet capture alerts.

### 2.2 API Layer (FastAPI)
*   **Routing**: Gatekeeper for incoming requests. Exposes user authentication (`/auth/*`), scan scheduling (`/api/schedule*`), scan execution (`/api/full-scan`), and audit metrics.
*   **Rate-Limiter**: Intercepts requests using Redis token-bucket middleware, protecting vulnerable endpoints from automated scraping or DoS.
*   **SSRF Gateway**: Outbound HTTP checks utilize custom safe connectors to prevent SSRF and DNS rebinding by resolving domain names at connection time and rejecting private IPs.

### 2.3 Task Queue (Celery & Redis)
*   Long-running tasks are offloaded to **Celery Workers**. 
*   **Redis** functions as the broker and result backend.
*   Celery workers run the pentesting engine modules (port scanners, exploit triggers, vulnerability modules, reporting generators) to keep the API server highly responsive.

### 2.4 Net-Watch Packet Engine
*   **Scapy Daemon**: Captured packets must utilize `CAP_NET_RAW`. Rather than executing the API server as root, a isolated background daemon (`NW_D`) handles raw sniffing.
*   **Unix IPC**: The API server and workers communicate with the daemon via Unix domain socket (`netwatch.sock`) by passing sanitized commands.

---

## 3. Hardening and Trust Boundaries

1.  **Strict Egress Controls**: All external API/HTTP probes from scanners transit through an egress proxy (e.g. *Smokescreen*) to enforce network segregation.
2.  **No Shell Executions**: subprocess calls inside modules bypass `shell=True` entirely and use structured tokenized arguments.
3.  **Privilege Isolation**: Scapy packet extraction runs in its own low-privilege capability wrapper (`CAP_NET_RAW` / `CAP_NET_ADMIN`) away from web-exposed surfaces.
