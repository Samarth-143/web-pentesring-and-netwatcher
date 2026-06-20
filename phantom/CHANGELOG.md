# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-06-07

### Added
- **Complete Re-architecture**: Migrated to a FastAPI backend and a React/Vite frontend.
- **Asynchronous Execution**: Integrated Celery and Redis to handle concurrent multi-module scanning without blocking the main event loop.
- **SQLite Persistence**: Scans are now saved into `phantom.db`, enabling the `History` and `Archives` UI to track past scans and retrieve previous results.
- **PDF Report Generation**: Integrated `reportlab` to export scan results from the UI directly into downloadable PDF documents.
- **Net-Watch Real-Time Telemetry**: Added a Scapy-based network daemon (`traffic_daemon.py`) running in the background. It communicates with the FastAPI server via Unix sockets/TCP IPC to emit live network traffic statistics.
- **WebSocket Streaming**: Added a WebSocket endpoint (`/ws/traffic`) that streams the Net-Watch telemetry to the frontend every 2 seconds.
- **Per-IP Live Dashboard**: Net-Watch UI now features a real-time table tracking the top 50 active source IPs, their PPS, BPS, dominant protocols, and anomaly status.
- **Anomaly Detection**: Net-Watch daemon actively detects "DDoS Suspected", "Traffic Spike", and "Port Scan" anomalies based on a rolling Z-score window.
- **Module Expansion**: Hardened 16 dedicated scanning modules across Recon, Exploit, and Audit categories. All mock stubs have been completely removed and delegated to real implementations.
- **OAuth Integration**: Added Google and GitHub OAuth logic to the FastAPI backend.
- **Task Scheduling**: Integrated `apscheduler` to allow users to schedule recurring scans (e.g., daily at midnight).
- **Automated Testing & CI**: Added `pytest`, `vitest`, and GitHub Actions workflows for automated testing and security scanning (`bandit`, `safety`).

### Fixed
- Fixed bug where frontend was using `replace('_', '-')` which only replaced the first occurrence in module names, causing 404 errors on API routing. Replaced with a robust dictionary map (`MODULE_ENDPOINT_MAP`).
- Fixed bug where initiating a multi-module scan from the dashboard only executed the first selected module. Refactored `handleStartScan` to use `Promise.allSettled`.
- Fixed bug where mock backend modules returned static sleep payloads instead of performing actual scans.
- Fixed UI layout grouping in the dashboard; modules are now correctly segmented by Type (Recon/Exploit/Audit) with clear icons and descriptions.
- Resolved CORS issues affecting the `DELETE /api/history/{id}` endpoint.
