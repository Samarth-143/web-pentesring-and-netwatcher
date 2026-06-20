---
title: PHANTOM
emoji: 🛡️
colorFrom: purple
colorTo: blue
sdk: docker
app_port: 7860
pinned: false
license: mit
---

# PHANTOM — Penetration Testing & Network Monitoring Framework

Backend API for the PHANTOM security audit platform. Built with FastAPI + SQLAlchemy + Supabase PostgreSQL.

## Features
- 16+ security scanning modules (port scan, SQLi, XSS, CSRF, SSRF, XXE, etc.)
- JWT authentication with Google OAuth
- PDF report generation with Supabase Storage
- Real-time network traffic monitoring via WebSocket
- Scheduled audit directives with APScheduler
