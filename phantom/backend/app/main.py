# PHANTOM v3.0 Backend Entrypoint
import asyncio
import time
import datetime
from typing import Optional, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

# Import database and authentication dependencies
from app.database import get_db, init_db
from app.auth import get_current_user, require_admin, verify_password, create_access_token, get_password_hash
from app import models

# Import schemas
from app.schemas import ScanRequest

# Import scanning modules directly from root-level hardened implementations
from app.tasks import scanner_tasks
from app import storage
















from app.api import traffic_client

app = FastAPI(
    title="PHANTOM",
    description="Penetration Testing and Network Monitoring Framework v3.0",
    version="3.0",
    docs_url=None,
    redoc_url=None,
    debug=False
)

import os

# CORS configurations
cors_origins_env = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:5173")
cors_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]

# Auto-allow the HF Space URL if running on HuggingFace
hf_space_url = os.getenv("HF_SPACE_URL", "")
if hf_space_url and hf_space_url not in cors_origins:
    cors_origins.append(hf_space_url)
    # Also add https variant
    if hf_space_url.startswith("http://"):
        cors_origins.append(hf_space_url.replace("http://", "https://"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],
)

from starlette.middleware.sessions import SessionMiddleware
from app.auth import SECRET_KEY
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis_async
import redis as _pyredis
from starlette.requests import Request as _LimiterRequest
from starlette.responses import Response as _LimiterResponse
from app.core.celery_app import CELERY_AVAILABLE

# Compatibility shim: fastapi-limiter 0.1.6 iterates ``app.routes`` and accesses
# ``route.path`` / ``route.methods`` directly. Newer FastAPI/Starlette versions
# include router wrapper objects that lack those attributes, which raises
# AttributeError and 500s every rate-limited endpoint. Guard the lookup so the
# limiter degrades gracefully across FastAPI versions. The Request/Response
# annotations are required so FastAPI injects them instead of treating them as
# query parameters.
async def _patched_ratelimiter_call(self, request: _LimiterRequest, response: _LimiterResponse):
    if not FastAPILimiter.redis:
        return None
    try:
        route_index = 0
        dep_index = 0
        for i, route in enumerate(request.app.routes):
            if getattr(route, "path", None) == request.scope["path"] and request.method in (getattr(route, "methods", None) or set()):
                route_index = i
                for j, dependency in enumerate(getattr(route, "dependencies", []) or []):
                    if self is dependency.dependency:
                        dep_index = j
                        break
        identifier = self.identifier or FastAPILimiter.identifier
        callback = self.callback or FastAPILimiter.http_callback
        rate_key = await identifier(request)
        key = f"{FastAPILimiter.prefix}:{rate_key}:{route_index}:{dep_index}"
        try:
            pexpire = await self._check(key)
        except _pyredis.exceptions.NoScriptError:
            FastAPILimiter.lua_sha = await FastAPILimiter.redis.script_load(FastAPILimiter.lua_script)
            pexpire = await self._check(key)
        if pexpire != 0:
            return await callback(request, response, pexpire)
    except Exception:
        return None

RateLimiter.__call__ = _patched_ratelimiter_call

from fastapi import Request
from jose import jwt, JWTError
from app.auth import SECRET_KEY, ALGORITHM

async def rate_limit_identifier(request: Request):
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if username:
                return username
        except JWTError:
            pass
            
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host + ":" + request.scope["path"]

@app.on_event("startup")
async def on_startup():
    # Initialize Rate Limiter (optional — degrades gracefully without Redis)
    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        redis_conn = redis_async.from_url(redis_url, encoding="utf8", decode_responses=True)
        await FastAPILimiter.init(redis_conn, identifier=rate_limit_identifier)
    except Exception as e:
        FastAPILimiter.redis = None
        print(f"[WARN] Rate limiter disabled (Redis unavailable): {e}")

    # Initialize database and tables
    await init_db()
    
    # Start APScheduler
    from app.scheduler import scheduler
    if not scheduler.running:
        scheduler.start()
        
    # Seed a default admin account if not already in the DB
    from app.database import get_db, _using_supabase_rest
    if _using_supabase_rest:
        from app.supabase_db import get_supabase_session
        db = await get_supabase_session()
    else:
        from app.database import async_session
        if not async_session:
            return
        db_cm = async_session()
        db = await db_cm.__aenter__()
    try:
        result = await db.execute(select(models.User).where(models.User.username == "admin"))
        if not result.scalars().first():
            admin_user = models.User(
                username="admin",
                hashed_password=get_password_hash("admin123"),
                role="admin"
            )
            db.add(admin_user)
            await db.commit()
            print("Default admin user created successfully: admin / admin123")
    finally:
        if not _using_supabase_rest:
            await db_cm.__aexit__(None, None, None)

# Risk ranking helper
RISK_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def get_highest_risk(risks: List[str]) -> str:
    highest = "INFO"
    for r in risks:
        if r in RISK_ORDER:
            if RISK_ORDER.index(r) > RISK_ORDER.index(highest):
                highest = r
    return highest


# Helper wrapper to automatically log execution results to SQLite DB
async def run_and_save_scan(
    db: AsyncSession,
    current_user: models.User,
    module_name: str,
    celery_task_func,
    target: str,
    options: Optional[dict]
):
    """
    Dispatch a Celery scanning task, wait for completion, persist result
    to the database, and return the result dict.
    """
    session_rec = models.ScanSession(
        user_id=current_user.id,
        target=target,
        status="running",
        modules_run=[module_name]
    )
    db.add(session_rec)
    await db.commit()
    await db.refresh(session_rec)
    session_id = session_rec.id

    start_time = time.monotonic()

    # All Celery tasks accept (target, options=None) — consistent signature
    task = celery_task_func.delay(target, options)

    # Poll with a 15-minute timeout to prevent hanging forever
    max_wait = 900
    elapsed = 0.0
    while not task.ready():
        await asyncio.sleep(0.5)
        elapsed += 0.5
        if elapsed >= max_wait:
            break

    if not task.ready():
        res = {"status": "error", "message": "Task timed out after 15 minutes", "risk": "INFO", "vulnerable": False}
        err = "timeout"
    elif task.state == 'FAILURE':
        res = {"status": "error", "message": str(task.result), "risk": "INFO", "vulnerable": False}
        err = str(task.result)
    else:
        res = task.result if task.result is not None else {}
        err = None

    duration = time.monotonic() - start_time

    risk = res.get("risk", "INFO") if isinstance(res, dict) else "INFO"
    vuln = res.get("vulnerable", False) if isinstance(res, dict) else False

    result_rec = models.ScanResult(
        session_id=session_id,
        module_name=module_name,
        risk_level=risk,
        vulnerable=vuln,
        duration_seconds=round(duration, 2),
        result_data=res,
        error_message=err
    )
    db.add(result_rec)

    if vuln:
        alert_rec = models.Alert(
            session_id=session_id,
            module_name=module_name,
            severity=risk,
            description=f"Vulnerability detected in module {module_name} on {target}"
        )
        db.add(alert_rec)

    session_rec = await db.get(models.ScanSession, session_id)
    if session_rec:
        session_rec.status = "completed" if err is None else "failed"
        session_rec.overall_risk = risk
        session_rec.completed_at = datetime.datetime.utcnow()
    await db.commit()

    # Auto-generate PDF report
    results_dict = {module_name: res} if isinstance(res, dict) else {}
    await _auto_generate_report(db, current_user, target, session_id, results_dict)

    return res


async def _auto_generate_report(db, current_user, target, session_id, results_dict):
    """Auto-generate PDF report after a scan and save to storage + DB."""
    try:
        import base64
        import report_gen as _report_gen
        payload_opts = {"results": results_dict}
        result = await _report_gen.generate_report(target, payload_opts)
        if "error" in result:
            return
        pdf_data_b64 = result.get("pdf_data", "")
        if not pdf_data_b64:
            return
        filename = result.get("filename", "report.pdf")
        overall_risk = result.get("overall_risk", "INFO")
        pdf_bytes = base64.b64decode(pdf_data_b64)
        storage_path = await storage.upload_pdf(current_user.username, filename, pdf_bytes)
        report_rec = models.ScanReport(
            user_id=current_user.id,
            session_id=session_id,
            filename=filename,
            storage_path=storage_path,
            target=target,
            overall_risk=overall_risk,
        )
        db.add(report_rec)
        await db.commit()
    except Exception as e:
        print(f"[WARN] Auto-report generation failed: {e}")


@app.get("/")
async def root():
    return {
        "framework": "PHANTOM",
        "version": "3.0",
        "total_modules": 18,
        "websocket_url": "ws://localhost:8000/ws/traffic"
    }

# ----------------- Authentication Routes -----------------

class LoginPayload(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
async def login(payload: LoginPayload, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.User).where(models.User.username == payload.username))
    user = result.scalars().first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password"
        )
    token = create_access_token({"sub": user.username, "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username
    }

@app.get("/auth/me")
async def get_me(current_user: models.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role
    }

# ----------------- User Management (Admin only) -----------------

class SignupPayload(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=128)

@app.post("/auth/signup", status_code=status.HTTP_201_CREATED, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def signup(payload: SignupPayload, db: AsyncSession = Depends(get_db)):
    username = payload.username.strip()
    existing = await db.execute(select(models.User).where(models.User.username == username))
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail=f"Username '{username}' already exists")

    new_user = models.User(
        username=username,
        hashed_password=get_password_hash(payload.password),
        role="user"
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    token = create_access_token({"sub": new_user.username, "role": new_user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": new_user.role,
        "username": new_user.username
    }

class CreateUserPayload(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=128)
    role: str = Field(default="user")

@app.get("/auth/users")
async def list_users(db: AsyncSession = Depends(get_db), current_user: models.User = Depends(require_admin)):
    result = await db.execute(select(models.User).order_by(models.User.id))
    users = result.scalars().all()
    return [
        {"id": u.id, "username": u.username, "role": u.role, "email": u.email}
        for u in users
    ]

@app.post("/auth/users", status_code=status.HTTP_201_CREATED, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def create_user(payload: CreateUserPayload, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(require_admin)):
    username = payload.username.strip()
    if payload.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")

    existing = await db.execute(select(models.User).where(models.User.username == username))
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail=f"Username '{username}' already exists")

    new_user = models.User(
        username=username,
        hashed_password=get_password_hash(payload.password),
        role=payload.role
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"id": new_user.id, "username": new_user.username, "role": new_user.role}

@app.delete("/auth/users/{user_id}")
async def delete_user(user_id: int, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(require_admin)):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    user = await db.get(models.User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(user)
    await db.commit()
    return {"status": "success", "message": f"User '{user.username}' deleted"}

# ----------------- Core Pentest Scanning Endpoints -----------------

@app.post("/api/port-scan", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_port_scan(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "port_scanner", scanner_tasks.port_scan_task, payload.target, payload.options)

@app.post("/api/sqli-test", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_sqli_test(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "sqli_tester", scanner_tasks.sqli_test_task, payload.target, payload.options)

@app.post("/api/xss-detect", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_xss_detect(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "xss_detector", scanner_tasks.xss_detect_task, payload.target, payload.options)

@app.post("/api/subdomain-enum", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_subdomain_enum(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "subdomain_enum", scanner_tasks.subdomain_enum_task, payload.target, payload.options)

@app.post("/api/header-analyze", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_header_analyze(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "header_analyzer", scanner_tasks.header_analyzer_task, payload.target, payload.options)

@app.post("/api/ssl-analyze", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_ssl_analyze(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "ssl_analyzer", scanner_tasks.ssl_analyzer_task, payload.target, payload.options)

@app.post("/api/dir-enum", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_dir_enum(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "dir_enum", scanner_tasks.dir_enum_task, payload.target, payload.options)

@app.post("/api/waf-detect", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_waf_detect(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "waf_detect", scanner_tasks.waf_detect_task, payload.target, payload.options)

@app.post("/api/whois-lookup", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_whois_lookup(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "whois_lookup", scanner_tasks.whois_lookup_task, payload.target, payload.options)

# Alias for frontend compatibility (/api/whois is called by the frontend)
@app.post("/api/whois", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_whois_alias(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "whois_lookup", scanner_tasks.whois_lookup_task, payload.target, payload.options)

@app.post("/api/dns-recon", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_dns_recon(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "dns_recon", scanner_tasks.dns_recon_task, payload.target, payload.options)

@app.post("/api/cve-lookup", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_cve_lookup(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "cve_lookup", scanner_tasks.cve_lookup_task, payload.target, payload.options)

@app.post("/api/report", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_report(
    payload: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Generate a PDF report, save it to Supabase Storage, and return it.
    Expects payload.options = { "results": { module_key: result_dict, ... } }
    """
    import base64
    import report_gen as _report_gen
    result = await _report_gen.generate_report(payload.target, payload.options)

    if "error" in result:
        return result

    pdf_data_b64 = result.get("pdf_data", "")
    filename = result.get("filename", "report.pdf")
    overall_risk = result.get("overall_risk", "INFO")
    session_id = None

    if pdf_data_b64:
        try:
            pdf_bytes = base64.b64decode(pdf_data_b64)
            storage_path = await storage.upload_pdf(current_user.username, filename, pdf_bytes)

            report_rec = models.ScanReport(
                user_id=current_user.id,
                session_id=session_id,
                filename=filename,
                storage_path=storage_path,
                target=payload.target,
                overall_risk=overall_risk,
            )
            db.add(report_rec)
            await db.commit()
            await db.refresh(report_rec)
            result["report_id"] = report_rec.id
        except Exception as e:
            result["storage_error"] = str(e)

    return result


@app.get("/api/reports", dependencies=[Depends(RateLimiter(times=30, seconds=60))])
async def list_reports(
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0),
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """List all saved PDF reports for the current user."""
    result = await db.execute(
        select(models.ScanReport)
        .where(models.ScanReport.user_id == current_user.id)
        .order_by(models.ScanReport.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    reports = result.scalars().all()

    from sqlalchemy import func
    count_res = await db.execute(
        select(func.count(models.ScanReport.id))
        .where(models.ScanReport.user_id == current_user.id)
    )
    total = count_res.scalar_one()

    items = []
    for r in reports:
        signed_url = None
        try:
            signed_url = await storage.get_signed_url(r.storage_path, expires=3600)
        except Exception:
            pass
        items.append({
            "id": r.id,
            "filename": r.filename,
            "target": r.target,
            "overall_risk": r.overall_risk,
            "session_id": r.session_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "download_url": signed_url,
        })

    return {"total": total, "reports": items}


@app.get("/api/reports/{report_id}/download")
async def download_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Get a fresh signed URL for downloading a specific report."""
    result = await db.execute(
        select(models.ScanReport)
        .where(models.ScanReport.id == report_id, models.ScanReport.user_id == current_user.id)
    )
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        signed_url = await storage.get_signed_url(report.storage_path, expires=3600)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate download URL: {e}")

    return {"download_url": signed_url, "filename": report.filename}


@app.delete("/api/reports/{report_id}")
async def delete_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Delete a PDF report from Supabase Storage and the database."""
    result = await db.execute(
        select(models.ScanReport)
        .where(models.ScanReport.id == report_id, models.ScanReport.user_id == current_user.id)
    )
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        await storage.delete_file(report.storage_path)
    except Exception:
        pass

    await db.delete(report)
    await db.commit()
    return {"status": "success", "message": f"Report '{report.filename}' deleted"}

@app.post("/api/csrf-detect", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_csrf_detect(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "csrf_detector", scanner_tasks.csrf_detector_task, payload.target, payload.options)

@app.post("/api/ssrf-detect", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_ssrf_detect(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "ssrf_detector", scanner_tasks.ssrf_detector_task, payload.target, payload.options)

@app.post("/api/xxe-detect", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_xxe_detect(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "xxe_detector", scanner_tasks.xxe_detector_task, payload.target, payload.options)

@app.post("/api/auth-test", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_auth_test(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "auth_tester", scanner_tasks.auth_tester_task, payload.target, payload.options)

@app.post("/api/open-redirect", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_open_redirect(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return await run_and_save_scan(db, current_user, "open_redirect", scanner_tasks.open_redirect_task, payload.target, payload.options)

# ----------------- Orchestrated Full Scan -----------------

@app.post("/api/full-scan", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def route_full_scan(payload: ScanRequest, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    module_keys = [
        "port_scanner", "sqli_tester", "xss_detector", "subdomain_enum",
        "header_analyzer", "ssl_analyzer", "dir_enum", "waf_detect",
        "whois_lookup", "dns_recon", "cve_lookup", "csrf_detector",
        "ssrf_detector", "xxe_detector", "auth_tester", "open_redirect"
    ]
    
    session_rec = models.ScanSession(
        user_id=current_user.id,
        target=payload.target,
        status="running",
        modules_run=module_keys
    )
    db.add(session_rec)
    await db.commit()
    await db.refresh(session_rec)
    session_id = session_rec.id
    
    from app.tasks import scanner_tasks
    tasks = [
        scanner_tasks.port_scan_task.delay(payload.target, payload.options),
        scanner_tasks.sqli_test_task.delay(payload.target, payload.options),
        scanner_tasks.xss_detect_task.delay(payload.target, payload.options),
        scanner_tasks.subdomain_enum_task.delay(payload.target, payload.options),
        scanner_tasks.header_analyzer_task.delay(payload.target, payload.options),
        scanner_tasks.ssl_analyzer_task.delay(payload.target, payload.options),
        scanner_tasks.dir_enum_task.delay(payload.target, payload.options),
        scanner_tasks.waf_detect_task.delay(payload.target, payload.options),
        scanner_tasks.whois_lookup_task.delay(payload.target, payload.options),  # task accepts options, module ignores it
        scanner_tasks.dns_recon_task.delay(payload.target, payload.options),       # same
        scanner_tasks.cve_lookup_task.delay(payload.target, payload.options),
        scanner_tasks.csrf_detector_task.delay(payload.target, payload.options),
        scanner_tasks.ssrf_detector_task.delay(payload.target, payload.options),
        scanner_tasks.xxe_detector_task.delay(payload.target, payload.options),
        scanner_tasks.auth_tester_task.delay(payload.target, payload.options),
        scanner_tasks.open_redirect_task.delay(payload.target, payload.options),
    ]
    
    start_time = time.monotonic()
    max_wait_seconds = 900  # 15 minute timeout
    
    while True:
        all_done = all(t.ready() for t in tasks)
        if all_done:
            break
        if time.monotonic() - start_time > max_wait_seconds:
            break  # timeout — partial results will be collected below
        await asyncio.sleep(0.5)
        
    duration = time.monotonic() - start_time
    
    # Collect results — handle SUCCESS, FAILURE, and timed-out tasks
    results = []
    for t in tasks:
        if not t.ready():
            results.append(Exception("Task timed out"))
        elif t.state == 'FAILURE':
            results.append(Exception(str(t.result)))
        else:
            results.append(t.result)
    
    aggregated = {}
    findings_risks = []
    
    for key, res in zip(module_keys, results):
        result_rec = models.ScanResult(
            session_id=session_id,
            module_name=key,
        )
        if isinstance(res, Exception):
            result_rec.risk_level = "INFO"
            result_rec.vulnerable = False
            result_rec.error_message = str(res)
            aggregated[key] = {"status": "error", "message": str(res)}
        else:
            risk = res.get("risk", "INFO") if isinstance(res, dict) else "INFO"
            vuln = res.get("vulnerable", False) if isinstance(res, dict) else False
            result_rec.risk_level = risk
            result_rec.vulnerable = vuln
            result_rec.result_data = res
            findings_risks.append(risk)
            aggregated[key] = res
            
            if vuln:
                alert_rec = models.Alert(
                    session_id=session_id,
                    module_name=key,
                    severity=risk,
                    description=f"Vulnerability detected in {key} on {payload.target}"
                )
                db.add(alert_rec)
        db.add(result_rec)
        
    overall_risk = get_highest_risk(findings_risks)
    session_rec = await db.get(models.ScanSession, session_id)
    if session_rec:
        session_rec.status = "completed"
        session_rec.overall_risk = overall_risk
        session_rec.completed_at = datetime.datetime.utcnow()
        
    await db.commit()

    # Auto-generate PDF report
    await _auto_generate_report(db, current_user, payload.target, session_id, aggregated)
    
    return {
        "session_id": session_id,
        "target": payload.target,
        "status": "completed",
        "overall_risk": overall_risk,
        "duration_seconds": round(duration, 2),
        "results": aggregated
    }

# ----------------- Database and History APIS -----------------

@app.get("/api/history")
async def get_history(limit: int = 10, offset: int = 0, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    result = await db.execute(
        select(models.ScanSession)
        .where(models.ScanSession.user_id == current_user.id)
        .order_by(models.ScanSession.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    sessions = result.scalars().all()
    
    from sqlalchemy import func
    count_res = await db.execute(select(func.count(models.ScanSession.id)).where(models.ScanSession.user_id == current_user.id))
    total = count_res.scalar_one()
    
    return {
        "total": total,
        "sessions": [
            {
                "id": s.id,
                "target": s.target,
                "status": s.status,
                "overall_risk": s.overall_risk,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "modules_run": s.modules_run
            }
            for s in sessions
        ]
    }

@app.get("/api/history/{session_id}")
async def get_history_detail(session_id: int, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from sqlalchemy.orm import selectinload
    result = await db.execute(
        select(models.ScanSession)
        .where(models.ScanSession.id == session_id, models.ScanSession.user_id == current_user.id)
        .options(selectinload(models.ScanSession.results), selectinload(models.ScanSession.alerts))
    )
    session = result.scalars().first()
    if not session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    return {
        "id": session.id,
        "target": session.target,
        "status": session.status,
        "overall_risk": session.overall_risk,
        "created_at": session.created_at.isoformat() if session.created_at else None,
        "completed_at": session.completed_at.isoformat() if session.completed_at else None,
        "modules_run": session.modules_run,
        "results": [
            {
                "module_name": r.module_name,
                "risk_level": r.risk_level,
                "vulnerable": r.vulnerable,
                "duration_seconds": r.duration_seconds,
                "result_data": r.result_data,
                "error_message": r.error_message
            }
            for r in session.results
        ],
        "alerts": [
            {
                "module_name": a.module_name,
                "severity": a.severity,
                "description": a.description,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "acknowledged": a.acknowledged
            }
            for a in session.alerts
        ]
    }

@app.delete("/api/history/{session_id}")
async def delete_history(session_id: int, db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    result = await db.execute(select(models.ScanSession).where(models.ScanSession.id == session_id, models.ScanSession.user_id == current_user.id))
    session = result.scalars().first()
    if not session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    await db.delete(session)
    await db.commit()
    return {"status": "success", "message": f"Session {session_id} deleted"}

@app.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from sqlalchemy import func
    t_scans = await db.execute(select(func.count(models.ScanSession.id)))
    total_scans = t_scans.scalar_one()
    
    t_alerts = await db.execute(select(func.count(models.Alert.id)))
    total_alerts = t_alerts.scalar_one()
    
    today = datetime.datetime.utcnow().date()
    today_start = datetime.datetime.combine(today, datetime.time.min)
    t_today = await db.execute(select(func.count(models.ScanSession.id)).where(models.ScanSession.created_at >= today_start))
    scans_today = t_today.scalar_one()
    
    risky_targets_res = await db.execute(
        select(models.ScanSession.target, func.count(models.ScanSession.id))
        .where(models.ScanSession.overall_risk.in_(["HIGH", "CRITICAL"]))
        .group_by(models.ScanSession.target)
        .order_by(func.count(models.ScanSession.id).desc())
        .limit(5)
    )
    risky_targets = [{"target": row[0], "count": row[1]} for row in risky_targets_res.all()]
    
    module_usage_res = await db.execute(
        select(models.ScanResult.module_name, func.count(models.ScanResult.id))
        .group_by(models.ScanResult.module_name)
    )
    module_usage = {row[0]: row[1] for row in module_usage_res.all()}
    
    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_alerts,
        "scans_today": scans_today,
        "top_risky_targets": risky_targets,
        "module_usage": module_usage
    }

# ----------------- Scan Scheduling APIS -----------------

class SchedulePayload(BaseModel):
    target: str
    modules: List[str]
    interval_seconds: Optional[int] = None
    cron_expression: Optional[str] = None

@app.post("/api/schedule", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def create_schedule(payload: SchedulePayload, current_user: models.User = Depends(get_current_user)):
    from app.scheduler import scheduler, execute_scheduled_scan
    job_id = f"job_{int(time.time())}"
    
    if payload.interval_seconds:
        scheduler.add_job(
            execute_scheduled_scan,
            trigger="interval",
            seconds=payload.interval_seconds,
            args=[payload.target, payload.modules],
            kwargs={"user_id": current_user.id},
            id=job_id
        )
    elif payload.cron_expression:
        from apscheduler.triggers.cron import CronTrigger
        try:
            trigger = CronTrigger.from_crontab(payload.cron_expression)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid cron expression: {e}")
        scheduler.add_job(
            execute_scheduled_scan,
            trigger=trigger,
            args=[payload.target, payload.modules],
            kwargs={"user_id": current_user.id},
            id=job_id
        )
    else:
        raise HTTPException(status_code=400, detail="Must provide interval_seconds or cron_expression")
        
    return {"status": "success", "job_id": job_id, "message": f"Scan scheduled on {payload.target}"}

@app.get("/api/schedule")
async def list_schedule(current_user: models.User = Depends(get_current_user)):
    from app.scheduler import scheduler
    jobs = [j for j in scheduler.get_jobs() if j.kwargs.get("user_id") == current_user.id]
    return [
        {
            "id": j.id,
            "name": j.name,
            "next_run_time": j.next_run_time.isoformat() if j.next_run_time else None,
            "target": j.args[0] if j.args else None,
            "modules": j.args[1] if j.args and len(j.args) > 1 else None
        }
        for j in jobs
    ]

@app.post("/api/schedule/{job_id}/pause", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def pause_job(job_id: str, current_user: models.User = Depends(get_current_user)):
    from app.scheduler import scheduler
    job = scheduler.get_job(job_id)
    if not job or job.kwargs.get("user_id") != current_user.id:
        raise HTTPException(status_code=404, detail="Job not found")
    try:
        scheduler.pause_job(job_id)
        return {"status": "success", "message": f"Job {job_id} paused"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error pausing job: {e}")

@app.post("/api/schedule/{job_id}/resume", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def resume_job(job_id: str, current_user: models.User = Depends(get_current_user)):
    from app.scheduler import scheduler
    job = scheduler.get_job(job_id)
    if not job or job.kwargs.get("user_id") != current_user.id:
        raise HTTPException(status_code=404, detail="Job not found")
    try:
        scheduler.resume_job(job_id)
        return {"status": "success", "message": f"Job {job_id} resumed"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error resuming job: {e}")

@app.delete("/api/schedule/{job_id}")
async def delete_job(job_id: str, current_user: models.User = Depends(get_current_user)):
    from app.scheduler import scheduler
    job = scheduler.get_job(job_id)
    if not job or job.kwargs.get("user_id") != current_user.id:
        raise HTTPException(status_code=404, detail="Job not found")
    try:
        scheduler.remove_job(job_id)
        return {"status": "success", "message": f"Job {job_id} deleted"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error deleting job: {e}")

# ----------------- Net-Watch Monitoring -----------------

@app.get("/api/traffic/snapshot")
async def route_traffic_snapshot(interface: str = Query(default="eth0"), current_user: models.User = Depends(get_current_user)):
    return traffic_client.get_traffic_snapshot(interface)

@app.websocket("/ws/traffic")
async def route_traffic_ws(websocket: WebSocket, token: str = Query(None), interface: str = Query(default="eth0"), db: AsyncSession = Depends(get_db)):
    import logging
    ws_log = logging.getLogger("phantom.websocket")
    
    if not token:
        ws_log.warning("WebSocket /ws/traffic rejected: no token provided")
        await websocket.accept()
        await websocket.close(code=4001, reason="No authentication token provided")
        return
        
    from jose import JWTError, jwt
    from app.auth import SECRET_KEY, ALGORITHM
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            ws_log.warning("WebSocket /ws/traffic rejected: token has no 'sub' claim")
            await websocket.accept()
            await websocket.close(code=4001, reason="Invalid token: missing subject")
            return
            
        result = await db.execute(select(models.User).where(models.User.username == username))
        user = result.scalars().first()
        if user is None:
            ws_log.warning(f"WebSocket /ws/traffic rejected: user '{username}' not found in DB")
            await websocket.accept()
            await websocket.close(code=4001, reason=f"User not found: {username}")
            return
            
    except JWTError as e:
        ws_log.warning(f"WebSocket /ws/traffic rejected: JWT error - {e}")
        await websocket.accept()
        await websocket.close(code=4001, reason="Invalid or expired token - please log in again")
        return

    await websocket.accept()
    try:
        while True:
            # Emit dynamic traffic snapshots every 2 seconds
            snapshot = traffic_client.get_traffic_snapshot(interface)
            await websocket.send_json(snapshot)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass

from app.api.oauth import router as oauth_router
app.include_router(oauth_router)
