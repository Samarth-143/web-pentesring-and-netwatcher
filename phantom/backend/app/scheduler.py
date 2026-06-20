import logging
import asyncio
import time
import datetime
from typing import List, Optional
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

from app.database import async_session
from app import models
from app.tasks import scanner_tasks
from app.tasks.scanner_tasks import CELERY_AVAILABLE

logger = logging.getLogger("phantom.scheduler")

# Setup APScheduler with a dedicated job store database file
jobstores = {
    'default': SQLAlchemyJobStore(url='sqlite:///phantom_jobs.db')
}
scheduler = AsyncIOScheduler(jobstores=jobstores)

MODULE_MAP = {
    "port_scanner": scanner_tasks.port_scan_task,
    "sqli_tester": scanner_tasks.sqli_test_task,
    "xss_detector": scanner_tasks.xss_detect_task,
    "subdomain_enum": scanner_tasks.subdomain_enum_task,
    "header_analyzer": scanner_tasks.header_analyzer_task,
    "ssl_analyzer": scanner_tasks.ssl_analyzer_task,
    "dir_enum": scanner_tasks.dir_enum_task,
    "waf_detect": scanner_tasks.waf_detect_task,
    "whois_lookup": scanner_tasks.whois_lookup_task,
    "dns_recon": scanner_tasks.dns_recon_task,
    "cve_lookup": scanner_tasks.cve_lookup_task,
    "csrf_detector": scanner_tasks.csrf_detector_task,
    "ssrf_detector": scanner_tasks.ssrf_detector_task,
    "xxe_detector": scanner_tasks.xxe_detector_task,
    "auth_tester": scanner_tasks.auth_tester_task,
    "open_redirect": scanner_tasks.open_redirect_task,
}

RISK_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def get_highest_risk(risks: List[str]) -> str:
    highest = "INFO"
    for r in risks:
        if r in RISK_ORDER:
            if RISK_ORDER.index(r) > RISK_ORDER.index(highest):
                highest = r
    return highest


async def execute_scheduled_scan(target: str, modules_to_run: List[str], user_id: Optional[int] = None):
    """
    Execute a scheduled scan for the given target and modules.
    """
    logger.info(f"Executing scheduled scan on target: {target} | modules: {modules_to_run} | user_id: {user_id}")

    async with async_session() as db:
        session_record = models.ScanSession(
            user_id=user_id,
            target=target,
            status="running",
            modules_run=modules_to_run
        )
        db.add(session_record)
        await db.commit()
        await db.refresh(session_record)
        session_id = session_record.id

    tasks = []
    active_keys = []
    for m in modules_to_run:
        if m in MODULE_MAP:
            func = MODULE_MAP[m]
            tasks.append(func.delay(target, None))
            active_keys.append(m)

    if not tasks:
        logger.warning(f"No valid modules found in: {modules_to_run}")
        return

    start_time = time.monotonic()

    max_wait = 900
    elapsed_wait = 0
    poll_interval = 0.5
    while elapsed_wait < max_wait:
        if all(t.ready() for t in tasks):
            break
        await asyncio.sleep(poll_interval)
        elapsed_wait += poll_interval

    duration = time.monotonic() - start_time

    findings_risks = []
    async with async_session() as db:
        for m_name, task in zip(active_keys, tasks):
            r_record = models.ScanResult(
                session_id=session_id,
                module_name=m_name,
            )

            if not task.ready():
                r_record.risk_level = "INFO"
                r_record.error_message = "Task timed out after 15 minutes"
                r_record.vulnerable = False
            elif task.state == 'FAILURE':
                res = {"status": "error", "message": str(task.result)}
                r_record.risk_level = "INFO"
                r_record.error_message = str(task.result)
                r_record.vulnerable = False
            else:
                res = task.result
                risk = res.get("risk", "INFO") if isinstance(res, dict) else "INFO"
                vuln = res.get("vulnerable", False) if isinstance(res, dict) else False
                r_record.risk_level = risk
                r_record.vulnerable = vuln
                r_record.result_data = res
                findings_risks.append(risk)

                if vuln:
                    alert_record = models.Alert(
                        session_id=session_id,
                        module_name=m_name,
                        severity=risk,
                        description=f"Vulnerability detected in module {m_name} on {target}"
                    )
                    db.add(alert_record)

            db.add(r_record)

        overall_risk = get_highest_risk(findings_risks)
        session_record = await db.get(models.ScanSession, session_id)
        if session_record:
            session_record.status = "completed"
            session_record.overall_risk = overall_risk
            session_record.completed_at = datetime.datetime.utcnow()

        await db.commit()

    logger.info(f"Scheduled scan for target '{target}' finished in {duration:.2f}s | overall_risk={overall_risk}")
