import asyncio
from typing import Optional
from app.core.celery_app import celery_app, CELERY_AVAILABLE

import port_scanner
import sqli_tester
import xss_detector
import subdomain_enum
import header_analyzer
import ssl_analyzer
import dir_enum
import waf_detect
import whois_lookup
import dns_recon
import cve_lookup
import report_gen
import csrf_detector
import ssrf_detector
import xxe_detector
import auth_tester
import open_redirect


def run_async(coro):
    """
    Safe async runner for Celery tasks (sync context).
    Uses asyncio.run() which creates a fresh event loop — correct for Python 3.10+.
    """
    try:
        return asyncio.run(coro)
    except RuntimeError as e:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result(timeout=300)


# Direct (non-Celery) runner — used when Redis/Celery is unavailable (e.g. HF Spaces)
class DirectResult:
    """Mimics Celery AsyncResult interface for inline execution."""
    def __init__(self, result):
        self._result = result
        self._state = 'SUCCESS'
        self._ready = True

    @property
    def state(self):
        return self._state

    def ready(self):
        return True

    @property
    def result(self):
        return self._result


# Map of task functions for direct execution
_DIRECT_RUNNERS = {
    "port_scanner": lambda t, o: run_async(port_scanner.scan_ports(t, o)),
    "sqli_tester": lambda t, o: run_async(sqli_tester.test_sqli(t, o)),
    "xss_detector": lambda t, o: run_async(xss_detector.detect_xss(t, o)),
    "subdomain_enum": lambda t, o: run_async(subdomain_enum.enumerate_subdomains(t, o)),
    "header_analyzer": lambda t, o: run_async(header_analyzer.analyze_headers(t, o)),
    "ssl_analyzer": lambda t, o: run_async(ssl_analyzer.analyze_ssl(t, o)),
    "dir_enum": lambda t, o: run_async(dir_enum.enumerate_directories(t, o)),
    "waf_detect": lambda t, o: run_async(waf_detect.detect_waf(t, o)),
    "whois_lookup": lambda t, o: run_async(whois_lookup.whois_lookup(t)),
    "dns_recon": lambda t, o: run_async(dns_recon.dns_recon(t)),
    "cve_lookup": lambda t, o: run_async(cve_lookup.lookup_cve(t, o)),
    "csrf_detector": lambda t, o: run_async(csrf_detector.detect_csrf(t, o)),
    "ssrf_detector": lambda t, o: run_async(ssrf_detector.detect_ssrf(t, o)),
    "xxe_detector": lambda t, o: run_async(xxe_detector.detect_xxe(t, o)),
    "auth_tester": lambda t, o: run_async(auth_tester.test_auth(t, o)),
    "open_redirect": lambda t, o: run_async(open_redirect.test_open_redirect(t, o)),
    "report_gen": lambda t, o: run_async(report_gen.generate_report(t, o)),
}


def run_task_direct(module_name: str, target: str, options: Optional[dict] = None):
    """Run a scan module directly (without Celery) and return a DirectResult."""
    runner = _DIRECT_RUNNERS.get(module_name)
    if not runner:
        return DirectResult({"status": "error", "message": f"Unknown module: {module_name}", "risk": "INFO", "vulnerable": False})
    try:
        result = runner(target, options)
        return DirectResult(result)
    except Exception as e:
        return DirectResult({"status": "error", "message": str(e), "risk": "INFO", "vulnerable": False})


if CELERY_AVAILABLE and celery_app is not None:
    @celery_app.task(bind=True, name="port_scan_task")
    def port_scan_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Running port scan'})
        return run_async(port_scanner.scan_ports(target, options))

    @celery_app.task(bind=True, name="sqli_test_task")
    def sqli_test_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Running SQLi test'})
        return run_async(sqli_tester.test_sqli(target, options))

    @celery_app.task(bind=True, name="xss_detect_task")
    def xss_detect_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Running XSS scan'})
        return run_async(xss_detector.detect_xss(target, options))

    @celery_app.task(bind=True, name="subdomain_enum_task")
    def subdomain_enum_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Running Subdomain enum'})
        return run_async(subdomain_enum.enumerate_subdomains(target, options))

    @celery_app.task(bind=True, name="header_analyzer_task")
    def header_analyzer_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Analyzing HTTP headers'})
        return run_async(header_analyzer.analyze_headers(target, options))

    @celery_app.task(bind=True, name="ssl_analyzer_task")
    def ssl_analyzer_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Analyzing SSL/TLS configuration'})
        return run_async(ssl_analyzer.analyze_ssl(target, options))

    @celery_app.task(bind=True, name="dir_enum_task")
    def dir_enum_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Enumerating directories'})
        return run_async(dir_enum.enumerate_directories(target, options))

    @celery_app.task(bind=True, name="waf_detect_task")
    def waf_detect_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Detecting WAF'})
        return run_async(waf_detect.detect_waf(target, options))

    @celery_app.task(bind=True, name="whois_lookup_task")
    def whois_lookup_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Performing WHOIS lookup'})
        return run_async(whois_lookup.whois_lookup(target))

    @celery_app.task(bind=True, name="dns_recon_task")
    def dns_recon_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Performing DNS recon'})
        return run_async(dns_recon.dns_recon(target))

    @celery_app.task(bind=True, name="cve_lookup_task")
    def cve_lookup_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Performing CVE lookup'})
        return run_async(cve_lookup.lookup_cve(target, options))

    @celery_app.task(bind=True, name="csrf_detector_task")
    def csrf_detector_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Testing CSRF vulnerabilities'})
        return run_async(csrf_detector.detect_csrf(target, options))

    @celery_app.task(bind=True, name="ssrf_detector_task")
    def ssrf_detector_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Testing SSRF vulnerabilities'})
        return run_async(ssrf_detector.detect_ssrf(target, options))

    @celery_app.task(bind=True, name="xxe_detector_task")
    def xxe_detector_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Testing XXE vulnerabilities'})
        return run_async(xxe_detector.detect_xxe(target, options))

    @celery_app.task(bind=True, name="auth_tester_task")
    def auth_tester_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Testing Broken Authentication'})
        return run_async(auth_tester.test_auth(target, options))

    @celery_app.task(bind=True, name="open_redirect_task")
    def open_redirect_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Testing Open Redirects'})
        return run_async(open_redirect.test_open_redirect(target, options))

    @celery_app.task(bind=True, name="report_gen_task")
    def report_gen_task(self, target: str, options: Optional[dict] = None):
        self.update_state(state='PROGRESS', meta={'status': 'Generating Report'})
        return run_async(report_gen.generate_report(target, options))
else:
    # Stub task objects when Celery is unavailable — .delay() runs inline
    class _StubTask:
        def __init__(self, module_name):
            self._module = module_name
        def delay(self, target, options=None):
            return run_task_direct(self._module, target, options)

    port_scan_task = _StubTask("port_scanner")
    sqli_test_task = _StubTask("sqli_tester")
    xss_detect_task = _StubTask("xss_detector")
    subdomain_enum_task = _StubTask("subdomain_enum")
    header_analyzer_task = _StubTask("header_analyzer")
    ssl_analyzer_task = _StubTask("ssl_analyzer")
    dir_enum_task = _StubTask("dir_enum")
    waf_detect_task = _StubTask("waf_detect")
    whois_lookup_task = _StubTask("whois_lookup")
    dns_recon_task = _StubTask("dns_recon")
    cve_lookup_task = _StubTask("cve_lookup")
    csrf_detector_task = _StubTask("csrf_detector")
    ssrf_detector_task = _StubTask("ssrf_detector")
    xxe_detector_task = _StubTask("xxe_detector")
    auth_tester_task = _StubTask("auth_tester")
    open_redirect_task = _StubTask("open_redirect")
    report_gen_task = _StubTask("report_gen")
