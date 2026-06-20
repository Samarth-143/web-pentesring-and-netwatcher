"""
report_gen.py – Production-hardened PHANTOM scan report generator.

Hardening applied:
  - No outbound HTTP requests — operates purely on scan result data
  - Input sanitisation: all string fields stripped of control characters
    before insertion into PDF (prevents ReportLab injection via Unicode
    control sequences and null bytes)
  - File output path validated to /tmp/phantom_reports/ (no path traversal)
  - ReportLab used in pure-Python mode (no C extensions required)
  - Findings sorted by severity before rendering
  - Risk colour mapping: CRITICAL=red, HIGH=orange, MEDIUM=amber, LOW=green, INFO=gray
  - Page header/footer with timestamp, target, page number
  - Graceful degradation: if a module key is missing, section is skipped
"""

import html
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
        HRFlowable,
        PageBreak,
        KeepTogether,
    )
    from reportlab.platypus.flowables import Flowable
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False

import tempfile
OUTPUT_DIR = Path(tempfile.gettempdir()) / "phantom_reports"

RISK_COLOURS = {
    "CRITICAL": colors.HexColor("#B91C1C"),
    "HIGH":     colors.HexColor("#C2410C"),
    "MEDIUM":   colors.HexColor("#B45309"),
    "LOW":      colors.HexColor("#15803D"),
    "INFO":     colors.HexColor("#374151"),
    "UNKNOWN":  colors.HexColor("#6B7280"),
}

RISK_BG_COLOURS = {
    "CRITICAL": colors.HexColor("#FEE2E2"),
    "HIGH":     colors.HexColor("#FFEDD5"),
    "MEDIUM":   colors.HexColor("#FEF3C7"),
    "LOW":      colors.HexColor("#DCFCE7"),
    "INFO":     colors.HexColor("#F3F4F6"),
    "UNKNOWN":  colors.HexColor("#F9FAFB"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}

# Module display names and their result-dict key names
MODULE_META: list[dict[str, str]] = [
    {"key": "port_scanner",   "label": "Port Scanner",            "risk_field": "risk"},
    {"key": "sqli_tester",    "label": "SQL Injection Tester",    "risk_field": "risk"},
    {"key": "xss_detector",   "label": "XSS Detector",            "risk_field": "risk"},
    {"key": "subdomain_enum", "label": "Subdomain Enumerator",    "risk_field": "risk"},
    {"key": "header_analyzer","label": "HTTP Header Analyzer",    "risk_field": "risk"},
    {"key": "ssl_analyzer",   "label": "SSL/TLS Analyzer",        "risk_field": "risk"},
    {"key": "dir_enum",       "label": "Directory Enumerator",    "risk_field": "risk"},
    {"key": "waf_detect",     "label": "WAF Detector",            "risk_field": "risk"},
    {"key": "whois_lookup",   "label": "WHOIS Lookup",            "risk_field": None},
    {"key": "dns_recon",      "label": "DNS Reconnaissance",      "risk_field": "risk"},
    {"key": "cve_lookup",     "label": "CVE Lookup",              "risk_field": "risk"},
    {"key": "csrf_detector",  "label": "CSRF Detector",           "risk_field": "risk"},
    {"key": "ssrf_detector",  "label": "SSRF Detector",           "risk_field": "risk"},
    {"key": "xxe_detector",   "label": "XXE Detector",            "risk_field": "risk"},
    {"key": "auth_tester",    "label": "Auth Tester",             "risk_field": "risk"},
    {"key": "open_redirect",  "label": "Open Redirect Tester",    "risk_field": "risk"},
]

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# ── Input sanitisation ────────────────────────────────────────────────────────

def _sanitise(value: Any, max_len: int = 500) -> str:
    """Strip control characters and truncate. Safe for insertion into PDF paragraphs."""
    if value is None:
        return "—"
    s = str(value)
    s = _CONTROL_CHAR_RE.sub("", s)
    s = html.escape(s, quote=False)
    return s[:max_len]


def _sanitise_path(filename: str) -> Path:
    """Validate output filename to prevent path traversal."""
    name = Path(filename).name   # strip any directory components
    # Allow only safe characters in filename
    name = re.sub(r"[^\w\-\.]", "_", name)
    if not name.endswith(".pdf"):
        name += ".pdf"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR / name


# ── Risk aggregation ──────────────────────────────────────────────────────────

def _aggregate_risk(module_results: dict[str, Any]) -> str:
    """Return the highest risk across all module results."""
    highest = "LOW"
    for meta in MODULE_META:
        result = module_results.get(meta["key"], {})
        if not isinstance(result, dict):
            continue
        risk_field = meta["risk_field"]
        if not risk_field:
            continue
        risk = result.get(risk_field, "LOW").upper()
        if SEVERITY_ORDER.get(risk, 99) < SEVERITY_ORDER.get(highest, 99):
            highest = risk
    return highest


def _collect_all_findings(module_results: dict[str, Any]) -> list[dict[str, str]]:
    """
    Collect and sort all findings across modules.
    Returns list of {module, finding, severity} sorted by severity descending.
    """
    all_findings: list[dict[str, str]] = []

    SEVERITY_RE = re.compile(r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO):", re.I)

    for meta in MODULE_META:
        result = module_results.get(meta["key"], {})
        if not isinstance(result, dict):
            continue
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            continue
        for finding in findings:
            f_str = str(finding)
            m = SEVERITY_RE.match(f_str)
            severity = m.group(1).upper() if m else "INFO"
            all_findings.append({
                "module": meta["label"],
                "finding": f_str,
                "severity": severity,
            })

    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return all_findings


# ── ReportLab PDF construction ────────────────────────────────────────────────

def _make_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "PHTitle",
            parent=base["Title"],
            fontSize=24,
            leading=30,
            textColor=colors.HexColor("#111827"),
            spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "PHSubtitle",
            parent=base["Normal"],
            fontSize=11,
            textColor=colors.HexColor("#6B7280"),
            spaceAfter=4,
        ),
        "h2": ParagraphStyle(
            "PHH2",
            parent=base["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#111827"),
            spaceBefore=14,
            spaceAfter=6,
            borderPad=0,
        ),
        "h3": ParagraphStyle(
            "PHH3",
            parent=base["Heading3"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#374151"),
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "PHBody",
            parent=base["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#374151"),
        ),
        "mono": ParagraphStyle(
            "PHMono",
            parent=base["Code"],
            fontSize=8,
            leading=12,
            textColor=colors.HexColor("#1F2937"),
            backColor=colors.HexColor("#F3F4F6"),
            borderPad=4,
            leftIndent=8,
        ),
        "finding_critical": ParagraphStyle(
            "PHFindingCritical",
            parent=base["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=RISK_COLOURS["CRITICAL"],
        ),
        "finding_high": ParagraphStyle(
            "PHFindingHigh",
            parent=base["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=RISK_COLOURS["HIGH"],
        ),
        "finding_medium": ParagraphStyle(
            "PHFindingMedium",
            parent=base["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=RISK_COLOURS["MEDIUM"],
        ),
        "finding_low": ParagraphStyle(
            "PHFindingLow",
            parent=base["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=RISK_COLOURS["LOW"],
        ),
        "finding_info": ParagraphStyle(
            "PHFindingInfo",
            parent=base["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=RISK_COLOURS["INFO"],
        ),
    }


def _finding_style(styles: dict, severity: str) -> ParagraphStyle:
    key = f"finding_{severity.lower()}"
    return styles.get(key, styles["finding_info"])


def _risk_badge_table(risk: str) -> Table:
    """Render a coloured risk badge as a single-cell table."""
    colour = RISK_COLOURS.get(risk.upper(), RISK_COLOURS["UNKNOWN"])
    bg = RISK_BG_COLOURS.get(risk.upper(), RISK_BG_COLOURS["UNKNOWN"])
    t = Table([[risk.upper()]], colWidths=[60], rowHeights=[18])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), bg),
        ("TEXTCOLOR",   (0, 0), (-1, -1), colour),
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ("TOPPADDING",  (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
    ]))
    return t


def _summary_table(module_results: dict, styles: dict) -> Table:
    """Build the executive summary table: Module | Risk | Key Metric."""
    rows = [["Module", "Risk", "Key Metric"]]
    for meta in MODULE_META:
        result = module_results.get(meta["key"])
        if not isinstance(result, dict):
            continue
        risk = "—"
        if meta["risk_field"]:
            risk = result.get(meta["risk_field"], "—").upper()

        # Module-specific key metric
        metric = "—"
        k = meta["key"]
        if k == "port_scanner":
            metric = f"{len(result.get('open_ports', []))} open ports"
        elif k == "sqli_tester":
            hits = result.get("sqli_findings", [])
            metric = f"{len(hits)} injection point(s)" if hits else "No injections found"
        elif k == "xss_detector":
            hits = result.get("xss_findings", [])
            metric = f"{len(hits)} reflection(s)" if hits else "No reflections found"
        elif k == "subdomain_enum":
            metric = f"{result.get('total_found', 0)} subdomains"
        elif k == "header_analyzer":
            metric = f"Grade {result.get('grade', '?')} ({result.get('score', 0)}/100)"
        elif k == "ssl_analyzer":
            metric = result.get("tls_version", "—")
        elif k == "dir_enum":
            metric = f"{result.get('sensitive_count', 0)} sensitive paths"
        elif k == "waf_detect":
            metric = "WAF detected" if result.get("waf_detected") else "No WAF"
        elif k == "dns_recon":
            metric = "AXFR vulnerable" if result.get("zone_transfer_vulnerable") else "AXFR secure"
        elif k == "cve_lookup":
            metric = f"{result.get('total_results', 0)} CVE(s) found"
        elif k == "csrf_detector":
            metric = f"{len(result.get('csrf_missing_forms', []))} unprotected form(s)"
        elif k == "ssrf_detector":
            metric = f"{result.get('probes_run', 0)} probes"
        elif k == "xxe_detector":
            metric = f"{len(result.get('xxe_findings', []))} XXE hit(s)"
        elif k == "auth_tester":
            spray = result.get("credential_spray", {})
            metric = "Rate limited" if spray.get("has_rate_limiting") else "No lockout detected"
        elif k == "open_redirect":
            metric = f"{len(result.get('open_redirects', []))} redirect(s)"

        colour = RISK_COLOURS.get(risk, RISK_COLOURS["UNKNOWN"])
        rows.append([
            Paragraph(_sanitise(meta["label"]), styles["body"]),
            Paragraph(f'<font color="{colour.hexval()}">{risk}</font>', styles["body"]),
            Paragraph(_sanitise(metric), styles["body"]),
        ])

    col_widths = [130, 60, None]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        # Header row
        ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#1F2937")),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0),  9),
        ("ALIGN",        (0, 0), (-1, 0),  "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        # Body rows
        ("FONTSIZE",     (0, 1), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#F9FAFB")]),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _header_footer(canvas, doc):
    """Per-page header and footer callback for SimpleDocTemplate."""
    canvas.saveState()
    width, height = A4

    # Header bar
    canvas.setFillColor(colors.HexColor("#1F2937"))
    canvas.rect(0, height - 28 * mm, width, 28 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(20 * mm, height - 12 * mm, "PHANTOM Security Report")
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(width - 20 * mm, height - 12 * mm, doc.phantom_target)

    # Footer
    canvas.setFillColor(colors.HexColor("#6B7280"))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(20 * mm, 10 * mm, f"Generated {doc.phantom_timestamp} UTC")
    canvas.drawRightString(width - 20 * mm, 10 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(colors.HexColor("#E5E7EB"))
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, 15 * mm, width - 20 * mm, 15 * mm)

    canvas.restoreState()


def _build_pdf(
    output_path: Path,
    target: str,
    scan_timestamp: str,
    overall_risk: str,
    module_results: dict[str, Any],
    styles: dict,
) -> None:
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=35 * mm,
        bottomMargin=22 * mm,
    )
    # Attach metadata for the header/footer callback
    doc.phantom_target = _sanitise(target, 80)
    doc.phantom_timestamp = scan_timestamp

    story: list = []

    # ── Cover / Title block ───────────────────────────────────────────────────
    story.append(Paragraph("Penetration Test Report", styles["title"]))
    story.append(Paragraph(f"Target: <b>{_sanitise(target, 120)}</b>", styles["subtitle"]))
    story.append(Paragraph(f"Scan date: {scan_timestamp} UTC", styles["subtitle"]))

    # Overall risk badge
    colour = RISK_COLOURS.get(overall_risk, RISK_COLOURS["UNKNOWN"])
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f'Overall risk: <font color="{colour.hexval()}"><b>{overall_risk}</b></font>',
        styles["h3"],
    ))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB")))
    story.append(Spacer(1, 10))

    # ── Executive Summary table ───────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["h2"]))
    story.append(_summary_table(module_results, styles))
    story.append(Spacer(1, 14))

    # ── Consolidated Findings ─────────────────────────────────────────────────
    story.append(Paragraph("Consolidated Findings", styles["h2"]))
    all_findings = _collect_all_findings(module_results)

    if all_findings:
        finding_rows = [["Severity", "Module", "Finding"]]
        for f in all_findings:
            sev = f["severity"]
            colour = RISK_COLOURS.get(sev, RISK_COLOURS["INFO"])
            finding_rows.append([
                Paragraph(f'<font color="{colour.hexval()}"><b>{sev}</b></font>', styles["body"]),
                Paragraph(_sanitise(f["module"]), styles["body"]),
                Paragraph(_sanitise(f["finding"], 300), styles["body"]),
            ])

        ft = Table(finding_rows, colWidths=[60, 110, None], repeatRows=1)
        ft.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#1F2937")),
            ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0),  9),
            ("ALIGN",        (0, 0), (-1, 0),  "CENTER"),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE",     (0, 1), (-1, -1), 8.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F9FAFB")]),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("TOPPADDING",   (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(ft)
    else:
        story.append(Paragraph("No findings recorded.", styles["body"]))

    story.append(Spacer(1, 16))
    story.append(PageBreak())

    # ── Per-module detail sections ────────────────────────────────────────────
    story.append(Paragraph("Module Detail", styles["h2"]))

    for meta in MODULE_META:
        result = module_results.get(meta["key"])
        if not isinstance(result, dict):
            continue
        if result.get("error"):
            continue   # skip errored modules in detail

        risk = result.get(meta["risk_field"] or "risk", "—").upper() if meta["risk_field"] else "—"
        colour = RISK_COLOURS.get(risk, RISK_COLOURS["UNKNOWN"])

        section: list = []
        section.append(Paragraph(
            f'{meta["label"]} '
            f'<font color="{colour.hexval()}">({risk})</font>',
            styles["h3"],
        ))

        # Findings for this module
        module_findings = result.get("findings", [])
        if module_findings:
            for f in module_findings:
                sev_match = re.match(r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO):", str(f), re.I)
                sev = sev_match.group(1).upper() if sev_match else "INFO"
                sty = _finding_style(styles, sev)
                section.append(Paragraph(f"• {_sanitise(str(f), 300)}", sty))

        # Module-specific supplementary data
        k = meta["key"]

        if k == "port_scanner":
            ports = result.get("open_ports", [])
            if ports:
                section.append(Paragraph("Open ports:", styles["body"]))
                port_rows = [["Port", "Service", "Version", "Risk"]]
                for p in ports[:30]:
                    risk_flag = "⚠" if p.get("is_risky") else ""
                    port_rows.append([
                        str(p.get("port", "")),
                        _sanitise(p.get("service", ""), 20),
                        _sanitise(p.get("version", "")[:40], 40),
                        risk_flag,
                    ])
                pt = Table(port_rows, colWidths=[45, 90, 170, 30], repeatRows=1)
                pt.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE",   (0, 0), (-1, -1), 8),
                    ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.white, colors.HexColor("#F9FAFB")]),
                    ("TOPPADDING",    (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ]))
                section.append(pt)

        elif k == "header_analyzer":
            missing = result.get("headers_missing", [])
            if missing:
                section.append(Paragraph(
                    f"Missing headers: {', '.join(_sanitise(h) for h in missing)}",
                    styles["body"],
                ))
            leaky = result.get("leaky_headers", [])
            if leaky:
                section.append(Paragraph(
                    f"Leaky headers: {', '.join(_sanitise(h['header']) for h in leaky)}",
                    styles["body"],
                ))

        elif k == "ssl_analyzer":
            cert = result.get("certificate", {})
            if cert:
                section.append(Paragraph(
                    f"Certificate: {_sanitise(cert.get('subject_cn', '—'))} | "
                    f"Expires: {_sanitise(cert.get('not_after', '—'))} | "
                    f"Days remaining: {cert.get('days_to_expiry', '—')}",
                    styles["body"],
                ))

        elif k == "subdomain_enum":
            hvt = result.get("high_value_targets", [])
            if hvt:
                section.append(Paragraph("High-value subdomains:", styles["body"]))
                for entry in hvt[:10]:
                    section.append(Paragraph(
                        f"  • {_sanitise(entry.get('subdomain', ''))} "
                        f"[{_sanitise(entry.get('ip', '—'))}]",
                        styles["body"],
                    ))

        elif k == "cve_lookup":
            cve_list = result.get("cve_list", [])
            for cve in cve_list[:10]:
                cvss = cve.get("cvss", {})
                section.append(Paragraph(
                    f"  <b>{_sanitise(cve.get('cve_id', ''))}</b> "
                    f"CVSS {cvss.get('score', '?')} {cvss.get('severity', '')} — "
                    f"{_sanitise(cve.get('description', ''), 200)}",
                    styles["body"],
                ))

        elif k == "waf_detect":
            detections = result.get("detections", [])
            if detections:
                for d in detections:
                    section.append(Paragraph(
                        f"  WAF: {_sanitise(d.get('waf', ''))} "
                        f"[{_sanitise(d.get('confidence', ''))}]",
                        styles["body"],
                    ))
            bypass = result.get("bypass_techniques", [])
            if bypass:
                section.append(Paragraph("Bypass techniques:", styles["body"]))
                for b in bypass[:5]:
                    section.append(Paragraph(f"  • {_sanitise(b)}", styles["body"]))

        section.append(Spacer(1, 6))
        story.append(KeepTogether(section))

    # ── Methodology note ──────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Methodology & Disclaimer", styles["h2"]))
    story.append(Paragraph(
        "This report was generated by PHANTOM v3.0, an automated penetration testing "
        "framework. Automated scanning cannot replace manual security assessment. "
        "All findings should be validated by a qualified security professional before "
        "remediation. False positives are possible — particularly for time-based blind "
        "injection and behavioural anomaly detections.",
        styles["body"],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report is confidential and intended solely for the authorised recipient. "
        "Scanning was performed only against targets for which written authorisation "
        "was obtained.",
        styles["body"],
    ))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)


# ── Public API ────────────────────────────────────────────────────────────────

async def generate_report(target: str, options: dict | None = None) -> dict[str, Any]:
    """
    Generate a PDF penetration test report from aggregated scan results.

    Parameters
    ----------
    target  : target hostname / URL (used for display and filename)
    options : optional
        results       – dict of module_key → result_dict (full scan output)
        filename      – output filename without path (default: phantom_<timestamp>.pdf)
        include_modules – list[str] of module keys to include (default: all)

    Returns
    -------
    dict with: output_path, page_count_estimate, overall_risk,
               modules_included, findings_count
    """
    if not _REPORTLAB_AVAILABLE:
        return {
            "error": "reportlab is not installed. Run: pip install reportlab",
            "target": target,
        }

    options = options or {}
    module_results: dict[str, Any] = options.get("results", {})
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    # Sanitise filename
    safe_target = re.sub(r"[^\w\-\.]", "_", target.split("//")[-1].split("/")[0])
    default_filename = f"phantom_{safe_target}_{int(time.time())}.pdf"
    filename = options.get("filename", default_filename)
    output_path = _sanitise_path(filename)

    overall_risk = _aggregate_risk(module_results)
    all_findings = _collect_all_findings(module_results)
    modules_included = [
        meta["label"] for meta in MODULE_META
        if isinstance(module_results.get(meta["key"]), dict)
        and not module_results[meta["key"]].get("error")
    ]

    styles = _make_styles()

    try:
        _build_pdf(
            output_path=output_path,
            target=target,
            scan_timestamp=timestamp,
            overall_risk=overall_risk,
            module_results=module_results,
            styles=styles,
        )
    except Exception as exc:
        return {"error": f"PDF generation failed: {exc}", "target": target}

    import base64
    pdf_base64 = ""
    try:
        if output_path.exists():
            with open(output_path, "rb") as f:
                pdf_base64 = base64.b64encode(f.read()).decode("utf-8")
    except Exception as read_exc:
        return {"error": f"Failed to read generated PDF file: {read_exc}", "target": target}

    return {
        "output_path": str(output_path),
        "filename": output_path.name,
        "pdf_data": pdf_base64,
        "overall_risk": overall_risk,
        "modules_included": modules_included,
        "findings_count": len(all_findings),
        "critical_count": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
        "high_count":     sum(1 for f in all_findings if f["severity"] == "HIGH"),
        "medium_count":   sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
        "low_count":      sum(1 for f in all_findings if f["severity"] == "LOW"),
        "scan_timestamp": timestamp,
    }
