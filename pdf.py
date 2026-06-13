"""
pdf.py — PDF Report Generator
================================
Builds a clean, branded PDF from a scan result dict.
Uses ReportLab Platypus — no external services, no cloud storage.

Called from app.py's GET /report/{id}/pdf endpoint.
"""

import logging
from datetime import datetime, timezone
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors

logger = logging.getLogger("secretscan.pdf")

# Brand colours
_DARK     = colors.HexColor("#0f172a")
_ACCENT   = colors.HexColor("#5b7bfe")
_HIGH     = colors.HexColor("#f43f5e")
_MEDIUM   = colors.HexColor("#fb923c")
_LOW      = colors.HexColor("#facc15")
_NONE     = colors.HexColor("#22c55e")
_MUTED    = colors.HexColor("#64748b")
_BG_LIGHT = colors.HexColor("#f8fafc")

_SEV_COLOR = {"HIGH": _HIGH, "MEDIUM": _MEDIUM, "LOW": _LOW, "NONE": _NONE}


def generate_pdf(scan_id: str, result: dict, out_path: str) -> None:
    """
    Write a PDF report to out_path.

    Args:
        scan_id:  UUID of the scan (shown in header).
        result:   The full build_result() dict from scanner.py.
        out_path: Filesystem path to write the .pdf file.

    Raises:
        Exception: propagates ReportLab errors to the caller.
    """
    styles   = getSampleStyleSheet()
    doc      = SimpleDocTemplate(
        out_path,
        pagesize     = letter,
        topMargin    = 36,
        bottomMargin = 36,
        leftMargin   = 48,
        rightMargin  = 48,
    )

    findings = result.get("findings", [])
    summary  = result.get("summary", {})
    risk     = result.get("risk_level", "NONE")
    total    = result.get("total_secrets", 0)
    source   = result.get("source", "")
    truncated= result.get("truncated", False)

    story: list = []

    # ── Header ────────────────────────────────────────────────
    story.append(Paragraph(
        "🔐 SecretScan Security Report",
        ParagraphStyle("Title", parent=styles["Title"],
                       fontSize=22, textColor=_DARK, spaceAfter=2),
    ))
    story.append(Paragraph(
        f"Scan ID: {scan_id[:8]}…  ·  "
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        ParagraphStyle("Sub", parent=styles["Normal"],
                       fontSize=9, textColor=_MUTED, spaceAfter=10),
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=_ACCENT, spaceAfter=12))

    # ── Risk banner ───────────────────────────────────────────
    risk_color = _SEV_COLOR.get(risk, _NONE)
    story.append(Paragraph(
        f"Overall Risk Level: <b>{risk}</b>",
        ParagraphStyle("Risk", parent=styles["Normal"],
                       fontSize=16, textColor=risk_color, spaceAfter=6),
    ))

    # ── Summary table ─────────────────────────────────────────
    table_data = [
        ["Total Secrets", "HIGH", "MEDIUM", "LOW"],
        [
            str(total),
            str(summary.get("high",   0)),
            str(summary.get("medium", 0)),
            str(summary.get("low",    0)),
        ],
    ]
    tbl = Table(table_data, colWidths=[120, 80, 80, 80])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  _DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 10),
        ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_BG_LIGHT, colors.white]),
        ("GRID",           (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        # Colour the HIGH/MEDIUM/LOW header cells
        ("TEXTCOLOR",      (1, 0), (1, 0),   _HIGH),
        ("TEXTCOLOR",      (2, 0), (2, 0),   _MEDIUM),
        ("TEXTCOLOR",      (3, 0), (3, 0),   _LOW),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 14))

    # ── Source ────────────────────────────────────────────────
    if source:
        story.append(Paragraph(
            f"<b>Source:</b> {source}",
            ParagraphStyle("Src", parent=styles["Normal"],
                           fontSize=9, textColor=_MUTED, spaceAfter=14),
        ))

    # ── Free-tier truncation notice ───────────────────────────
    if truncated:
        story.append(Paragraph(
            "⚠ This report shows a partial view. "
            "Upgrade to SecretScan Pro to see all findings and download the full PDF.",
            ParagraphStyle("Warn", parent=styles["Normal"],
                           fontSize=10, textColor=_MEDIUM,
                           backColor=colors.HexColor("#fff7ed"),
                           borderPadding=8, spaceAfter=14),
        ))

    # ── Findings ──────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"),
                            spaceAfter=8))

    if not findings:
        story.append(Paragraph(
            "✓ No secrets detected in this scan.",
            ParagraphStyle("Good", parent=styles["Normal"],
                           fontSize=12, textColor=_NONE),
        ))
    else:
        story.append(Paragraph(
            f"Findings ({len(findings)} shown)",
            ParagraphStyle("H2", parent=styles["Heading2"],
                           fontSize=13, textColor=_DARK, spaceAfter=8),
        ))

        for idx, f in enumerate(findings, 1):
            sev   = f.get("severity", "LOW")
            color = _SEV_COLOR.get(sev, _LOW)

            # Finding header: index + type + severity badge
            story.append(Paragraph(
                f"{idx}.&nbsp; <b>{f.get('type', 'Unknown')}</b>"
                f"  <font color='#{color.hexval()[2:]}' size='9'>[{sev}]</font>",
                ParagraphStyle(f"FH{idx}", parent=styles["Normal"],
                               fontSize=11, textColor=_DARK, spaceAfter=2),
            ))

            # File + line
            story.append(Paragraph(
                f"<font color='#64748b' size='9'>"
                f"📄 {f.get('file', '?')}  ·  Line {f.get('line', '?')}"
                f"</font>",
                styles["Normal"],
            ))

            # Redacted match
            if f.get("match"):
                story.append(Paragraph(
                    f"<font color='#64748b' size='8'><i>Match: {f['match']}</i></font>",
                    styles["Normal"],
                ))

            # Description
            story.append(Paragraph(
                f.get("description", ""),
                ParagraphStyle(f"FD{idx}", parent=styles["Normal"],
                               fontSize=9, textColor=_MUTED, spaceAfter=2),
            ))

            # Fix recommendation
            story.append(Paragraph(
                f"<b>Fix:</b> {f.get('fix', '')}",
                ParagraphStyle(f"FF{idx}", parent=styles["Normal"],
                               fontSize=9, textColor=_DARK, spaceAfter=10),
            ))

            story.append(HRFlowable(
                width="100%", thickness=0.3,
                color=colors.HexColor("#e2e8f0"), spaceAfter=8,
            ))

    # ── Footer ────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "Generated by SecretScan — secretscan.io",
        ParagraphStyle("Footer", parent=styles["Normal"],
                       fontSize=8, textColor=_MUTED, alignment=1),
    ))

    doc.build(story)
    logger.info(f"PDF generated: {out_path} ({len(findings)} findings)")


# ══════════════════════════════════════════════════════════════
#  PHASE 1 — EXECUTIVE PDF REPORTS  (item 5)
#  New function. generate_pdf() above is UNCHANGED and still used
#  by any existing callers — this is a richer, additive report type
#  for Pro/Enterprise users.
# ══════════════════════════════════════════════════════════════

from reportlab.platypus import PageBreak, Image as RLImage
from reportlab.lib.units import inch

_GOOD    = colors.HexColor("#22c55e")
_BRAND   = colors.HexColor("#5b7bfe")
_SECONDARY = colors.HexColor("#38bdf8")

_SCORE_BAND_COLOR = {
    "Excellent": _GOOD,
    "Good":      _GOOD,
    "Moderate":  _MEDIUM,
    "High Risk": _HIGH,
    "Critical":  colors.HexColor("#c026d3"),
}


def generate_executive_pdf(scan_id: str, result: dict, out_path: str,
                            org_name: str = "", user_email: str = "") -> None:
    """
    Generate a multi-section "Executive" PDF security assessment report.

    Sections:
      1. Cover / header — branding, org name, scan timestamp
      2. Executive Summary — security score, risk level, key stats
      3. Repository Health (if present in result['repo_health'])
      4. Critical & High Findings — detailed, with OWASP/NIST mapping
      5. Detected Secrets (Secrets Exposure category findings)
      6. Dependency Risks (if result['dependency_findings'] present)
      7. Compliance Mapping summary table (OWASP Top 10 coverage)
      8. Recommendations
      9. Footer — branding, scan ID, timestamp

    Args:
        scan_id:    UUID of the scan (shown in header).
        result:     The full build_result() dict from scanner.py — may
                     include Phase 1 fields (security_score, repo_health,
                     dependency_findings, and per-finding owasp/nist/auto_fix).
        out_path:   Filesystem path to write the .pdf file.
        org_name:   Organization name for branding (optional).
        user_email: Requesting user's email, shown in report metadata (optional).

    Raises:
        Exception: propagates ReportLab errors to the caller.
    """
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        out_path,
        pagesize=letter,
        topMargin=40, bottomMargin=40, leftMargin=48, rightMargin=48,
    )

    findings    = result.get("findings", [])
    dep_findings = result.get("dependency_findings", [])
    summary     = result.get("summary", {})
    risk        = result.get("risk_level", "NONE")
    total       = result.get("total_secrets", len(findings))
    source      = result.get("source", "")
    truncated   = result.get("truncated", False)

    security_score   = result.get("security_score", 0)
    score_risk_level = result.get("score_risk_level", "Moderate")
    repo_health      = result.get("repo_health")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story: list = []

    # ── Title / Cover ────────────────────────────────────────
    story.append(Paragraph(
        "SafeAIScan Security Assessment",
        ParagraphStyle("Title", parent=styles["Title"],
                       fontSize=24, textColor=_DARK, spaceAfter=4),
    ))
    story.append(Paragraph(
        "Executive Security Report",
        ParagraphStyle("Subtitle", parent=styles["Normal"],
                       fontSize=13, textColor=_ACCENT, spaceAfter=12),
    ))

    meta_lines = [f"<b>Scan ID:</b> {scan_id[:8]}…",
                   f"<b>Generated:</b> {now_str}"]
    if org_name:
        meta_lines.append(f"<b>Organization:</b> {org_name}")
    if user_email:
        meta_lines.append(f"<b>Requested by:</b> {user_email}")
    if source:
        meta_lines.append(f"<b>Source:</b> {source}")

    story.append(Paragraph(
        "  &nbsp;·&nbsp;  ".join(meta_lines),
        ParagraphStyle("Meta", parent=styles["Normal"],
                       fontSize=9, textColor=_MUTED, spaceAfter=10),
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=_ACCENT, spaceAfter=16))

    # ── Executive Summary ────────────────────────────────────
    story.append(Paragraph(
        "Executive Summary",
        ParagraphStyle("H1", parent=styles["Heading1"], fontSize=15,
                       textColor=_DARK, spaceAfter=8),
    ))

    score_color = _SCORE_BAND_COLOR.get(score_risk_level, _MEDIUM)
    summary_table_data = [
        ["Security Score", "Risk Level", "Total Findings", "Critical", "High"],
        [
            f"{security_score} / 100",
            score_risk_level,
            str(total),
            str(summary.get("critical", 0)),
            str(summary.get("high", 0)),
        ],
    ]
    summary_tbl = Table(summary_table_data, colWidths=[100, 95, 95, 70, 70])
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), _DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 10),
        ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
        ("GRID",           (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",     (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 8),
        ("BACKGROUND",     (0, 1), (0, 1), colors.HexColor("#f8fafc")),
        ("TEXTCOLOR",      (0, 1), (0, 1), score_color),
        ("FONTNAME",       (0, 1), (0, 1), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 1), (0, 1), 13),
        ("TEXTCOLOR",      (1, 1), (1, 1), score_color),
        ("FONTNAME",       (1, 1), (1, 1), "Helvetica-Bold"),
        ("TEXTCOLOR",      (3, 1), (3, 1), colors.HexColor("#c026d3")),
        ("TEXTCOLOR",      (4, 1), (4, 1), _HIGH),
    ]))
    story.append(summary_tbl)
    story.append(Spacer(1, 14))

    exec_summary_text = (
        f"This assessment identified <b>{total}</b> finding(s) across the scanned "
        f"{'repository' if source.startswith('http') else 'submission'}, resulting in an overall "
        f"security score of <b>{security_score}/100</b> "
        f"(<font color='#{score_color.hexval()[2:]}'><b>{score_risk_level}</b></font>). "
    )
    if summary.get("critical", 0) > 0:
        exec_summary_text += (
            f"<b>{summary['critical']} CRITICAL</b> finding(s) require immediate attention "
            f"as they represent direct exposure of credentials or code-execution risks. "
        )
    if not findings:
        exec_summary_text = (
            "No security findings were detected in this scan. The codebase appears to "
            "follow secure coding practices for the patterns checked."
        )

    story.append(Paragraph(
        exec_summary_text,
        ParagraphStyle("ExecSum", parent=styles["Normal"], fontSize=10,
                       textColor=_DARK, spaceAfter=14, leading=15),
    ))

    if truncated:
        story.append(Paragraph(
            "⚠ This report shows a partial view based on your current plan. "
            "Upgrade to SafeAIScan Pro to see all findings and unlock full executive reports.",
            ParagraphStyle("Warn", parent=styles["Normal"], fontSize=9,
                           textColor=_MEDIUM, backColor=colors.HexColor("#fff7ed"),
                           borderPadding=8, spaceAfter=14),
        ))

    # ── Repository Health ─────────────────────────────────────
    if repo_health:
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=8))
        story.append(Paragraph(
            "Repository Health",
            ParagraphStyle("H2RH", parent=styles["Heading2"], fontSize=13,
                           textColor=_DARK, spaceAfter=8),
        ))
        health_data = [
            ["Critical", "High", "Medium", "Low", "Secrets", "Dependencies", "Outdated"],
            [
                str(repo_health.get("critical_count", 0)),
                str(repo_health.get("high_count", 0)),
                str(repo_health.get("medium_count", 0)),
                str(repo_health.get("low_count", 0)),
                str(repo_health.get("secret_count", 0)),
                str(repo_health.get("dependency_count", 0)),
                str(repo_health.get("outdated_packages", 0)),
            ],
        ]
        health_tbl = Table(health_data, colWidths=[58]*7)
        health_tbl.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",       (0, 0), (-1, -1), 9),
            ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
            ("GRID",           (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
            ("TOPPADDING",     (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
            ("TEXTCOLOR",      (0, 1), (0, 1), colors.HexColor("#c026d3")),
            ("TEXTCOLOR",      (1, 1), (1, 1), _HIGH),
            ("TEXTCOLOR",      (2, 1), (2, 1), _MEDIUM),
            ("TEXTCOLOR",      (3, 1), (3, 1), _GOOD),
        ]))
        story.append(health_tbl)
        story.append(Spacer(1, 14))

    # ── Critical & High Findings (detailed) ──────────────────
    critical_high = [f for f in findings if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH")]
    if critical_high:
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=8))
        story.append(Paragraph(
            f"Critical &amp; High Findings ({len(critical_high)})",
            ParagraphStyle("H2CH", parent=styles["Heading2"], fontSize=13,
                           textColor=_DARK, spaceAfter=8),
        ))
        for idx, f in enumerate(critical_high, 1):
            _render_finding(story, styles, f, idx, show_compliance=True)

    # ── Detected Secrets (Secrets Exposure category) ──────────
    secrets = [f for f in findings if str(f.get("category", "")).lower() == "secrets exposure"]
    if secrets:
        story.append(PageBreak())
        story.append(Paragraph(
            f"Detected Secrets ({len(secrets)})",
            ParagraphStyle("H2Sec", parent=styles["Heading2"], fontSize=13,
                           textColor=_DARK, spaceAfter=8),
        ))
        for idx, f in enumerate(secrets, 1):
            _render_finding(story, styles, f, idx, show_compliance=False, compact=True)

    # ── Dependency Risks ──────────────────────────────────────
    if dep_findings:
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=8))
        story.append(Paragraph(
            f"Dependency Risks ({len(dep_findings)})",
            ParagraphStyle("H2Dep", parent=styles["Heading2"], fontSize=13,
                           textColor=_DARK, spaceAfter=8),
        ))
        dep_table_data = [["Package", "Version", "Severity", "CVE", "Issue"]]
        for d in dep_findings[:20]:
            dep_table_data.append([
                d.get("package", "?"),
                d.get("version", "?"),
                d.get("severity", "LOW"),
                d.get("cve", "N/A"),
                (d.get("title", "") or d.get("description", ""))[:50],
            ])
        dep_tbl = Table(dep_table_data, colWidths=[90, 60, 60, 90, 175])
        dep_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_BG_LIGHT, colors.white]),
        ]))
        story.append(dep_tbl)
        story.append(Spacer(1, 14))

    # ── Compliance Mapping Summary ───────────────────────────
    owasp_counts: dict = {}
    for f in findings:
        owasp = f.get("owasp")
        if owasp:
            owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1

    if owasp_counts:
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=8))
        story.append(Paragraph(
            "Compliance Mapping — OWASP Top 10 Coverage",
            ParagraphStyle("H2Comp", parent=styles["Heading2"], fontSize=13,
                           textColor=_DARK, spaceAfter=8),
        ))
        comp_data = [["OWASP Category", "Findings"]]
        for owasp, count in sorted(owasp_counts.items(), key=lambda x: -x[1]):
            comp_data.append([owasp, str(count)])
        comp_tbl = Table(comp_data, colWidths=[380, 80])
        comp_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("ALIGN",         (1, 0), (1, -1), "CENTER"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_BG_LIGHT, colors.white]),
        ]))
        story.append(comp_tbl)
        story.append(Spacer(1, 14))

    # ── Recommendations ───────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=8))
    story.append(Paragraph(
        "Recommendations",
        ParagraphStyle("H2Rec", parent=styles["Heading2"], fontSize=13,
                       textColor=_DARK, spaceAfter=8),
    ))

    recs = []
    if summary.get("critical", 0) > 0:
        recs.append("Rotate all exposed credentials immediately — treat CRITICAL findings as already compromised.")
    if secrets:
        recs.append("Move all secrets to environment variables or a secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager, or your platform's secret store).")
    if dep_findings:
        recs.append("Update vulnerable dependencies to the versions specified in this report, prioritising CRITICAL and HIGH severity packages.")
    if summary.get("high", 0) > 0:
        recs.append("Review and remediate HIGH severity findings — these represent significant exploitable risk.")
    recs.append("Add automated SafeAIScan checks to your CI/CD pipeline to catch new issues before merge.")
    recs.append("Re-run this scan after remediation to confirm your security score has improved.")

    for r in recs:
        story.append(Paragraph(f"• {r}", ParagraphStyle(
            "Rec", parent=styles["Normal"], fontSize=9.5, textColor=_DARK,
            spaceAfter=4, leading=14,
        )))

    # ── Footer ────────────────────────────────────────────────
    story.append(Spacer(1, 24))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=6))
    story.append(Paragraph(
        f"Generated by SafeAIScan · {now_str} · Scan ID {scan_id[:8]}… · safeaiscan.io",
        ParagraphStyle("Footer", parent=styles["Normal"],
                       fontSize=8, textColor=_MUTED, alignment=1),
    ))

    doc.build(story)
    logger.info(f"Executive PDF generated: {out_path} ({len(findings)} findings, score={security_score})")


def _render_finding(story: list, styles, f: dict, idx: int,
                     show_compliance: bool = False, compact: bool = False) -> None:
    """Helper: render a single finding block into the PDF story."""
    sev   = (f.get("severity") or "LOW").upper()
    color = _SEV_COLOR.get(sev, _LOW) if sev != "CRITICAL" else colors.HexColor("#c026d3")

    header = (
        f"{idx}.&nbsp; <b>{f.get('type', f.get('title', 'Issue'))}</b>"
        f"  <font color='#{color.hexval()[2:]}' size='9'>[{sev}]</font>"
    )
    story.append(Paragraph(header, ParagraphStyle(
        f"FH{idx}_{id(f)}", parent=styles["Normal"], fontSize=11, textColor=_DARK, spaceAfter=2,
    )))

    if f.get("file"):
        story.append(Paragraph(
            f"<font color='#64748b' size='9'>File: {f.get('file', '?')}"
            f"{'  ·  Line ' + str(f.get('line')) if f.get('line') else ''}</font>",
            styles["Normal"],
        ))

    if f.get("match"):
        story.append(Paragraph(
            f"<font color='#64748b' size='8'><i>Match: {f['match']}</i></font>",
            styles["Normal"],
        ))

    if f.get("description"):
        story.append(Paragraph(
            f.get("description", ""),
            ParagraphStyle(f"FD{idx}_{id(f)}", parent=styles["Normal"],
                           fontSize=9, textColor=_MUTED, spaceAfter=2),
        ))

    if f.get("fix"):
        story.append(Paragraph(
            f"<b>Fix:</b> {f.get('fix', '')}",
            ParagraphStyle(f"FF{idx}_{id(f)}", parent=styles["Normal"],
                           fontSize=9, textColor=_DARK, spaceAfter=2),
        ))

    if show_compliance and (f.get("owasp") or f.get("nist")):
        story.append(Paragraph(
            f"<font size='8' color='#5b7bfe'><b>Compliance:</b> "
            f"OWASP {f.get('owasp','')}  ·  NIST {f.get('nist','')}</font>",
            styles["Normal"],
        ))

    if f.get("auto_fix") and not compact:
        af = f["auto_fix"]
        story.append(Paragraph(
            f"<font size='8' color='#22c55e'><b>Suggested fix (confidence {af.get('confidence',0)}%):</b> "
            f"{af.get('after','')}</font>",
            styles["Normal"],
        ))

    story.append(Spacer(1, 4))
    story.append(HRFlowable(
        width="100%", thickness=0.3,
        color=colors.HexColor("#e2e8f0"), spaceAfter=8,
    ))
