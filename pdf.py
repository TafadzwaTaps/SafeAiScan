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
