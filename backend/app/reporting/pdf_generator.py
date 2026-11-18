"""PDF assessment report generation with ReportLab (Feature J)."""
from __future__ import annotations

import io
import json
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#dc2626"),
    "Medium": colors.HexColor("#d97706"),
    "Low": colors.HexColor("#2563eb"),
    "Informational": colors.HexColor("#64748b"),
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("Sub", parent=ss["Normal"], textColor=colors.HexColor("#334155"), fontSize=9))
    ss.add(ParagraphStyle("FindTitle", parent=ss["Heading3"], spaceBefore=10))
    ss.add(ParagraphStyle("Label", parent=ss["Normal"], fontName="Helvetica-Bold"))
    return ss


def build_report_pdf(scan, target, findings, results) -> bytes:
    """Render the assessment report for one scan. All evidence pre-masked."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"API PrivacyGuard Report - {scan.name}",
    )
    ss = _styles()
    story = []

    # ---- Cover / summary ----
    story.append(Paragraph("API PrivacyGuard", ss["Title"]))
    story.append(Paragraph("BOLA / IDOR Security Assessment Report", ss["Heading2"]))
    story.append(Spacer(1, 6 * mm))
    meta = [
        ["Assessment", scan.name],
        ["Target", f"{target.name} ({target.base_url})"],
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Scan started", scan.started_at.strftime("%Y-%m-%d %H:%M UTC") if scan.started_at else "-"],
        ["Scan finished", scan.finished_at.strftime("%Y-%m-%d %H:%M UTC") if scan.finished_at else "-"],
        ["Status", scan.status],
    ]
    table = Table([[Paragraph(a, ss["Label"]), Paragraph(b, ss["Normal"])] for a, b in meta],
                  colWidths=[35 * mm, 120 * mm])
    table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph("Executive summary", ss["Heading3"]))
    story.append(Paragraph(
        f"{scan.endpoints_tested} endpoint(s) were tested for Broken Object Level "
        f"Authorization using {len({r.requester_name for r in results} | {r.owner_name for r in results})} "
        f"authenticated test account(s). Results: "
        f"{scan.confirmed_count} confirmed BOLA/IDOR, {scan.potential_count} potential, "
        f"{scan.blocked_count} blocked (protected), {scan.authorized_count} authorized, "
        f"{scan.inconclusive_count} inconclusive.", ss["Normal"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "Scope note: testing was performed exclusively against an explicitly "
        "authorised target using read-only (GET) requests with two or more "
        "test accounts owned by the assessor.", ss["Sub"]))

    # ---- Endpoints tested ----
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Endpoints tested", ss["Heading3"]))
    ep_rows = [["Endpoint", "Method", "Path", "Resource", "Owner", "Result"]]
    seen = set()
    for r in results:
        k = (r.endpoint_id, r.resource_id, r.requester_name, r.owner_name)
        if k in seen:
            continue
        seen.add(k)
        ep_rows.append([
            Paragraph(r.endpoint_name, ss["Sub"]), Paragraph(r.method, ss["Sub"]),
            Paragraph(r.path, ss["Sub"]), Paragraph(str(r.resource_id), ss["Sub"]),
            Paragraph(f"{r.requester_name} &rarr; {r.owner_name}", ss["Sub"]),
            Paragraph(r.classification, ss["Sub"]),
        ])
    t2 = Table(ep_rows, colWidths=[30 * mm, 14 * mm, 42 * mm, 18 * mm, 30 * mm, 30 * mm], repeatRows=1)
    t2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#94a3b8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t2)

    # ---- Findings ----
    story.append(PageBreak())
    story.append(Paragraph(f"Vulnerability findings ({len(findings)})", ss["Heading2"]))
    if not findings:
        story.append(Paragraph("No BOLA/IDOR vulnerabilities were confirmed in this assessment.", ss["Normal"]))
    for i, f in enumerate(findings, 1):
        sev_color = SEVERITY_COLORS.get(f.severity, colors.HexColor("#64748b"))
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(f"{i}. {f.name}", ss["FindTitle"]))
        cats = ", ".join(json.loads(f.exposed_categories)) if f.exposed_categories else "none detected"
        detail_rows = [
            ["Severity", Paragraph(f'<font color="#{sev_color.hexval()[2:]}"><b>{f.severity}</b></font>', ss["Normal"])],
            ["Classification", f.classification],
            ["Affected endpoint", f"{f.method} {f.path}"],
            ["Requesting account", f.requester_name],
            ["Resource owner", f.owner_name],
            ["Resource id", str(f.resource_id)],
            ["HTTP response status", str(f.http_status if f.http_status is not None else "-")],
            ["Exposed data categories", cats],
        ]
        t3 = Table([[Paragraph(a, ss["Label"]), Paragraph(str(b), ss["Normal"])] for a, b in detail_rows],
                   colWidths=[42 * mm, 113 * mm])
        t3.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ]))
        story.append(t3)
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph("Technical explanation", ss["Label"]))
        story.append(Paragraph(f.technical_explanation or "", ss["Normal"]))
        story.append(Paragraph("Potential impact", ss["Label"]))
        story.append(Paragraph(f.potential_impact or "", ss["Normal"]))
        story.append(Paragraph("Recommended remediation", ss["Label"]))
        story.append(Paragraph(f.remediation or "", ss["Normal"]))
        story.append(Paragraph("Sanitized evidence (masked)", ss["Label"]))
        evidence_text = (f.evidence or "")[:2000]
        story.append(Paragraph(
            f'<font face="Courier" size="7">{_esc(evidence_text)}</font>', ss["Normal"]))

    doc.build(story)
    return buf.getvalue()


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\n", "<br/>")
    )
