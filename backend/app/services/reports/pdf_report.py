"""
PDF report generation using reportlab.
Produces a clear, professional security assessment report featuring:
- Executive Summary & Scan Metadata
- Master Table of Subdomains (Subdomain, IP, URL, HTTP/HTTPS Response Status, Header Score, TLS)
- HTTPS Header Analysis & SSL Check Findings as a list per host
- Detailed Security Findings (Critical, High, Medium, Low, Info)
"""
import io
from datetime import datetime
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.orm import Session

from backend.app.models.models import Asset, Finding, Scan


SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#DC2626"),
    "HIGH": colors.HexColor("#EA580C"),
    "MEDIUM": colors.HexColor("#CA8A04"),
    "LOW": colors.HexColor("#2563EB"),
    "INFO": colors.HexColor("#4B5563"),
}


def generate_pdf_report(scan: Scan, db: Session) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=20, leading=24, spaceAfter=4, textColor=colors.HexColor("#0F172A"))
    h1_style = ParagraphStyle("H1Style", parent=styles["Heading1"], fontSize=13, leading=16, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#1E3A8A"))
    h2_style = ParagraphStyle("H2Style", parent=styles["Heading2"], fontSize=10, leading=13, spaceBefore=6, spaceAfter=2, textColor=colors.HexColor("#334155"))
    body_style = ParagraphStyle("BodyStyle", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#374151"))
    mono_style = ParagraphStyle("MonoStyle", parent=body_style, fontName="Courier", fontSize=7.5, leading=10)
    bullet_style = ParagraphStyle("BulletStyle", parent=body_style, leftIndent=10, fontSize=7.5, leading=10)

    story = []

    # ── Cover Header ──────────────────────────────────────────────────────────
    story.append(Paragraph("VAPT Reconnaissance & Security Audit Report", title_style))
    story.append(Paragraph(f"Target Scope: <b>{scan.target_domain}</b> | Scan ID: <code>{scan.id[:12]}...</code>", h2_style))
    story.append(Paragraph(f"Execution Mode: <b>{scan.mode.upper()}</b> | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", body_style))
    story.append(Spacer(1, 0.3 * cm))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563EB")))
    story.append(Spacer(1, 0.4 * cm))

    # ── Executive Summary ─────────────────────────────────────────────────────
    assets = db.query(Asset).filter(Asset.scan_id == scan.id).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    active_assets = [a for a in assets if a.status == "ACTIVE"]

    story.append(Paragraph("1. Executive Summary", h1_style))
    summary_data = [
        ["Metric", "Value", "Metric", "Value"],
        ["Target Domain", scan.target_domain, "Total Subdomains Discovered", str(len(assets))],
        ["Active Assets (HTTP/HTTPS)", str(len(active_assets)), "DNS Valid Assets", str(sum(1 for a in assets if a.dns_resolved))],
        ["TLS Assessed Assets", str(sum(1 for a in assets if a.tls_assessed)), "Total Security Findings", str(len(findings))],
        ["Critical Findings", str(sum(1 for f in findings if f.severity == "CRITICAL")), "High Findings", str(sum(1 for f in findings if f.severity == "HIGH"))],
        ["Medium Findings", str(sum(1 for f in findings if f.severity == "MEDIUM")), "Low & Info Findings", str(sum(1 for f in findings if f.severity in ("LOW", "INFO")))],
    ]
    st = Table(summary_data, colWidths=[4.5 * cm, 4.5 * cm, 4.5 * cm, 4.5 * cm])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(st)
    story.append(Spacer(1, 0.5 * cm))

    # ── Subdomains Master Audit Table ─────────────────────────────────────────
    story.append(Paragraph("2. Subdomains & Endpoints Audit Table", h1_style))
    story.append(Paragraph("Consolidated inventory of discovered subdomains, IP addresses, target URLs, and response status codes.", body_style))
    story.append(Spacer(1, 0.2 * cm))

    if assets:
        table_data = [["Subdomain", "IP Address", "URL", "HTTP", "HTTPS", "Hdr Score", "TLS"]]
        for a in assets[:60]:
            ip = a.ip_addresses[0] if a.ip_addresses else "—"
            url = f"https://{a.hostname}" if a.https_status_code is not None else f"http://{a.hostname}"
            table_data.append([
                Paragraph(f"<b>{a.hostname}</b>", mono_style),
                Paragraph(ip, mono_style),
                Paragraph(url, mono_style),
                str(a.http_status_code or "—"),
                str(a.https_status_code or "—"),
                f"{a.security_headers_score or 0}/100",
                a.tls_grade or ("✓" if a.tls_assessed else "—"),
            ])

        at = Table(table_data, colWidths=[5.0 * cm, 2.7 * cm, 4.8 * cm, 1.4 * cm, 1.4 * cm, 1.7 * cm, 1.0 * cm])
        at.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("ALIGN", (3, 0), (-1, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(at)
    else:
        story.append(Paragraph("No subdomains identified.", body_style))

    story.append(Spacer(1, 0.5 * cm))

    # ── HTTPS Header Analysis & SSL Check Findings as a List ─────────────────
    story.append(Paragraph("3. HTTPS Header Analysis & SSL Check Findings (Detailed List)", h1_style))
    story.append(Paragraph("Detailed breakdown of HTTP security headers and SSL/TLS findings for reachable assets.", body_style))
    story.append(Spacer(1, 0.2 * cm))

    # Index findings by host
    findings_by_host = {}
    for f in findings:
        h = f.asset_hostname or "general"
        if h not in findings_by_host:
            findings_by_host[h] = []
        findings_by_host[h].append(f)

    active_with_data = [a for a in active_assets if a.tls_assessed or a.header_results or (a.hostname in findings_by_host)]
    if not active_with_data:
        active_with_data = active_assets[:15]

    for a in active_with_data[:30]:
        host_flowables = []
        host_flowables.append(Paragraph(f"<b>🌐 Subdomain: {a.hostname}</b> ({a.ip_addresses[0] if a.ip_addresses else '—'})", h2_style))

        # Header analysis row
        hdr_status = []
        hdr_status.append(f"HSTS: {'✓' if a.has_hsts else '✗'}")
        hdr_status.append(f"CSP: {'✓' if a.has_csp else '✗'}")
        hdr_status.append(f"X-Frame-Options: {'✓' if a.has_xfo else '✗'}")
        hdr_status.append(f"X-Content-Type: {'✓' if a.has_xcto else '✗'}")
        hdr_summary_str = f"<b>Security Headers ({a.security_headers_score or 0}/100):</b> " + ", ".join(hdr_status)
        host_flowables.append(Paragraph(hdr_summary_str, body_style))

        # SSL / TLS details
        ssl_items = []
        if a.tls_results and len(a.tls_results) > 0:
            t = a.tls_results[0]
            protos = []
            if t.tls1_3_enabled: protos.append("TLS 1.3")
            if t.tls1_2_enabled: protos.append("TLS 1.2")
            if t.tls1_1_enabled: protos.append("TLS 1.1 (deprecated)")
            if t.tls1_0_enabled: protos.append("TLS 1.0 (deprecated)")
            if t.ssl3_enabled: protos.append("SSLv3 (vulnerable)")
            if protos:
                ssl_items.append(f"<b>Protocols:</b> {', '.join(protos)} (Status: {t.protocol_status})")

        if a.cert_results and len(a.cert_results) > 0:
            c = a.cert_results[0]
            cert_str = f"<b>Certificate:</b> {c.status} | CN: {c.common_name or '—'} | Issuer: {c.issuer or '—'} | Valid Until: {c.valid_until or '—'} ({c.days_remaining}d remaining)"
            if not c.hostname_match:
                cert_str += " <font color='#DC2626'>[HOSTNAME MISMATCH]</font>"
            ssl_items.append(cert_str)

        # Host-specific TLS/CERT findings list
        host_finds = findings_by_host.get(a.hostname, [])
        for f in host_finds:
            color_hex = SEVERITY_COLORS.get(f.severity, colors.black).hexval()
            ssl_items.append(f"<font color='{color_hex}'>• [{f.severity}] <b>{f.title}</b></font>: {f.recommendation or f.description or ''}")

        if not ssl_items and a.tls_assessed:
            ssl_items.append("• Modern TLS enabled, valid certificate, zero SSL/TLS vulnerabilities detected.")

        for item in ssl_items:
            host_flowables.append(Paragraph(item, bullet_style))

        host_flowables.append(Spacer(1, 0.25 * cm))
        story.append(KeepTogether(host_flowables))

    story.append(Spacer(1, 0.4 * cm))

    # ── Security Findings ─────────────────────────────────────────────────────
    story.append(Paragraph("4. Complete Security Findings", h1_style))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_findings = [f for f in findings if f.severity == sev]
        if not sev_findings:
            continue
        color_hex = SEVERITY_COLORS[sev].hexval()
        story.append(Paragraph(f"<font color='{color_hex}'><b>{sev} Findings ({len(sev_findings)})</b></font>", h2_style))

        for f in sev_findings:
            f_box = []
            f_box.append(Paragraph(f"<b>{f.title}</b> — <font color='#0284C7'>{f.asset_hostname or 'General Scope'}</font>", body_style))
            if f.description:
                f_box.append(Paragraph(f.description, body_style))
            if f.evidence:
                f_box.append(Paragraph(f"<b>Evidence:</b> {f.evidence}", mono_style))
            if f.recommendation:
                f_box.append(Paragraph(f"<b>Remediation:</b> {f.recommendation}", body_style))
            f_box.append(Spacer(1, 0.2 * cm))
            story.append(KeepTogether(f_box))

    doc.build(story)
    return buffer.getvalue()
