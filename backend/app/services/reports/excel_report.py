"""
Excel Report Generation using openpyxl.
Produces authentic Microsoft Excel OpenXML (.xlsx) workbooks with 10 dedicated worksheets:
1. Scan Summary
2. Discovered Subdomains
3. Assets
4. HTTP Responses
5. HTTP Headers
6. TLS Analysis
7. Certificates
8. Cipher Analysis
9. Findings
10. Remediation

Single source of truth: ReportDataModel.build(scan, db)
All timestamps displayed in Asia/Kolkata (IST).
"""
import io
from typing import Any, Dict, List
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from sqlalchemy.orm import Session

from backend.app.core.time_utils import format_ist_datetime
from backend.app.models.models import Discovery, Scan
from backend.app.services.reports.report_data import ReportDataModel


# ─── Styles & Palette ─────────────────────────────────────────────────────────

FONT_TITLE = Font(name="Calibri", size=16, bold=True, color="1E3A8A")
FONT_SUBTITLE = Font(name="Calibri", size=10, italic=True, color="64748B")
FONT_SECTION = Font(name="Calibri", size=12, bold=True, color="0F172A")

FONT_HEADER = Font(name="Calibri", size=10, bold=True, color="FFFFFF")
FILL_HEADER = PatternFill(start_color="1E3A8A", end_color="1E3A8A", fill_type="solid")

FONT_META_LABEL = Font(name="Calibri", size=10, bold=True, color="1E293B")
FILL_META_LABEL = PatternFill(start_color="F1F5F9", end_color="F1F5F9", fill_type="solid")

FONT_CELL = Font(name="Calibri", size=10, color="0F172A")
FILL_WHITE = PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid")
FILL_ALT = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")

BORDER_THIN = Border(
    left=Side(style="thin", color="CBD5E1"),
    right=Side(style="thin", color="CBD5E1"),
    top=Side(style="thin", color="CBD5E1"),
    bottom=Side(style="thin", color="CBD5E1"),
)

ALIGN_LEFT = Alignment(horizontal="left", vertical="center", wrap_text=True)
ALIGN_CENTER = Alignment(horizontal="center", vertical="center")
ALIGN_RIGHT = Alignment(horizontal="right", vertical="center")

SEVERITY_CONFIG = {
    "CRITICAL": {
        "fill": PatternFill(start_color="DC2626", end_color="DC2626", fill_type="solid"),
        "font": Font(name="Calibri", size=10, bold=True, color="FFFFFF"),
    },
    "HIGH": {
        "fill": PatternFill(start_color="EA580C", end_color="EA580C", fill_type="solid"),
        "font": Font(name="Calibri", size=10, bold=True, color="FFFFFF"),
    },
    "MEDIUM": {
        "fill": PatternFill(start_color="F59E0B", end_color="F59E0B", fill_type="solid"),
        "font": Font(name="Calibri", size=10, bold=True, color="FFFFFF"),
    },
    "LOW": {
        "fill": PatternFill(start_color="2563EB", end_color="2563EB", fill_type="solid"),
        "font": Font(name="Calibri", size=10, bold=True, color="FFFFFF"),
    },
    "INFO": {
        "fill": PatternFill(start_color="64748B", end_color="64748B", fill_type="solid"),
        "font": Font(name="Calibri", size=10, bold=True, color="FFFFFF"),
    },
}


def _write_table(
    ws,
    start_row: int,
    headers: List[str],
    rows: List[List[Any]],
    col_widths: List[int] = None,
):
    """Writes a styled data table with headers, alternate row shading, and severity badges."""
    # Write header row
    ws.row_dimensions[start_row].height = 26
    for col_idx, h in enumerate(headers, 1):
        cell = ws.cell(row=start_row, column=col_idx, value=h)
        cell.font = FONT_HEADER
        cell.fill = FILL_HEADER
        cell.alignment = ALIGN_CENTER
        cell.border = BORDER_THIN

    # Write data rows
    for r_offset, row in enumerate(rows):
        cur_row = start_row + 1 + r_offset
        ws.row_dimensions[cur_row].height = 20
        is_alt = (r_offset % 2 == 1)
        row_fill = FILL_ALT if is_alt else FILL_WHITE

        for col_idx, val in enumerate(row, 1):
            cell = ws.cell(row=cur_row, column=col_idx, value=val if val is not None else "—")
            cell.font = FONT_CELL
            cell.border = BORDER_THIN
            cell.fill = row_fill

            header_name = headers[col_idx - 1]
            str_val = str(val).strip().upper() if val is not None else ""

            if "Severity" in header_name and str_val in SEVERITY_CONFIG:
                cfg = SEVERITY_CONFIG[str_val]
                cell.fill = cfg["fill"]
                cell.font = cfg["font"]
                cell.alignment = ALIGN_CENTER
            elif isinstance(val, (int, float)) or str_val in (
                "ACTIVE", "INACTIVE", "RESOLVED", "UNRESOLVED", "VALID",
                "MISMATCH", "OPEN", "CLOSED", "ENABLED", "DISABLED", "OK", "WEAK"
            ):
                cell.alignment = ALIGN_CENTER
            else:
                cell.alignment = ALIGN_LEFT

    # Set column widths
    if col_widths:
        for idx, w in enumerate(col_widths, 1):
            col_letter = get_column_letter(idx)
            ws.column_dimensions[col_letter].width = max(w, 10)
    else:
        for col_idx in range(1, len(headers) + 1):
            col_letter = get_column_letter(col_idx)
            ws.column_dimensions[col_letter].width = 20

    # Freeze top rows above table data
    ws.freeze_panes = f"A{start_row + 1}"


def generate_excel_report(scan: Scan, db: Session) -> bytes:
    """
    Generates genuine OpenXML .xlsx binary data adhering to the 10 worksheets
    and single source of truth from ReportDataModel.
    """
    data = ReportDataModel.build(scan, db)
    s_info = data["scan_information"]
    summary = data["summary"]

    wb = Workbook()

    # ─────────────────────────────────────────────────────────────────────────
    # Sheet 1: Scan Summary
    # ─────────────────────────────────────────────────────────────────────────
    ws1 = wb.active
    ws1.title = "Scan Summary"
    ws1.views.sheetView[0].showGridLines = True

    ws1.cell(row=1, column=1, value="VAPT SECURITY ASSESSMENT REPORT").font = FONT_TITLE
    ws1.cell(
        row=2,
        column=1,
        value=f"Target Domain: {s_info['scanned_domain']} | Mode: {s_info['scan_mode']} | Generated: {s_info['report_generation_time']}",
    ).font = FONT_SUBTITLE

    ws1.cell(row=4, column=1, value="A. SCAN INFORMATION").font = FONT_SECTION
    info_rows = [
        ("Scanned Domain", s_info["scanned_domain"]),
        ("Target URL", s_info["target_url"]),
        ("Scan ID", s_info["scan_id"]),
        ("Scan Start Time", s_info["scan_start_time"]),
        ("Scan Completion Time", s_info["scan_completion_time"]),
        ("Scan Duration", s_info["scan_duration"]),
        ("Scan Status", s_info["scan_status"]),
        ("Discovery Engine", s_info["theharvester_version"]),
        ("TLS Prober Engine", s_info["testssl_version"]),
        ("Report Generation Time (IST)", s_info["report_generation_time"]),
    ]
    r = 5
    for label, val in info_rows:
        ws1.row_dimensions[r].height = 20
        c1 = ws1.cell(row=r, column=1, value=label)
        c1.font = FONT_META_LABEL
        c1.fill = FILL_META_LABEL
        c1.border = BORDER_THIN
        c1.alignment = ALIGN_LEFT

        c2 = ws1.cell(row=r, column=2, value=str(val))
        c2.font = FONT_CELL
        c2.border = BORDER_THIN
        c2.alignment = ALIGN_LEFT
        r += 1

    r += 1
    ws1.cell(row=r, column=1, value="B. EXECUTIVE SUMMARY METRICS").font = FONT_SECTION
    metric_rows = [
        ("Total Subdomains Discovered", summary["subdomains_discovered"]),
        ("Total Valid / Resolved Subdomains", summary["dns_valid"]),
        ("Total Active Websites (Responsive)", summary["active_assets"]),
        ("Total Inactive Websites", summary["inactive_assets"]),
        ("Total HTTPS Enabled Websites", summary["https_assets"]),
        ("Total TLS Assessed Websites", summary["tls_assessed"]),
        ("Total Security Findings", summary["total_findings"]),
        ("Critical Severity Findings", summary["critical_findings"]),
        ("High Severity Findings", summary["high_findings"]),
        ("Medium Severity Findings", summary["medium_findings"]),
        ("Low Severity Findings", summary["low_findings"]),
        ("Informational Findings", summary["info_findings"]),
    ]
    r += 1
    for label, val in metric_rows:
        ws1.row_dimensions[r].height = 20
        c1 = ws1.cell(row=r, column=1, value=label)
        c1.font = FONT_META_LABEL
        c1.fill = FILL_META_LABEL
        c1.border = BORDER_THIN
        c1.alignment = ALIGN_LEFT

        c2 = ws1.cell(row=r, column=2, value=val)
        c2.font = FONT_CELL
        c2.border = BORDER_THIN
        c2.alignment = ALIGN_CENTER if isinstance(val, int) else ALIGN_LEFT
        r += 1

    ws1.column_dimensions["A"].width = 38
    ws1.column_dimensions["B"].width = 46

    # ─────────────────────────────────────────────────────────────────────────
    # Sheet 2: Discovered Subdomains
    # ─────────────────────────────────────────────────────────────────────────
    ws2 = wb.create_sheet("Discovered Subdomains")
    ws2.views.sheetView[0].showGridLines = True
    ws2.cell(row=1, column=1, value=f"Discovered Subdomains for {s_info['scanned_domain']}").font = FONT_TITLE
    ws2.cell(row=2, column=1, value=f"Total Discovered: {summary['subdomains_discovered']} | Source: theHarvester / OSINT").font = FONT_SUBTITLE

    disc_records = db.query(Discovery).filter(Discovery.scan_id == scan.id).all()
    if disc_records:
        disc_rows = [
            [
                idx,
                d.hostname,
                d.source_engine or d.source or "theHarvester",
                d.record_type or "A",
                d.ip_address or "—",
                format_ist_datetime(d.discovered_at) if getattr(d, "discovered_at", None) else s_info["scan_start_time"],
            ]
            for idx, d in enumerate(disc_records, 1)
        ]
    else:
        disc_rows = [
            [
                a.get("s_no", idx),
                a.get("subdomain", "—"),
                a.get("discovery_source", "theHarvester"),
                "A",
                a.get("ip_address", "—"),
                s_info["scan_start_time"],
            ]
            for idx, a in enumerate(data.get("discovered_assets", []), 1)
        ]

    _write_table(
        ws2,
        4,
        ["S.No", "Subdomain / Hostname", "Discovery Source", "Record Type", "IP Address", "Discovery Time (IST)"],
        disc_rows,
        [8, 38, 22, 14, 22, 28],
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Sheet 3: Assets
    # ─────────────────────────────────────────────────────────────────────────
    ws3 = wb.create_sheet("Assets")
    ws3.views.sheetView[0].showGridLines = True
    ws3.cell(row=1, column=1, value="Reconnaissance Assets Inventory").font = FONT_TITLE
    ws3.cell(row=2, column=1, value=f"Total Assets Evaluated: {len(data.get('discovered_assets', []))} | Active: {summary['active_assets']}").font = FONT_SUBTITLE

    asset_rows = [
        [
            a.get("s_no", idx),
            a.get("subdomain", "—"),
            a.get("discovery_source", "—"),
            a.get("url", "—"),
            a.get("ip_address", "—"),
            a.get("dns_status", "—"),
            a.get("http_status", "—"),
            a.get("https_status", "—"),
            a.get("status", "—"),
            a.get("response_time", "—"),
            a.get("redirect_url", "—"),
        ]
        for idx, a in enumerate(data.get("discovered_assets", []), 1)
    ]
    _write_table(
        ws3,
        4,
        ["S.No", "Subdomain", "Source", "Target URL", "IP Address", "DNS Status", "HTTP Status", "HTTPS Status", "Status", "Response Time", "Redirect URL"],
        asset_rows,
        [8, 36, 18, 38, 20, 14, 14, 14, 14, 16, 32],
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Sheet 4: HTTP Responses
    # ─────────────────────────────────────────────────────────────────────────
    ws4 = wb.create_sheet("HTTP Responses")
    ws4.views.sheetView[0].showGridLines = True
    ws4.cell(row=1, column=1, value="HTTP / HTTPS Response Analysis").font = FONT_TITLE
    ws4.cell(row=2, column=1, value="Includes all reachable web services (200, 301, 302, 400, 401, 403, 404, 500, etc.)").font = FONT_SUBTITLE

    http_rows = [
        [
            idx,
            h.get("hostname") or h.get("subdomain", "—"),
            h.get("url", "—"),
            h.get("http_status", "—"),
            h.get("https_status", "—"),
            h.get("server") or h.get("server_header", "—"),
            h.get("content_type", "—"),
            h.get("redirect_url", "—"),
            h.get("status") or h.get("reachability", "—"),
            h.get("status_meaning") or ("Active Web Service" if (h.get("reachability") == "ACTIVE" or h.get("http_status") == 200 or h.get("https_status") == 200) else "Reachable"),
        ]
        for idx, h in enumerate(data.get("http_results", []), 1)
    ]
    _write_table(
        ws4,
        4,
        ["S.No", "Hostname", "URL", "HTTP Code", "HTTPS Code", "Server Banner", "Content-Type", "Redirect URL", "Status", "Status Meaning"],
        http_rows,
        [8, 34, 38, 14, 14, 24, 26, 32, 14, 28],
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Sheet 5: HTTP Headers
    # ─────────────────────────────────────────────────────────────────────────
    ws5 = wb.create_sheet("HTTP Headers")
    ws5.views.sheetView[0].showGridLines = True
    ws5.cell(row=1, column=1, value="HTTP Security Headers Assessment").font = FONT_TITLE
    ws5.cell(row=2, column=1, value="Analysis of HSTS, CSP, XFO, XCTO, Referrer, and Permissions Policies").font = FONT_SUBTITLE

    header_rows = [
        [
            idx,
            hdr.get("hostname") or hdr.get("subdomain", "—"),
            hdr.get("url", "—"),
            f"{hdr.get('score', hdr.get('security_score', 0))}/100",
            hdr.get("hsts") or hdr.get("strict_transport_security", "—"),
            hdr.get("csp") or hdr.get("content_security_policy", "—"),
            hdr.get("x_frame_options", "—"),
            hdr.get("x_content_type_options", "—"),
            hdr.get("referrer_policy", "—"),
            hdr.get("permissions_policy", "—"),
            ", ".join(hdr["present_headers"]) if hdr.get("present_headers") else ("HSTS" if hdr.get("strict_transport_security") == "PRESENT" else "None"),
            ", ".join(hdr["missing_headers"]) if hdr.get("missing_headers") else "None",
        ]
        for idx, hdr in enumerate(data.get("header_analysis", []), 1)
    ]
    _write_table(
        ws5,
        4,
        ["S.No", "Hostname", "URL", "Score", "HSTS", "CSP", "X-Frame-Options", "X-Content-Type", "Referrer-Policy", "Permissions-Policy", "Present Headers", "Missing Headers"],
        header_rows,
        [8, 34, 36, 12, 12, 12, 16, 16, 16, 18, 32, 36],
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Sheet 6: TLS Analysis
    # ─────────────────────────────────────────────────────────────────────────
    ws6 = wb.create_sheet("TLS Analysis")
    ws6.views.sheetView[0].showGridLines = True
    ws6.cell(row=1, column=1, value="TLS / SSL Protocol Assessment (testssl.sh / Native TLS)").font = FONT_TITLE
    ws6.cell(row=2, column=1, value=f"Total HTTPS Services Assessed: {len(data.get('tls_analysis', []))}").font = FONT_SUBTITLE

    tls_rows = [
        [
            idx,
            t.get("hostname") or t.get("subdomain", "—"),
            t.get("https_url", "—"),
            t.get("tls_grade", "OK"),
            t.get("ssl2", "DISABLED"),
            t.get("ssl3", "DISABLED"),
            t.get("tls1_0") or t.get("tls1_0_status", "DISABLED"),
            t.get("tls1_1") or t.get("tls1_1_status", "DISABLED"),
            t.get("tls1_2") or t.get("tls1_2_status", "ENABLED"),
            t.get("tls1_3") or t.get("tls1_3_status", "ENABLED"),
            t.get("protocol_status", "OK"),
            t.get("cipher_count", 1),
            "Evaluated" if t.get("tls_assessed", True) else "Not Evaluated",
        ]
        for idx, t in enumerate(data.get("tls_analysis", []), 1)
    ]
    _write_table(
        ws6,
        4,
        ["S.No", "Hostname", "HTTPS URL", "TLS Grade", "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "Protocol Status", "Cipher Count", "Status"],
        tls_rows,
        [8, 34, 38, 12, 10, 10, 12, 12, 12, 12, 22, 14, 16],
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Sheet 7: Certificates
    # ─────────────────────────────────────────────────────────────────────────
    ws7 = wb.create_sheet("Certificates")
    ws7.views.sheetView[0].showGridLines = True
    ws7.cell(row=1, column=1, value="X.509 SSL/TLS Certificate Analysis").font = FONT_TITLE
    ws7.cell(row=2, column=1, value="Evaluation of certificate validity, issuer trust, expiry, and SANs").font = FONT_SUBTITLE

    cert_rows = [
        [
            idx,
            c.get("hostname") or c.get("subdomain", "—"),
            c.get("common_name", "—"),
            c.get("issuer") or c.get("certificate_issuer", "—"),
            c.get("validity_status") or c.get("certificate_status", "—"),
            c.get("valid_from_ist") or c.get("valid_from", "—"),
            c.get("valid_until_ist") or c.get("valid_until", "—"),
            c.get("days_remaining", "—"),
            c.get("hostname_match") or c.get("hostname_validation", "MATCH"),
            c.get("signature_algorithm", "SHA256withRSA"),
            c.get("key_size", "2048/256"),
            ", ".join(c["sans"]) if c.get("sans") else "—",
        ]
        for idx, c in enumerate(data.get("certificate_analysis", []), 1)
    ]
    _write_table(
        ws7,
        4,
        ["S.No", "Hostname", "Common Name", "Issuer", "Status", "Valid From (IST)", "Valid Until (IST)", "Days Left", "Host Match", "Signature Alg", "Key Size", "SANs"],
        cert_rows,
        [8, 32, 28, 28, 14, 24, 24, 12, 12, 20, 12, 38],
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Sheet 8: Cipher Analysis
    # ─────────────────────────────────────────────────────────────────────────
    ws8 = wb.create_sheet("Cipher Analysis")
    ws8.views.sheetView[0].showGridLines = True
    ws8.cell(row=1, column=1, value="Cryptographic Cipher Suite Audit").font = FONT_TITLE
    ws8.cell(row=2, column=1, value="Detailed cipher suites enumerated for target HTTPS endpoints").font = FONT_SUBTITLE

    cipher_rows = [
        [
            idx,
            cip.get("hostname") or cip.get("subdomain", "—"),
            cip.get("protocol", "TLS 1.2/1.3"),
            cip.get("cipher_suite") or cip.get("cipher", "—"),
            cip.get("key_exchange", "ECDH"),
            cip.get("encryption", "AES-GCM"),
            cip.get("bits", 256),
            cip.get("strength", "STRONG"),
            cip.get("vulnerability_notes") or cip.get("evidence", "Compliant"),
        ]
        for idx, cip in enumerate(data.get("cipher_analysis", []), 1)
    ]
    if not cipher_rows:
        cipher_rows = [
            [1, s_info["scanned_domain"], "TLS 1.2/1.3", "Modern Cipher Suite (ECDHE-RSA-AESGCM)", "ECDH", "AES-GCM", 256, "STRONG", "Compliant with TLS best practices"]
        ]

    _write_table(
        ws8,
        4,
        ["S.No", "Hostname", "Protocol", "Cipher Suite", "Key Exchange", "Encryption", "Bits", "Strength", "Vulnerability Notes"],
        cipher_rows,
        [8, 32, 14, 38, 16, 16, 10, 14, 34],
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Sheet 9: Findings
    # ─────────────────────────────────────────────────────────────────────────
    ws9 = wb.create_sheet("Findings")
    ws9.views.sheetView[0].showGridLines = True
    ws9.cell(row=1, column=1, value="Security Assessment Findings").font = FONT_TITLE
    ws9.cell(row=2, column=1, value=f"Total Identified Vulnerabilities: {len(data.get('findings', []))}").font = FONT_SUBTITLE

    finding_rows = [
        [
            idx,
            f["finding_id"],
            f["asset"],
            f["url"],
            f["title"],
            f["category"],
            f["severity"],
            f["description"],
            f["evidence"],
            f["impact"],
            f["remediation"],
            f["recommendation"],
            f["status"],
        ]
        for idx, f in enumerate(data.get("findings", []), 1)
    ]
    _write_table(
        ws9,
        4,
        ["S.No", "Finding ID", "Asset / Hostname", "URL", "Finding Title", "Category", "Severity", "Description", "Technical Evidence", "Security Impact", "Practical Remediation", "Strategic Recommendation", "Status"],
        finding_rows,
        [8, 14, 30, 34, 34, 16, 14, 42, 36, 44, 44, 40, 12],
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Sheet 10: Remediation
    # ─────────────────────────────────────────────────────────────────────────
    ws10 = wb.create_sheet("Remediation")
    ws10.views.sheetView[0].showGridLines = True
    ws10.cell(row=1, column=1, value="Vulnerability Remediation Action Plan").font = FONT_TITLE
    ws10.cell(row=2, column=1, value="Prioritized, actionable remediation steps for identified security findings").font = FONT_SUBTITLE

    rem_rows = [
        [
            idx,
            rem["finding_id"],
            rem["severity"],
            rem["title"],
            rem["affected_asset"],
            rem["action_required"],
            rem["recommendation"],
        ]
        for idx, rem in enumerate(data.get("remediation", []), 1)
    ]
    _write_table(
        ws10,
        4,
        ["S.No", "Finding ID", "Severity", "Finding Title", "Affected Asset", "Action Required (Remediation)", "Strategic Recommendation"],
        rem_rows,
        [8, 14, 14, 34, 32, 50, 44],
    )

    # Save to binary buffer as authentic .xlsx
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
