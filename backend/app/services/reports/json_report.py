"""
JSON Report Generation.
Produces structured JSON export adhering to the normalized ReportDataModel:
- scan_information (with ISO-8601 timestamps in Asia/Kolkata +05:30)
- summary (counts for discovered, dns valid, active, inactive, https, tls, findings)
- discovered_assets
- http_results
- header_analysis
- tls_analysis
- certificate_analysis
- cipher_analysis
- findings (with Title, Category, Severity, Description, Evidence, Impact, Remediation)
- remediation (actionable, non-generic steps per finding)
"""
import json
from typing import Any, Dict
from sqlalchemy.orm import Session

from backend.app.models.models import Scan
from backend.app.services.reports.report_data import ReportDataModel


def generate_json_report(scan: Scan, db: Session) -> Dict[str, Any]:
    """Generates the structured JSON dictionary from the normalized report data model."""
    return ReportDataModel.build(scan, db)


def generate_json_report_bytes(scan: Scan, db: Session) -> bytes:
    """Generates formatted JSON bytes for download."""
    data = generate_json_report(scan, db)
    return json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
