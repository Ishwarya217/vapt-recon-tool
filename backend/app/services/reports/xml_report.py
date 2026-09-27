"""XML report generation."""
import xml.etree.ElementTree as ET
from datetime import datetime

from sqlalchemy.orm import Session

from backend.app.models.models import Asset, Discovery, Finding, Scan


def _sub(parent, tag, text=None, **attrs):
    el = ET.SubElement(parent, tag, **{k: str(v) for k, v in attrs.items()})
    if text is not None:
        el.text = str(text)
    return el


def generate_xml_report(scan: Scan, db: Session) -> bytes:
    root = ET.Element("VAPTReport", generated=datetime.utcnow().isoformat(), version="1.0")

    # Scan meta
    meta = _sub(root, "Scan")
    _sub(meta, "ID", scan.id)
    _sub(meta, "Target", scan.target_domain)
    _sub(meta, "Mode", scan.mode)
    _sub(meta, "Status", scan.status)
    _sub(meta, "StartedAt", str(scan.started_at or ""))
    _sub(meta, "CompletedAt", str(scan.completed_at or ""))

    # Discoveries
    disc_el = _sub(root, "Discoveries")
    for d in db.query(Discovery).filter(Discovery.scan_id == scan.id).all():
        de = _sub(disc_el, "Discovery")
        _sub(de, "Hostname", d.hostname)
        _sub(de, "Source", d.source)
        _sub(de, "SourceEngine", d.source_engine or "")
        _sub(de, "RecordType", d.record_type)

    # Assets
    assets_el = _sub(root, "Assets")
    for a in db.query(Asset).filter(Asset.scan_id == scan.id).all():
        ae = _sub(assets_el, "Asset", status=str(a.status))
        _sub(ae, "Hostname", a.hostname)
        _sub(ae, "DNSResolved", str(a.dns_resolved))
        _sub(ae, "IPs", ", ".join(a.ip_addresses or []))
        _sub(ae, "HTTPStatus", str(a.http_status_code or ""))
        _sub(ae, "HTTPSStatus", str(a.https_status_code or ""))
        _sub(ae, "TLSAssessed", str(a.tls_assessed))
        _sub(ae, "HeaderScore", str(a.security_headers_score or 0))

        for t in a.tls_results:
            te = _sub(ae, "TLS")
            _sub(te, "TLS10", str(t.tls1_0_enabled))
            _sub(te, "TLS11", str(t.tls1_1_enabled))
            _sub(te, "TLS12", str(t.tls1_2_enabled))
            _sub(te, "TLS13", str(t.tls1_3_enabled))
            _sub(te, "ProtocolStatus", t.protocol_status)

        for c in a.cert_results:
            ce = _sub(ae, "Certificate", status=str(c.status))
            _sub(ce, "CommonName", c.common_name or "")
            _sub(ce, "Issuer", c.issuer or "")
            _sub(ce, "ValidUntil", c.valid_until or "")
            _sub(ce, "DaysRemaining", str(c.days_remaining or ""))

    # Findings
    findings_el = _sub(root, "Findings")
    for f in db.query(Finding).filter(Finding.scan_id == scan.id).all():
        fe = _sub(findings_el, "Finding", severity=str(f.severity), category=str(f.category or ""))
        _sub(fe, "Title", f.title)
        _sub(fe, "Asset", f.asset_hostname or "")
        _sub(fe, "Description", f.description or "")
        _sub(fe, "Recommendation", f.recommendation or "")
        if f.cve:
            _sub(fe, "CVE", f.cve)
        if f.cwe:
            _sub(fe, "CWE", f.cwe)

    tree = ET.ElementTree(root)
    import io
    buf = io.BytesIO()
    tree.write(buf, encoding="utf-8", xml_declaration=True)
    return buf.getvalue()
