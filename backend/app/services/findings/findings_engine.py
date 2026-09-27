"""Findings engine: generates security findings from validation and TLS results."""
from typing import List
from backend.app.models.models import FindingSeverity


class FindingItem:
    def __init__(self, category: str, severity: str, title: str, description: str, evidence: str = "", recommendation: str = "", cve: str = None, cwe: str = None, asset_hostname: str = None):
        self.category = category
        self.severity = severity
        self.title = title
        self.description = description
        self.evidence = evidence
        self.recommendation = recommendation
        self.cve = cve
        self.cwe = cwe
        self.asset_hostname = asset_hostname


class FindingsEngine:

    @staticmethod
    def analyze_tls(asset_hostname: str, tls_result) -> List[FindingItem]:
        findings = []

        if tls_result.ssl2_enabled:
            findings.append(FindingItem(
                category="TLS", severity=FindingSeverity.CRITICAL.value,
                title="SSLv2 Enabled",
                description=f"{asset_hostname} supports SSLv2, which is completely broken and obsolete.",
                evidence="SSLv2 protocol response confirmed",
                recommendation="Disable SSLv2 immediately. Use TLS 1.2 or TLS 1.3 only.",
                cve="CVE-2011-4762", cwe="CWE-326",
                asset_hostname=asset_hostname,
            ))
        if tls_result.ssl3_enabled:
            findings.append(FindingItem(
                category="TLS", severity=FindingSeverity.CRITICAL.value,
                title="SSLv3 Enabled (POODLE Vulnerable)",
                description=f"{asset_hostname} supports SSLv3, vulnerable to POODLE attack.",
                evidence="SSLv3 protocol response confirmed",
                recommendation="Disable SSLv3. Enable TLS 1.2/1.3 only.",
                cve="CVE-2014-3566", cwe="CWE-757",
                asset_hostname=asset_hostname,
            ))
        if tls_result.tls1_0_enabled:
            findings.append(FindingItem(
                category="TLS", severity=FindingSeverity.HIGH.value,
                title="TLS 1.0 Enabled",
                description=f"{asset_hostname} supports TLS 1.0, deprecated by PCI DSS and RFC 8996.",
                evidence="TLS 1.0 protocol response confirmed",
                recommendation="Disable TLS 1.0. Use TLS 1.2 (minimum) and TLS 1.3.",
                cve="CVE-2011-3389", cwe="CWE-326",
                asset_hostname=asset_hostname,
            ))
        if tls_result.tls1_1_enabled:
            findings.append(FindingItem(
                category="TLS", severity=FindingSeverity.MEDIUM.value,
                title="TLS 1.1 Enabled",
                description=f"{asset_hostname} supports TLS 1.1, deprecated by RFC 8996.",
                evidence="TLS 1.1 protocol response confirmed",
                recommendation="Disable TLS 1.1. Migrate to TLS 1.2 and TLS 1.3.",
                cwe="CWE-326",
                asset_hostname=asset_hostname,
            ))
        if not tls_result.tls1_2_enabled and not tls_result.tls1_3_enabled:
            findings.append(FindingItem(
                category="TLS", severity=FindingSeverity.CRITICAL.value,
                title="No Modern TLS Protocol Supported",
                description=f"{asset_hostname} does not support TLS 1.2 or TLS 1.3.",
                evidence="TLS 1.2 and TLS 1.3 both absent",
                recommendation="Enable TLS 1.2 and TLS 1.3 on your web server.",
                cwe="CWE-326",
                asset_hostname=asset_hostname,
            ))
        return findings

    @staticmethod
    def analyze_certificate(asset_hostname: str, cert) -> List[FindingItem]:
        findings = []
        if cert.status == "EXPIRED":
            findings.append(FindingItem(
                category="CERT", severity=FindingSeverity.CRITICAL.value,
                title="SSL Certificate Expired",
                description=f"Certificate on {asset_hostname} has expired.",
                evidence=f"Valid until: {cert.valid_until}",
                recommendation="Renew the SSL certificate immediately.",
                cwe="CWE-298",
                asset_hostname=asset_hostname,
            ))
        elif cert.status == "EXPIRING_SOON":
            days = cert.days_remaining or 0
            findings.append(FindingItem(
                category="CERT", severity=FindingSeverity.HIGH.value,
                title=f"SSL Certificate Expiring in {days} Days",
                description=f"Certificate on {asset_hostname} expires in {days} days.",
                evidence=f"Valid until: {cert.valid_until}",
                recommendation="Renew the SSL certificate before expiry.",
                cwe="CWE-298",
                asset_hostname=asset_hostname,
            ))
        if not cert.hostname_match:
            findings.append(FindingItem(
                category="CERT", severity=FindingSeverity.HIGH.value,
                title="Certificate Hostname Mismatch",
                description=f"Certificate CN/SANs do not match {asset_hostname}.",
                evidence=f"Subject: {cert.subject}, SANs: {cert.sans}",
                recommendation="Obtain a certificate valid for the target hostname.",
                cwe="CWE-297",
                asset_hostname=asset_hostname,
            ))
        return findings

    @staticmethod
    def analyze_ciphers(asset_hostname: str, ciphers: list) -> List[FindingItem]:
        findings = []
        weak = [c for c in ciphers if c.strength in ("WEAK", "DEPRECATED", "PROBLEMATIC")]
        if weak:
            findings.append(FindingItem(
                category="TLS", severity=FindingSeverity.HIGH.value,
                title=f"Weak/Deprecated Ciphers Supported ({len(weak)} found)",
                description=f"{asset_hostname} supports {len(weak)} weak cipher suite(s).",
                evidence="; ".join(f"{c.protocol}:{c.cipher}" for c in weak[:5]),
                recommendation="Disable weak cipher suites. Use AEAD ciphers (AES-GCM, ChaCha20) only.",
                cwe="CWE-326",
                asset_hostname=asset_hostname,
            ))
        return findings

    @staticmethod
    def analyze_headers(asset_hostname: str, header_results: list) -> List[FindingItem]:
        findings = []
        missing_critical = {
            "Strict-Transport-Security": (FindingSeverity.HIGH.value, "Missing HSTS allows downgrade attacks.", "CWE-319"),
            "Content-Security-Policy": (FindingSeverity.MEDIUM.value, "Missing CSP increases XSS risk.", "CWE-79"),
            "X-Frame-Options": (FindingSeverity.MEDIUM.value, "Missing X-Frame-Options allows clickjacking.", "CWE-1021"),
            "X-Content-Type-Options": (FindingSeverity.LOW.value, "Missing X-Content-Type-Options enables MIME sniffing.", "CWE-430"),
        }
        missing_in_results = {r.header_name for r in header_results if not r.present}
        for header, (sev, desc, cwe) in missing_critical.items():
            if header in missing_in_results:
                findings.append(FindingItem(
                    category="HEADER", severity=sev,
                    title=f"Missing Security Header: {header}",
                    description=f"{asset_hostname}: {desc}",
                    evidence=f"Header '{header}' not present in HTTP response",
                    recommendation=f"Add the '{header}' security header to all HTTP responses.",
                    cwe=cwe,
                    asset_hostname=asset_hostname,
                ))
        return findings
