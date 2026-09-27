import json
import os
import re
from datetime import datetime
from typing import Dict, List, Optional

from backend.app.services.testssl.models import (
    CertificateDetails,
    CipherDetails,
    ProtocolSupport,
    TLSAssessmentResult,
    VulnerabilityFinding,
)


class TestSSLParser:
    """Parses testssl.sh structured JSON output."""

    @staticmethod
    def parse_json_file(file_path: str, target: str) -> TLSAssessmentResult:
        if not os.path.exists(file_path):
            return TLSAssessmentResult(target=target)

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw_content = f.read()

        try:
            data = json.loads(raw_content)
        except Exception:
            return TLSAssessmentResult(target=target, raw_json_output=raw_content)

        findings = data.get("scanResult", [])
        if not isinstance(findings, list):
            findings = []

        cert_details = CertificateDetails()
        protocols = ProtocolSupport()
        ciphers: List[CipherDetails] = []
        vulnerabilities: List[VulnerabilityFinding] = []
        target_ip: Optional[str] = None

        sans_list: List[str] = []

        for item in findings:
            if not isinstance(item, dict):
                continue

            item_id = item.get("id", "")
            finding_str = item.get("finding", "")
            severity = item.get("severity", "INFO")
            ip = item.get("ip")
            if ip and not target_ip:
                target_ip = ip.split("/")[0]

            # 1. Protocols
            if item_id == "SSLv2":
                protocols.ssl2 = "offered" in finding_str.lower() or "offered (NOT ok)" in finding_str
            elif item_id == "SSLv3":
                protocols.ssl3 = "offered" in finding_str.lower() or "offered (NOT ok)" in finding_str
            elif item_id == "TLS1":
                protocols.tls1_0 = "offered" in finding_str.lower() and "not offered" not in finding_str.lower()
            elif item_id == "TLS1_1":
                protocols.tls1_1 = "offered" in finding_str.lower() and "not offered" not in finding_str.lower()
            elif item_id == "TLS1_2":
                protocols.tls1_2 = "offered" in finding_str.lower() and "not offered" not in finding_str.lower()
            elif item_id == "TLS1_3":
                protocols.tls1_3 = "offered" in finding_str.lower() and "not offered" not in finding_str.lower()

            # 2. Certificate Information
            elif item_id in ("cert_certTrust", "cert_trust"):
                cert_details.status = "VALID" if "ok" in finding_str.lower() else "INVALID"
            elif item_id in ("cert_cn", "cert_commonName"):
                cert_details.common_name = finding_str
            elif item_id in ("cert_issuer", "cert_issuerName"):
                cert_details.issuer = finding_str
            elif item_id in ("cert_san", "cert_subjectAltName"):
                sans_list.extend(finding_str.split())
            elif item_id in ("cert_expirationStatus", "cert_notAfter"):
                if "days" in finding_str:
                    match = re.search(r"(\d+)\s+days", finding_str)
                    if match:
                        days = int(match.group(1))
                        cert_details.days_remaining = days
                        if days <= 0:
                            cert_details.status = "EXPIRED"
                        elif days <= 30:
                            cert_details.status = "EXPIRING_SOON"
                cert_details.valid_until = finding_str
            elif item_id in ("cert_signatureAlgorithm", "cert_signature"):
                cert_details.signature_algorithm = finding_str
            elif item_id in ("cert_keySize", "cert_key"):
                cert_details.key_size = finding_str

            # 3. Ciphers
            elif "cipher" in item_id.lower():
                strength = "STRONG"
                if severity in ("HIGH", "CRITICAL"):
                    strength = "WEAK"
                elif severity in ("MEDIUM", "WARN"):
                    strength = "PROBLEMATIC"

                ciphers.append(
                    CipherDetails(
                        protocol=item.get("finding", "").split()[0] if item.get("finding") else "TLS",
                        cipher=item_id,
                        strength=strength,
                        status=severity,
                        evidence=finding_str,
                    )
                )

            # 4. Vulnerabilities
            elif severity in ("HIGH", "CRITICAL", "WARN", "MEDIUM"):
                vulnerabilities.append(
                    VulnerabilityFinding(
                        id=item_id,
                        severity=severity,
                        finding=finding_str,
                        cve=item.get("cve"),
                        cwe=item.get("cwe"),
                    )
                )

        if sans_list:
            cert_details.sans = list(set(sans_list))

        # Classify Protocol Security Status
        if protocols.ssl2 or protocols.ssl3:
            protocols.status = "CRITICAL"
        elif protocols.tls1_0 or protocols.tls1_1:
            protocols.status = "WEAK"
        else:
            protocols.status = "OK"

        return TLSAssessmentResult(
            target=target,
            ip_address=target_ip,
            certificate=cert_details,
            protocols=protocols,
            ciphers=ciphers,
            vulnerabilities=vulnerabilities,
            raw_json_output=raw_content,
        )
