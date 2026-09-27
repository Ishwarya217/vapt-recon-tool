"""Mock data generator for testing without live tools."""
from datetime import datetime, timedelta
from typing import List

from backend.app.services.theharvester.models import DiscoveredItem, DiscoveryBatch
from backend.app.services.testssl.models import (
    CertificateDetails,
    CipherDetails,
    ProtocolSupport,
    TLSAssessmentResult,
    VulnerabilityFinding,
)


def generate_mock_batch(domain: str) -> DiscoveryBatch:
    subdomains = [
        f"www.{domain}", f"mail.{domain}", f"api.{domain}",
        f"dev.{domain}", f"staging.{domain}", f"admin.{domain}",
        f"portal.{domain}", f"cdn.{domain}", f"static.{domain}",
        f"blog.{domain}", f"shop.{domain}", f"support.{domain}",
    ]
    items = []
    sources = ["crtsh", "hackertarget", "rapiddns", "certspotter"]
    for i, hn in enumerate(subdomains):
        items.append(DiscoveredItem(
            hostname=hn,
            domain=domain,
            source="theHarvester",
            source_engine=sources[i % len(sources)],
            record_type="hostname",
        ))
    return DiscoveryBatch(
        domain=domain,
        items=items,
        total_discovered=len(items),
        sources_used=sources,
    )


def generate_mock_tls(hostname: str) -> TLSAssessmentResult:
    cert_until = (datetime.utcnow() + timedelta(days=45)).strftime("%Y-%m-%d")
    cert = CertificateDetails(
        subject=f"CN={hostname}",
        common_name=hostname,
        issuer="Let's Encrypt Authority X3",
        valid_from="2025-01-01",
        valid_until=cert_until,
        days_remaining=45,
        sans=[hostname, f"www.{hostname}"],
        hostname_match=True,
        status="EXPIRING_SOON",
        signature_algorithm="sha256WithRSAEncryption",
        key_size="2048",
    )
    protocols = ProtocolSupport(
        tls1_0=True,   # Intentionally weak for demo findings
        tls1_1=False,
        tls1_2=True,
        tls1_3=True,
        ssl2=False,
        ssl3=False,
        status="WEAK",
    )
    ciphers = [
        CipherDetails(protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", strength="STRONG", status="OK", evidence="TLSv1.3 AEAD"),
        CipherDetails(protocol="TLSv1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256", strength="STRONG", status="OK", evidence="ECDHE forward secrecy"),
        CipherDetails(protocol="TLSv1.0", cipher="DES-CBC3-SHA", strength="WEAK", status="WEAK", evidence="Triple DES, deprecated"),
    ]
    return TLSAssessmentResult(
        target=hostname,
        ip_address="93.184.216.34",
        port=443,
        certificate=cert,
        protocols=protocols,
        ciphers=ciphers,
        vulnerabilities=[],
        execution_time_seconds=2.5,
    )
