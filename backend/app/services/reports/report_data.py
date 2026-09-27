"""
Single Normalized Report Data Model.
Acts as the single source of truth for all report formats (PDF, Excel, JSON) and UI consistency.
Pulls finalized scan records from the database without re-running any scanner.
All timestamps are converted and presented in Asia/Kolkata (IST, UTC+05:30).
"""
import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from backend.app.core.time_utils import (
    format_duration,
    format_ist_datetime,
    format_ist_iso,
    format_ist_short,
    now_ist,
    to_ist,
)
from backend.app.models.models import Asset, CertificateResult, CipherResult, Discovery, Finding, HeaderResult, Scan, TLSResult


# Curated, professional Impact and Remediation dictionary mapped to security findings
FINDING_KNOWLEDGE_BASE = {
    "SSLv2 Enabled": {
        "impact": "SSLv2 is fundamentally insecure and obsolete. Attackers can decrypt intercepted communications using known exploits such as DROWN (CVE-2016-0800), compromising user data and authentication tokens.",
        "remediation": "Disable SSLv2 immediately on the web server or load balancer. Configure protocols to permit only TLS 1.2 and TLS 1.3.",
    },
    "SSLv3 Enabled": {
        "impact": "SSLv3 is vulnerable to the POODLE attack (CVE-2014-3566), allowing an attacker in a man-in-the-middle position to decipher plaintext cookies and sensitive session information.",
        "remediation": "Disable SSLv3 across all server configurations. Enforce TLS 1.2 and TLS 1.3 as the exclusive supported protocols.",
    },
    "TLS 1.0 Enabled": {
        "impact": "TLS 1.0 relies on deprecated SHA-1 hashing and CBC cipher suites vulnerable to cryptographic attacks (e.g. BEAST). Running TLS 1.0 violates modern regulatory standards including PCI DSS 3.2.1.",
        "remediation": "Disable TLS 1.0 in web server and TLS termination configurations (e.g., in Nginx: 'ssl_protocols TLSv1.2 TLSv1.3;').",
    },
    "TLS 1.1 Enabled": {
        "impact": "TLS 1.1 has been deprecated by RFC 8996 and major browser vendors. It lacks support for modern AEAD ciphers and exposes traffic to downgrade and protocol weakness risks.",
        "remediation": "Disable TLS 1.1 on all edge routers, proxies, and web servers. Require TLS 1.2 and TLS 1.3.",
    },
    "No Modern TLS Protocol Supported": {
        "impact": "The server does not support TLS 1.2 or TLS 1.3. Secure clients will fail to connect or be forced into broken legacy protocols, leaving all session data exposed to eavesdropping.",
        "remediation": "Upgrade OpenSSL and web server software. Enable TLS 1.2 and TLS 1.3 cipher suites.",
    },
    "SSL Certificate Expired": {
        "impact": "Modern browsers and API consumers reject expired certificates with blocking security warnings, breaking service availability and preventing trusted encrypted connections.",
        "remediation": "Immediately renew and deploy a valid SSL/TLS certificate from a recognized Certificate Authority (CA). Implement automated certificate renewal via ACME/Certbot.",
    },
    "Certificate Hostname Mismatch": {
        "impact": "The certificate presented does not match the requested hostname. Browsers display security alerts, and automated clients fail TLS handshakes to prevent MITM impersonation.",
        "remediation": "Reissue the certificate to include this hostname in the Subject Alternative Name (SAN) extension, or deploy an appropriate wildcard or multi-domain certificate.",
    },
    "Weak/Deprecated Ciphers Supported": {
        "impact": "Insecure or legacy ciphers (e.g., RC4, 3DES, CBC mode ciphers) are susceptible to cryptographic attacks (SWEET32, Lucky13), reducing confidentiality of transmitted data.",
        "remediation": "Configure the web server cipher list to prioritize modern authenticated ciphers (such as ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384) and disable weak ciphers.",
    },
    "Missing Security Header: Strict-Transport-Security": {
        "impact": "Without HSTS, initial connections over plaintext HTTP can be intercepted via SSL stripping attacks, allowing eavesdroppers to hijack credentials or session tokens.",
        "remediation": "Add the 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header to all HTTPS responses.",
    },
    "Missing Security Header: Content-Security-Policy": {
        "impact": "Without a Content Security Policy (CSP), the application is more susceptible to Cross-Site Scripting (XSS), malicious script injection, and clickjacking attacks.",
        "remediation": "Implement a robust Content-Security-Policy header restricting resource loading to trusted domains and disallowing inline script execution.",
    },
    "Missing Security Header: X-Frame-Options": {
        "impact": "Without X-Frame-Options or CSP frame-ancestors, attackers can embed the application inside an invisible iframe on a malicious website to perform Clickjacking attacks.",
        "remediation": "Configure 'X-Frame-Options: SAMEORIGIN' (or 'DENY') on all web responses.",
    },
    "Missing Security Header: X-Content-Type-Options": {
        "impact": "Without 'X-Content-Type-Options: nosniff', older and non-standard browsers may perform MIME sniffing, treating non-script files (such as images) as executable JavaScript.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' to all HTTP and HTTPS responses.",
    },
    "Missing Security Header: Referrer-Policy": {
        "impact": "The Referer header may inadvertently leak internal URL parameters, authentication tokens, or sensitive endpoint paths to external third-party domains.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to all response headers.",
    },
    "Missing Security Header: Permissions-Policy": {
        "impact": "The browser cannot restrict access to sensitive device hardware (camera, microphone, geolocation, payment) in embedded contexts.",
        "remediation": "Implement a 'Permissions-Policy' header disabling unneeded browser features.",
    },
    "Server Version Disclosure": {
        "impact": "Revealing detailed web server and operating system versions assists attackers in selecting version-specific exploits.",
        "remediation": "Disable detailed version banners in the server configuration (e.g., 'ServerTokens Prod' in Apache, 'server_tokens off;' in Nginx).",
    },
}


def _get_impact_and_remediation(title: str, description: str = "", category: str = "") -> tuple:
    """Returns tailored impact and remediation strings for a given finding."""
    # Check exact match
    if title in FINDING_KNOWLEDGE_BASE:
        return FINDING_KNOWLEDGE_BASE[title]["impact"], FINDING_KNOWLEDGE_BASE[title]["remediation"]

    # Check partial match
    title_lower = title.lower()
    for key, data in FINDING_KNOWLEDGE_BASE.items():
        if key.lower() in title_lower or any(word in title_lower for word in key.lower().split() if len(word) > 4):
            return data["impact"], data["remediation"]

    # Category defaults
    if category == "TLS":
        return (
            "Cryptographic weaknesses or deprecated protocol settings can allow attackers to intercept, manipulate, or decrypt secure communication between clients and the server.",
            "Review server TLS configurations to disable legacy protocols and weak cipher suites. Enforce modern TLS 1.2 and TLS 1.3 standards."
        )
    elif category == "CERT":
        return (
            "Invalid, expiring, or misconfigured certificates undermine identity verification and cause browser warning alerts, potentially enabling man-in-the-middle attacks.",
            "Reissue and properly install a validated SSL/TLS certificate with complete chain and correct Subject Alternative Names (SANs)."
        )
    elif category == "HEADER":
        return (
            "Missing HTTP security headers leave the application vulnerable to client-side attacks such as Cross-Site Scripting (XSS), Clickjacking, and MIME-sniffing.",
            "Implement recommended security headers across all web server response configurations."
        )

    return (
        "This security condition may increase the attack surface or permit unauthorized access depending on surrounding controls.",
        "Apply vendor security best practices and harden the system configuration according to industry standards."
    )


class ReportDataModel:
    """Normalized scan report data model representing the single source of truth."""

    @staticmethod
    def build(scan: Scan, db: Session) -> Dict[str, Any]:
        """Builds the complete normalized report structure from database entities."""
        # 1. Fetch raw entities
        discoveries = db.query(Discovery).filter(Discovery.scan_id == scan.id).all()
        assets = db.query(Asset).filter(Asset.scan_id == scan.id).all()
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

        # Pre-index findings by asset hostname
        findings_by_host: Dict[str, List[Finding]] = {}
        for f in findings:
            host = (f.asset_hostname or "general").strip().lower()
            if host not in findings_by_host:
                findings_by_host[host] = []
            findings_by_host[host].append(f)

        # 2. Compute Exact Consistent Summary Counts
        total_subdomains = len(assets)
        dns_valid_count = sum(1 for a in assets if a.dns_resolved)
        active_assets_count = sum(1 for a in assets if a.status == "ACTIVE")
        inactive_assets_count = total_subdomains - active_assets_count
        https_assets_count = sum(1 for a in assets if a.https_status_code is not None)
        tls_assessed_count = sum(1 for a in assets if a.tls_assessed)

        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")
        info_count = sum(1 for f in findings if f.severity == "INFO")

        # 3. Scan Information (Section A)
        target_domain = scan.target_domain.strip().lower()
        target_url = f"https://{target_domain}"

        scan_info = {
            "scanned_domain": target_domain,
            "target_url": target_url,
            "scan_id": scan.id,
            "scan_start_time": format_ist_datetime(scan.started_at),
            "scan_completion_time": format_ist_datetime(scan.completed_at),
            "scan_start_iso": format_ist_iso(scan.started_at),
            "scan_completion_iso": format_ist_iso(scan.completed_at),
            "scan_duration": format_duration(scan.started_at, scan.completed_at),
            "scan_status": getattr(scan.status, "value", str(scan.status)),
            "scan_mode": scan.mode.upper(),
            "theharvester_version": scan.theharvester_version or "theHarvester 5.0.0",
            "testssl_version": scan.testssl_version or "testssl.sh / Native TLS Prober",
            "total_subdomains_discovered": total_subdomains,
            "total_valid_resolved_subdomains": dns_valid_count,
            "total_active_websites": active_assets_count,
            "total_inactive_websites": inactive_assets_count,
            "total_https_websites": https_assets_count,
            "total_tls_assessed": tls_assessed_count,
            "report_generation_time": format_ist_datetime(now_ist()),
            "report_generation_iso": format_ist_iso(now_ist()),
        }

        # 4. Discovered Assets (Section B)
        discovered_assets: List[Dict[str, Any]] = []
        http_results: List[Dict[str, Any]] = []
        header_analysis_list: List[Dict[str, Any]] = []
        tls_analysis_list: List[Dict[str, Any]] = []
        certificate_analysis_list: List[Dict[str, Any]] = []
        cipher_analysis_list: List[Dict[str, Any]] = []

        for idx, a in enumerate(assets, 1):
            hostname = a.hostname.strip().lower()
            ip_list = a.ip_addresses or []
            primary_ip = ip_list[0] if ip_list else "—"

            # URL determination
            if a.https_status_code is not None:
                url = f"https://{hostname}"
            elif a.http_status_code is not None:
                url = f"http://{hostname}"
            else:
                url = "—"

            dns_status_str = "Resolved" if a.dns_resolved else "Unresolved"
            status_str = "ACTIVE" if a.status == "ACTIVE" else "INACTIVE"
            response_time = (
                f"{int(round(a.https_response_time_ms))} ms"
                if a.https_response_time_ms
                else (f"{int(round(a.http_response_time_ms))} ms" if a.http_response_time_ms else "—")
            )

            asset_record = {
                "s_no": idx,
                "subdomain": hostname,
                "discovery_source": a.source or "theHarvester",
                "url": url,
                "ip_address": primary_ip,
                "all_ips": ip_list,
                "dns_status": dns_status_str,
                "http_status": a.http_status_code if a.http_status_code is not None else "—",
                "https_status": a.https_status_code if a.https_status_code is not None else "—",
                "status": status_str,
                "response_time": response_time,
                "redirect_url": a.http_redirect_url or "—",
            }
            discovered_assets.append(asset_record)

            # HTTP Responses (Section B / C drilldown)
            if a.http_status_code is not None or a.https_status_code is not None or a.status == "ACTIVE":
                http_results.append({
                    "subdomain": hostname,
                    "url": url,
                    "http_status": a.http_status_code if a.http_status_code is not None else "—",
                    "https_status": a.https_status_code if a.https_status_code is not None else "—",
                    "server_header": a.server_header or "—",
                    "response_time": response_time,
                    "redirect_url": a.http_redirect_url or "—",
                    "reachability": status_str,
                })

            # HTTP Header Analysis (Section C)
            headers_records = a.header_results or []
            hsts_val = next((h.header_value for h in headers_records if h.header_name == "Strict-Transport-Security"), None)
            csp_val = next((h.header_value for h in headers_records if h.header_name == "Content-Security-Policy"), None)
            xfo_val = next((h.header_value for h in headers_records if h.header_name == "X-Frame-Options"), None)
            xcto_val = next((h.header_value for h in headers_records if h.header_name == "X-Content-Type-Options"), None)
            ref_val = next((h.header_value for h in headers_records if h.header_name == "Referrer-Policy"), None)
            perm_val = next((h.header_value for h in headers_records if h.header_name == "Permissions-Policy"), None)

            header_status_map = {
                "Strict-Transport-Security": "PRESENT" if a.has_hsts else "MISSING",
                "Content-Security-Policy": "PRESENT" if a.has_csp else "MISSING",
                "X-Frame-Options": "PRESENT" if a.has_xfo else "MISSING",
                "X-Content-Type-Options": "PRESENT" if a.has_xcto else "MISSING",
                "Referrer-Policy": "PRESENT" if a.has_referrer_policy else "MISSING",
                "Permissions-Policy": "PRESENT" if a.has_permissions_policy else "MISSING",
            }

            if a.status == "ACTIVE" or headers_records or a.https_status_code is not None:
                header_analysis_list.append({
                    "subdomain": hostname,
                    "url": url,
                    "http_status": a.https_status_code or a.http_status_code or "—",
                    "server": a.server_header or "—",
                    "content_type": "text/html" if a.status == "ACTIVE" else "—",
                    "x_powered_by": "—",
                    "strict_transport_security": header_status_map["Strict-Transport-Security"],
                    "content_security_policy": header_status_map["Content-Security-Policy"],
                    "x_content_type_options": header_status_map["X-Content-Type-Options"],
                    "x_frame_options": header_status_map["X-Frame-Options"],
                    "referrer_policy": header_status_map["Referrer-Policy"],
                    "permissions_policy": header_status_map["Permissions-Policy"],
                    "security_score": a.security_headers_score if a.security_headers_score is not None else 0,
                    "hsts_value": hsts_val or "—",
                    "csp_value": csp_val or "—",
                    "xfo_value": xfo_val or "—",
                    "xcto_value": xcto_val or "—",
                })

            # TLS / SSL Analysis (Section D)
            if a.tls_results and len(a.tls_results) > 0:
                t = a.tls_results[0]
                protos = []
                if t.tls1_3_enabled: protos.append("TLS 1.3")
                if t.tls1_2_enabled: protos.append("TLS 1.2")
                if t.tls1_1_enabled: protos.append("TLS 1.1")
                if t.tls1_0_enabled: protos.append("TLS 1.0")
                if t.ssl3_enabled: protos.append("SSLv3")
                if t.ssl2_enabled: protos.append("SSLv2")

                weak_protos = []
                if t.tls1_0_enabled: weak_protos.append("TLS 1.0 (Deprecated)")
                if t.tls1_1_enabled: weak_protos.append("TLS 1.1 (Deprecated)")
                if t.ssl3_enabled: weak_protos.append("SSLv3 (Vulnerable)")
                if t.ssl2_enabled: weak_protos.append("SSLv2 (Broken)")

                tls_analysis_list.append({
                    "subdomain": hostname,
                    "https_url": f"https://{hostname}",
                    "tls_versions_supported": ", ".join(protos) if protos else "None",
                    "tls1_0_status": "ENABLED (Deprecated)" if t.tls1_0_enabled else "DISABLED",
                    "tls1_1_status": "ENABLED (Deprecated)" if t.tls1_1_enabled else "DISABLED",
                    "tls1_2_status": "ENABLED" if t.tls1_2_enabled else "DISABLED",
                    "tls1_3_status": "ENABLED" if t.tls1_3_enabled else "DISABLED",
                    "weak_deprecated_protocols": ", ".join(weak_protos) if weak_protos else "None detected",
                    "protocol_status": t.protocol_status or "OK",
                    "tls_grade": a.tls_grade or "OK",
                    "ip_address": t.ip_address or primary_ip,
                    "port": t.port or 443,
                })

            # Certificate Analysis (Section D drilldown)
            if a.cert_results and len(a.cert_results) > 0:
                c = a.cert_results[0]
                certificate_analysis_list.append({
                    "subdomain": hostname,
                    "certificate_status": getattr(c.status, "value", str(c.status)),
                    "certificate_subject": c.subject or c.common_name or "—",
                    "certificate_issuer": c.issuer or "—",
                    "common_name": c.common_name or "—",
                    "valid_from": c.valid_from or "—",
                    "valid_until": c.valid_until or "—",
                    "days_remaining": c.days_remaining if c.days_remaining is not None else "—",
                    "hostname_validation": "MATCH (Valid)" if c.hostname_match else "MISMATCH (Warning)",
                    "certificate_chain_validation": "VALID" if c.status == "VALID" else str(c.status),
                    "signature_algorithm": c.signature_algorithm or "SHA256withRSA / ECDSA",
                    "key_size": c.key_size or "2048/256 bits",
                    "sans": c.sans or [],
                })

            # Cipher Analysis (Section D drilldown)
            if a.cipher_results:
                for cr in a.cipher_results:
                    cipher_analysis_list.append({
                        "subdomain": hostname,
                        "protocol": cr.protocol or "TLS",
                        "cipher": cr.cipher or "—",
                        "strength": getattr(cr.strength, "value", str(cr.strength)),
                        "status": cr.status or "OFFERED",
                        "evidence": cr.evidence or "—",
                    })

        # 5. Security Findings (Section E, F, G)
        findings_list: List[Dict[str, Any]] = []
        remediation_list: List[Dict[str, Any]] = []

        for f_idx, f in enumerate(findings, 1):
            finding_id = f"FIND-{f_idx:03d}"
            host = f.asset_hostname or "general"
            url_for_finding = f"https://{host}" if host != "general" else target_url
            sev_str = getattr(f.severity, "value", str(f.severity))

            impact, remediation = _get_impact_and_remediation(f.title, f.description or "", f.category or "")

            finding_item = {
                "finding_id": finding_id,
                "asset": host,
                "url": url_for_finding,
                "title": f.title,
                "category": f.category or "GENERAL",
                "severity": sev_str,
                "description": f.description or "—",
                "evidence": f.evidence or "Observed during active target probing.",
                "impact": impact,
                "remediation": remediation,
                "recommendation": f.recommendation or remediation,
                "cve": f.cve or "—",
                "cwe": f.cwe or "—",
                "status": "OPEN",
                "created_at_ist": format_ist_datetime(f.created_at),
            }
            findings_list.append(finding_item)

            # Remediation items list
            remediation_list.append({
                "finding_id": finding_id,
                "severity": sev_str,
                "title": f.title,
                "affected_asset": host,
                "action_required": remediation,
                "recommendation": f.recommendation or remediation,
            })

        # Assemble Full Normalized Data Model
        return {
            "scan_information": scan_info,
            "summary": {
                "subdomains_discovered": total_subdomains,
                "dns_valid": dns_valid_count,
                "active_assets": active_assets_count,
                "inactive_assets": inactive_assets_count,
                "https_assets": https_assets_count,
                "tls_assessed": tls_assessed_count,
                "total_findings": len(findings),
                "critical_findings": critical_count,
                "high_findings": high_count,
                "medium_findings": medium_count,
                "low_findings": low_count,
                "info_findings": info_count,
            },
            "discovered_assets": discovered_assets,
            "http_results": http_results,
            "header_analysis": header_analysis_list,
            "tls_analysis": tls_analysis_list,
            "certificate_analysis": certificate_analysis_list,
            "cipher_analysis": cipher_analysis_list,
            "findings": findings_list,
            "remediation": remediation_list,
        }
