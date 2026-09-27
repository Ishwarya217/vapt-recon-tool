"""
Main Scan Orchestrator — coordinates the 13-stage scan state machine.
QUEUED → TARGET_VALIDATION → THEHARVESTER_RUNNING → DISCOVERY_PARSING →
SUBDOMAIN_VALIDATION → DNS_VALIDATION → HTTP_PROBING → ACTIVE_ASSETS_IDENTIFIED →
TESTSSL_RUNNING → HEADER_ANALYSIS → RESULT_PROCESSING → REPORT_GENERATION → COMPLETED / FAILED
"""
import asyncio
import os
import tempfile
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.models import (
    Asset, AssetStatus, AuditLog, CertificateResult, CipherResult,
    CipherStrength, Discovery, Finding, FindingSeverity, HeaderResult,
    Scan, ScanStatus, TLSResult, ToolExecution,
)
from backend.app.services.common.runner import ToolExecutionResult
from backend.app.services.findings.findings_engine import FindingsEngine
from backend.app.services.orchestration.events import event_bus
from backend.app.services.testssl.adapter import TestSSLAdapter
from backend.app.services.theharvester.adapter import TheHarvesterAdapter
from backend.app.services.validation.dns_validator import DNSValidator
from backend.app.services.validation.header_analyzer import HeaderAnalyzer
from backend.app.services.validation.http_prober import HTTPProber
from backend.app.services.validation.scope_validator import ScopeValidator


class ScanOrchestrator:
    def __init__(self, db: Session):
        self.db = db
        self.harvester_adapter = TheHarvesterAdapter()
        self.testssl_adapter = TestSSLAdapter()
        self.scope_validator = ScopeValidator()
        self.dns_validator = DNSValidator()
        self.http_prober = HTTPProber()
        self.header_analyzer = HeaderAnalyzer()

    def _log_audit(self, scan_id: str, event_type: str, message: str, data: dict = None):
        log = AuditLog(scan_id=scan_id, event_type=event_type, message=message, data=data)
        self.db.add(log)
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()

    async def _emit(self, scan_id: str, event_type: str, message: str, phase: str = None, data: dict = None):
        payload_data = dict(data or {})
        if phase and "phase" not in payload_data:
            payload_data["phase"] = phase
        await event_bus.publish(scan_id, event_type, message, phase, payload_data)
        self._log_audit(scan_id, event_type, message, payload_data)

    def _update_scan_status(self, scan: Scan, status: ScanStatus, error: str = None):
        scan.status = status
        if status == ScanStatus.FAILED:
            scan.error_message = error
        if status == ScanStatus.COMPLETED:
            scan.completed_at = datetime.utcnow()
        self.db.commit()

    async def run_scan(self, scan_id: str):
        """Main entry point: runs the full scan pipeline for a given scan_id."""
        scan: Scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        work_dir = tempfile.mkdtemp(prefix=f"vapt_{scan_id[:8]}_")

        try:
            scan.started_at = datetime.utcnow()
            self.db.commit()

            # ── Phase 1: TARGET VALIDATION ─────────────────────────────────
            self._update_scan_status(scan, ScanStatus.TARGET_VALIDATION)
            await self._emit(scan_id, "phase_change", f"Validating target: {scan.target_domain}", phase="TARGET_VALIDATION")

            domain = scan.target_domain.lower().strip()
            if not self.scope_validator.is_valid_domain(domain):
                raise ValueError(f"Invalid or disallowed target domain: {domain}")

            # ── Phase 2: THEHARVESTER RUNNING ──────────────────────────────
            self._update_scan_status(scan, ScanStatus.THEHARVESTER_RUNNING)
            await self._emit(scan_id, "phase_change", f"Running theHarvester on {domain}...", phase="THEHARVESTER_RUNNING")

            sources = scan.sources.split(",") if scan.sources else None

            if scan.mode == "mock":
                # Use mock data for testing
                from backend.app.services.orchestration.mock_data import generate_mock_batch
                batch = generate_mock_batch(domain)
                harvest_exec = None
            else:
                batch, harvest_exec = await self.harvester_adapter.discover(
                    domain=domain, sources=sources, work_dir=work_dir
                )

            if harvest_exec:
                scan.theharvester_version = await self.harvester_adapter.get_version()
                te = ToolExecution(
                    scan_id=scan_id, tool_name="theHarvester",
                    tool_version=scan.theharvester_version,
                    command=" ".join(harvest_exec.command),
                    exit_code=harvest_exec.exit_code,
                    duration_seconds=harvest_exec.duration_seconds,
                    timed_out=harvest_exec.timed_out,
                    started_at=scan.started_at,
                    completed_at=datetime.utcnow(),
                )
                self.db.add(te)
                self._log_audit(scan_id, "theharvester_exec", f"Exit: {harvest_exec.exit_code}, Stderr: {harvest_exec.stderr[:500]}", {"exit_code": harvest_exec.exit_code, "stderr": harvest_exec.stderr, "duration": harvest_exec.duration_seconds})
                self.db.commit()

                if harvest_exec.timed_out:
                    await self._emit(scan_id, "warning", f"theHarvester timed out after {harvest_exec.duration_seconds:.1f}s", phase="THEHARVESTER_RUNNING")
                elif harvest_exec.exit_code != 0 and len(batch.items) == 0:
                    err_msg = harvest_exec.stderr.strip() or f"Process exited with code {harvest_exec.exit_code}"
                    await self._emit(scan_id, "warning", f"theHarvester issue: {err_msg[:200]}", phase="THEHARVESTER_RUNNING")

            # ── Phase 3: DISCOVERY PARSING ─────────────────────────────────
            self._update_scan_status(scan, ScanStatus.DISCOVERY_PARSING)
            await self._emit(scan_id, "phase_change", f"Parsed {len(batch.items)} candidate hostnames", phase="DISCOVERY_PARSING", data={"count": len(batch.items)})

            if len(batch.items) == 0:
                await self._emit(scan_id, "discovery", f"No candidate hostnames discovered for {domain} across selected sources", phase="DISCOVERY_PARSING", data={"count": 0})

            for item in batch.items:
                d = Discovery(
                    scan_id=scan_id, hostname=item.hostname, domain=item.domain,
                    source=item.source, source_engine=item.source_engine,
                    record_type=item.record_type, ip_address=item.ip_address,
                )
                self.db.add(d)
            self.db.commit()

            # ── Phase 4: SUBDOMAIN VALIDATION ─────────────────────────────
            self._update_scan_status(scan, ScanStatus.SUBDOMAIN_VALIDATION)
            await self._emit(scan_id, "phase_change", "Validating subdomain scope...", phase="SUBDOMAIN_VALIDATION")

            unique_hostnames = {}
            for item in batch.items:
                hn = item.hostname.lower().strip()
                if hn not in unique_hostnames:
                    if self.scope_validator.is_in_scope(hn, domain):
                        unique_hostnames[hn] = item
                    else:
                        await self._emit(scan_id, "discovery", f"Out-of-scope: {hn}", data={"hostname": hn, "status": "OUT_OF_SCOPE"})

            await self._emit(scan_id, "phase_change", f"{len(unique_hostnames)} in-scope hostnames", phase="SUBDOMAIN_VALIDATION", data={"count": len(unique_hostnames)})

            # ── Phase 5: DNS VALIDATION ────────────────────────────────────
            self._update_scan_status(scan, ScanStatus.DNS_VALIDATION)
            await self._emit(scan_id, "phase_change", "Resolving DNS for discovered hostnames...", phase="DNS_VALIDATION")

            assets: List[Asset] = []
            dns_tasks = []
            hostname_list = list(unique_hostnames.keys())

            async def resolve_one(hn: str, source: str):
                dns_result = await self.dns_validator.resolve_hostname(hn)
                asset = Asset(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    hostname=hn,
                    source=source,
                    status=AssetStatus.DISCOVERED,
                    dns_resolved=dns_result.resolved,
                    ip_addresses=dns_result.ipv4_addresses + dns_result.ipv6_addresses,
                    cname=(dns_result.cname_records[0] if dns_result.cname_records else None),
                    dns_resolution_time_ms=dns_result.resolution_time_ms,
                )
                if dns_result.resolved:
                    asset.status = AssetStatus.DNS_VALID
                    await self._emit(scan_id, "discovery", f"DNS resolved: {hn} → {dns_result.ipv4_addresses}", data={"hostname": hn, "ips": dns_result.ipv4_addresses})
                else:
                    asset.status = AssetStatus.INACTIVE
                return asset

            sem = asyncio.Semaphore(20)

            async def resolve_with_sem(hn: str, source: str):
                async with sem:
                    return await resolve_one(hn, source)

            results = await asyncio.gather(*[resolve_with_sem(hn, unique_hostnames[hn].source) for hn in hostname_list], return_exceptions=True)
            for r in results:
                if isinstance(r, Asset):
                    assets.append(r)
                    self.db.add(r)
            self.db.commit()

            dns_valid = [a for a in assets if a.status == AssetStatus.DNS_VALID]
            await self._emit(scan_id, "phase_change", f"DNS validation complete: {len(dns_valid)}/{len(assets)} resolved", phase="DNS_VALIDATION", data={"resolved": len(dns_valid), "total": len(assets)})

            # ── Phase 6: HTTP PROBING ──────────────────────────────────────
            self._update_scan_status(scan, ScanStatus.HTTP_PROBING)
            await self._emit(scan_id, "phase_change", "HTTP/HTTPS probing active assets...", phase="HTTP_PROBING")

            probe_sem = asyncio.Semaphore(10)

            async def probe_one(asset: Asset):
                async with probe_sem:
                    try:
                        probe = await self.http_prober.probe_hostname(asset.hostname)
                        http_p = probe.http_probe
                        https_p = probe.https_probe
                        asset.http_status_code = http_p.status_code if http_p else None
                        asset.https_status_code = https_p.status_code if https_p else None
                        asset.http_response_time_ms = http_p.response_time_ms if http_p else None
                        asset.https_response_time_ms = https_p.response_time_ms if https_p else None
                        asset.server_header = (https_p.server_header if https_p else None) or (http_p.server_header if http_p else None)
                        asset.http_redirect_url = (http_p.redirect_url if http_p else None)

                        if probe.classification == "ACTIVE":
                            asset.status = AssetStatus.ACTIVE
                        elif asset.dns_resolved:
                            asset.status = AssetStatus.DNS_ONLY
                        else:
                            asset.status = AssetStatus.INACTIVE
                    except Exception as e:
                        asset.status = AssetStatus.HTTP_ERROR

            await asyncio.gather(*[probe_one(a) for a in dns_valid], return_exceptions=True)
            self.db.commit()

            active_assets = [a for a in assets if a.status == AssetStatus.ACTIVE]
            await self._emit(scan_id, "phase_change", f"HTTP probing complete: {len(active_assets)} ACTIVE assets", phase="ACTIVE_ASSETS_IDENTIFIED", data={"active": len(active_assets)})

            # ── Phase 7: TESTSSL RUNNING ───────────────────────────────────
            self._update_scan_status(scan, ScanStatus.TESTSSL_RUNNING)
            https_assets = [a for a in active_assets if a.https_status_code is not None]
            await self._emit(scan_id, "phase_change", f"Running TLS assessment on {len(https_assets)} HTTPS assets...", phase="TESTSSL_RUNNING", data={"count": len(https_assets)})

            testssl_sem = asyncio.Semaphore(10)

            async def assess_tls(asset_id: str, hostname: str):
                from backend.app.core.database import SessionLocal
                async with testssl_sem:
                    try:
                        await self._emit(scan_id, "phase_change", f"TLS scan: {hostname}", phase="TESTSSL_RUNNING", data={"hostname": hostname})

                        if scan.mode == "mock":
                            from backend.app.services.orchestration.mock_data import generate_mock_tls
                            tls_data = generate_mock_tls(hostname)
                        else:
                            tls_data, tls_exec = await self.testssl_adapter.assess_target(hostname, work_dir=work_dir)
                            if not scan.testssl_version:
                                scan.testssl_version = await self.testssl_adapter.get_version()

                        # Persist within a short-lived DB transaction
                        task_db = SessionLocal()
                        try:
                            ast = task_db.query(Asset).filter(Asset.id == asset_id).first()
                            if ast:
                                tls_orm = TLSResult(
                                    asset_id=ast.id,
                                    tls1_0_enabled=tls_data.protocols.tls1_0,
                                    tls1_1_enabled=tls_data.protocols.tls1_1,
                                    tls1_2_enabled=tls_data.protocols.tls1_2,
                                    tls1_3_enabled=tls_data.protocols.tls1_3,
                                    ssl2_enabled=tls_data.protocols.ssl2,
                                    ssl3_enabled=tls_data.protocols.ssl3,
                                    protocol_status=tls_data.protocols.status,
                                    ip_address=tls_data.ip_address,
                                    port=tls_data.port,
                                    execution_time_seconds=tls_data.execution_time_seconds,
                                )
                                task_db.add(tls_orm)

                                if tls_data.certificate:
                                    cert = tls_data.certificate
                                    cert_orm = CertificateResult(
                                        asset_id=ast.id,
                                        subject=cert.subject,
                                        common_name=cert.common_name,
                                        issuer=cert.issuer,
                                        valid_from=cert.valid_from,
                                        valid_until=cert.valid_until,
                                        days_remaining=cert.days_remaining,
                                        sans=cert.sans,
                                        hostname_match=cert.hostname_match,
                                        status=cert.status,
                                        signature_algorithm=cert.signature_algorithm,
                                        key_size=cert.key_size,
                                    )
                                    task_db.add(cert_orm)

                                    for f in FindingsEngine.analyze_certificate(ast.hostname, cert_orm):
                                        task_db.add(Finding(scan_id=scan_id, asset_hostname=f.asset_hostname, category=f.category, severity=f.severity, title=f.title, description=f.description, evidence=f.evidence, recommendation=f.recommendation, cve=f.cve, cwe=f.cwe))

                                for cipher in tls_data.ciphers:
                                    task_db.add(CipherResult(
                                        asset_id=ast.id,
                                        protocol=cipher.protocol,
                                        cipher=cipher.cipher,
                                        strength=cipher.strength,
                                        status=cipher.status,
                                        evidence=cipher.evidence,
                                    ))

                                for f in FindingsEngine.analyze_tls(ast.hostname, tls_orm):
                                    task_db.add(Finding(scan_id=scan_id, asset_hostname=f.asset_hostname, category=f.category, severity=f.severity, title=f.title, description=f.description, evidence=f.evidence, recommendation=f.recommendation, cve=f.cve, cwe=f.cwe))
                                for f in FindingsEngine.analyze_ciphers(ast.hostname, tls_data.ciphers):
                                    task_db.add(Finding(scan_id=scan_id, asset_hostname=f.asset_hostname, category=f.category, severity=f.severity, title=f.title, description=f.description, evidence=f.evidence, recommendation=f.recommendation, cve=f.cve, cwe=f.cwe))

                                ast.tls_assessed = True
                                ast.tls_grade = tls_data.protocols.status
                                task_db.commit()
                        finally:
                            task_db.close()

                    except Exception as e:
                        await self._emit(scan_id, "error", f"TLS scan failed for {hostname}: {str(e)}")

            await asyncio.gather(*[assess_tls(a.id, a.hostname) for a in https_assets], return_exceptions=True)


            # ── Phase 8: HEADER ANALYSIS ───────────────────────────────────
            self._update_scan_status(scan, ScanStatus.HEADER_ANALYSIS)
            await self._emit(scan_id, "phase_change", "Analyzing HTTP security headers...", phase="HEADER_ANALYSIS")

            for asset in active_assets:
                try:
                    # Fetch headers via HTTPS probe
                    target_url = f"https://{asset.hostname}"
                    import httpx
                    raw_hdrs = {}
                    try:
                        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                            resp = await client.get(target_url, follow_redirects=True)
                            raw_hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    except Exception:
                        try:
                            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                                resp = await client.get(f"http://{asset.hostname}", follow_redirects=True)
                                raw_hdrs = {k.lower(): v for k, v in resp.headers.items()}
                        except Exception:
                            pass

                    analysis = self.header_analyzer.analyze_headers(asset.hostname, target_url, raw_hdrs)
                    score = 0

                    # Convert HeaderEvaluation → HeaderResult ORM + extract presence
                    class _HRProxy:
                        def __init__(self, e): self.header_name = e.header_name; self.present = e.status == "PRESENT"

                    hr_proxies = [_HRProxy(e) for e in analysis.evaluations]

                    for ev in analysis.evaluations:
                        orm_hr = HeaderResult(
                            asset_id=asset.id,
                            header_name=ev.header_name,
                            header_value=ev.value,
                            present=(ev.status == "PRESENT"),
                            severity=ev.severity,
                            recommendation=ev.recommendation,
                        )
                        self.db.add(orm_hr)
                        if ev.status == "PRESENT":
                            score += 16

                    asset.security_headers_score = min(score, 100)
                    asset.has_hsts = any(e.header_name == "Strict-Transport-Security" and e.status == "PRESENT" for e in analysis.evaluations)
                    asset.has_csp = any(e.header_name == "Content-Security-Policy" and e.status == "PRESENT" for e in analysis.evaluations)
                    asset.has_xfo = any(e.header_name == "X-Frame-Options" and e.status == "PRESENT" for e in analysis.evaluations)
                    asset.has_xcto = any(e.header_name == "X-Content-Type-Options" and e.status == "PRESENT" for e in analysis.evaluations)
                    asset.has_referrer_policy = any(e.header_name == "Referrer-Policy" and e.status == "PRESENT" for e in analysis.evaluations)
                    asset.has_permissions_policy = any(e.header_name == "Permissions-Policy" and e.status == "PRESENT" for e in analysis.evaluations)

                    # Header findings
                    for f in FindingsEngine.analyze_headers(asset.hostname, hr_proxies):
                        self.db.add(Finding(scan_id=scan_id, asset_hostname=f.asset_hostname, category=f.category, severity=f.severity, title=f.title, description=f.description, evidence=f.evidence, recommendation=f.recommendation, cve=f.cve, cwe=f.cwe))

                except Exception:
                    pass

            self.db.commit()

            # ── Phase 9: RESULT PROCESSING ─────────────────────────────────
            self._update_scan_status(scan, ScanStatus.RESULT_PROCESSING)
            await self._emit(scan_id, "phase_change", "Processing results...", phase="RESULT_PROCESSING")

            # ── Phase 10: COMPLETED ────────────────────────────────────────
            self._update_scan_status(scan, ScanStatus.COMPLETED)
            scan.completed_at = datetime.utcnow()
            self.db.commit()

            findings_count = self.db.query(Finding).filter(Finding.scan_id == scan_id).count()
            await self._emit(scan_id, "completed", f"Scan complete! {len(active_assets)} active assets, {findings_count} findings.", phase="COMPLETED", data={
                "active_assets": len(active_assets),
                "findings": findings_count,
                "total_discoveries": len(batch.items),
            })

        except Exception as e:
            self._update_scan_status(scan, ScanStatus.FAILED, error=str(e))
            await self._emit(scan_id, "failed", f"Scan failed: {str(e)}", phase="FAILED")
        finally:
            # Cleanup work dir
            import shutil
            try:
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception:
                pass
