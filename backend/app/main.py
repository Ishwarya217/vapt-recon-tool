"""FastAPI REST API — scans, assets, findings, system health, SSE events, reports."""
import asyncio
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.database import get_db, init_db
from backend.app.models.models import (
    Asset, AuditLog, CertificateResult, CipherResult,
    Discovery, Finding, HeaderResult, Scan, ScanStatus, TLSResult,
)
from backend.app.schemas.schemas import (
    AssetSchema, DiscoverySchema, FindingSchema,
    ScanCreateRequest, ScanDetail, ScanStats, ScanSummary,
    SystemHealthSchema, ToolStatus,
)
from backend.app.services.orchestration.events import event_bus
from backend.app.services.orchestration.orchestrator import ScanOrchestrator
from backend.app.services.testssl.adapter import TestSSLAdapter
from backend.app.services.theharvester.adapter import TheHarvesterAdapter


# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="VAPT Recon Platform API",
    version="1.0.0",
    description="Security orchestration platform around theHarvester and testssl.sh",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    init_db()


# ─── System Health ────────────────────────────────────────────────────────────

@app.get("/api/v1/system/health", response_model=SystemHealthSchema, tags=["System"])
async def system_health():
    tools = []

    # theHarvester
    try:
        adapter = TheHarvesterAdapter()
        avail = await adapter.check_availability()
        version = await adapter.get_version() if avail else None
        tools.append(ToolStatus(name="theHarvester", available=avail, version=version))
    except Exception as e:
        tools.append(ToolStatus(name="theHarvester", available=False, error=str(e)))

    # testssl.sh
    try:
        adapter2 = TestSSLAdapter()
        avail2 = await adapter2.check_availability()
        version2 = await adapter2.get_version() if avail2 else None
        tools.append(ToolStatus(name="testssl.sh", available=avail2, version=version2))
    except Exception as e:
        tools.append(ToolStatus(name="testssl.sh", available=False, error=str(e)))

    all_ok = all(t.available for t in tools)
    some_ok = any(t.available for t in tools)
    status = "healthy" if all_ok else ("degraded" if some_ok else "unhealthy")

    return SystemHealthSchema(
        status=status,
        scanner_mode=settings.SCANNER_MODE,
        tools=tools,
        database="connected",
    )


# ─── Scans ────────────────────────────────────────────────────────────────────

@app.post("/api/v1/scans", response_model=ScanSummary, status_code=201, tags=["Scans"])
async def create_scan(body: ScanCreateRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    scan = Scan(
        id=str(uuid.uuid4()),
        target_domain=body.target_domain.lower().strip(),
        scope=body.scope,
        mode=body.mode or settings.SCANNER_MODE,
        sources=",".join(body.sources) if body.sources else None,
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    async def run_scan_bg(scan_id: str):
        from backend.app.core.database import SessionLocal
        bg_db = SessionLocal()
        try:
            orchestrator = ScanOrchestrator(bg_db)
            await orchestrator.run_scan(scan_id)
        except Exception as e:
            import traceback
            traceback.print_exc()
        finally:
            bg_db.close()

    background_tasks.add_task(run_scan_bg, scan.id)
    return scan


@app.get("/api/v1/scans", response_model=List[ScanSummary], tags=["Scans"])
def list_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.created_at.desc()).all()


@app.get("/api/v1/scans/{scan_id}", response_model=ScanDetail, tags=["Scans"])
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    stats = ScanStats(
        total_discoveries=db.query(Discovery).filter(Discovery.scan_id == scan_id).count(),
        total_assets=len(assets),
        active_assets=sum(1 for a in assets if a.status == "ACTIVE"),
        dns_valid=sum(1 for a in assets if a.dns_resolved),
        tls_assessed=sum(1 for a in assets if a.tls_assessed),
        total_findings=len(findings),
        critical_findings=sum(1 for f in findings if f.severity == "CRITICAL"),
        high_findings=sum(1 for f in findings if f.severity == "HIGH"),
        medium_findings=sum(1 for f in findings if f.severity == "MEDIUM"),
        low_findings=sum(1 for f in findings if f.severity == "LOW"),
        info_findings=sum(1 for f in findings if f.severity == "INFO"),
    )

    return ScanDetail(
        id=scan.id, target_domain=scan.target_domain, status=scan.status,
        mode=scan.mode, created_at=scan.created_at, started_at=scan.started_at,
        completed_at=scan.completed_at, error_message=scan.error_message,
        theharvester_version=scan.theharvester_version,
        testssl_version=scan.testssl_version,
        stats=stats,
    )


@app.delete("/api/v1/scans/{scan_id}", status_code=204, tags=["Scans"])
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ─── Scan Sub-Resources ───────────────────────────────────────────────────────

@app.get("/api/v1/scans/{scan_id}/discoveries", response_model=List[DiscoverySchema], tags=["Results"])
def get_discoveries(scan_id: str, db: Session = Depends(get_db)):
    return db.query(Discovery).filter(Discovery.scan_id == scan_id).all()


@app.get("/api/v1/scans/{scan_id}/assets", response_model=List[AssetSchema], tags=["Results"])
def get_assets(scan_id: str, db: Session = Depends(get_db)):
    return db.query(Asset).filter(Asset.scan_id == scan_id).all()


@app.get("/api/v1/scans/{scan_id}/findings", response_model=List[FindingSchema], tags=["Results"])
def get_findings(scan_id: str, severity: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity.upper())
    return q.order_by(Finding.severity).all()


# ─── SSE Events ───────────────────────────────────────────────────────────────

@app.get("/api/v1/scans/{scan_id}/events", tags=["Events"])
async def scan_events(scan_id: str):
    async def gen():
        async for chunk in event_bus.stream(scan_id):
            yield chunk

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


# ─── Reports ─────────────────────────────────────────────────────────────────

@app.post("/api/v1/scans/{scan_id}/reports/json", tags=["Reports"])
@app.get("/api/v1/scans/{scan_id}/reports/json", tags=["Reports"])
def generate_json(scan_id: str, db: Session = Depends(get_db)):
    from backend.app.services.reports.json_report import generate_json_report_bytes
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    json_bytes = generate_json_report_bytes(scan, db)
    fname = f"vapt_report_{scan.target_domain}_{scan_id[:8]}.json"
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


@app.post("/api/v1/scans/{scan_id}/reports/pdf", tags=["Reports"])
@app.get("/api/v1/scans/{scan_id}/reports/pdf", tags=["Reports"])
def generate_pdf(scan_id: str, db: Session = Depends(get_db)):
    from backend.app.services.reports.pdf_report import generate_pdf_report
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    pdf_bytes = generate_pdf_report(scan, db)
    fname = f"vapt_report_{scan.target_domain}_{scan_id[:8]}.pdf"
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.post("/api/v1/scans/{scan_id}/reports/excel", tags=["Reports"])
@app.get("/api/v1/scans/{scan_id}/reports/excel", tags=["Reports"])
def generate_excel(scan_id: str, db: Session = Depends(get_db)):
    from backend.app.services.reports.excel_report import generate_excel_report
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    excel_bytes = generate_excel_report(scan, db)
    fname = f"vapt_report_{scan.target_domain}_{scan_id[:8]}.xlsx"
    return Response(content=excel_bytes, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.post("/api/v1/scans/{scan_id}/reports/xml", tags=["Reports"])
@app.get("/api/v1/scans/{scan_id}/reports/xml", tags=["Reports"])
def generate_xml(scan_id: str, db: Session = Depends(get_db)):
    from backend.app.services.reports.xml_report import generate_xml_report
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    xml_bytes = generate_xml_report(scan, db)
    fname = f"vapt_report_{scan.target_domain}_{scan_id[:8]}.xml"
    return Response(content=xml_bytes, media_type="application/xml", headers={"Content-Disposition": f"attachment; filename={fname}"})



# ─── Dashboard Stats ──────────────────────────────────────────────────────────

@app.get("/api/v1/dashboard/stats", tags=["Dashboard"])
def dashboard_stats(db: Session = Depends(get_db)):
    scans = db.query(Scan).all()
    findings = db.query(Finding).all()
    assets = db.query(Asset).all()
    return {
        "total_scans": len(scans),
        "completed_scans": sum(1 for s in scans if s.status == "COMPLETED"),
        "active_assets": sum(1 for a in assets if a.status == "ACTIVE"),
        "total_findings": len(findings),
        "critical_findings": sum(1 for f in findings if f.severity == "CRITICAL"),
        "high_findings": sum(1 for f in findings if f.severity == "HIGH"),
        "medium_findings": sum(1 for f in findings if f.severity == "MEDIUM"),
        "low_findings": sum(1 for f in findings if f.severity == "LOW"),
        "scanner_mode": settings.SCANNER_MODE,
    }


if __name__ == "__main__":
    import sys
    import uvicorn
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
