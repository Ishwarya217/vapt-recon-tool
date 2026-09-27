from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ─── Scan Schemas ─────────────────────────────────────────────────────────────

class ScanCreateRequest(BaseModel):
    target_domain: str
    scope: Optional[str] = None
    sources: Optional[List[str]] = None
    mode: str = "real"


class ScanSummary(BaseModel):
    id: str
    target_domain: str
    status: str
    mode: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    theharvester_version: Optional[str] = None
    testssl_version: Optional[str] = None

    class Config:
        from_attributes = True


class ScanStats(BaseModel):
    total_discoveries: int = 0
    total_assets: int = 0
    active_assets: int = 0
    dns_valid: int = 0
    tls_assessed: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0


class ScanDetail(ScanSummary):
    stats: ScanStats = Field(default_factory=ScanStats)


# ─── Discovery Schemas ────────────────────────────────────────────────────────

class DiscoverySchema(BaseModel):
    id: str
    scan_id: str
    hostname: str
    domain: str
    source: str
    source_engine: Optional[str] = None
    record_type: str
    ip_address: Optional[str] = None
    discovered_at: datetime

    class Config:
        from_attributes = True


# ─── Asset Schemas ─────────────────────────────────────────────────────────────

class HeaderResultSchema(BaseModel):
    header_name: str
    header_value: Optional[str] = None
    present: bool
    severity: Optional[str] = None
    recommendation: Optional[str] = None

    class Config:
        from_attributes = True


class TLSResultSchema(BaseModel):
    tls1_0_enabled: bool
    tls1_1_enabled: bool
    tls1_2_enabled: bool
    tls1_3_enabled: bool
    ssl2_enabled: bool
    ssl3_enabled: bool
    protocol_status: str
    ip_address: Optional[str] = None
    port: int
    execution_time_seconds: Optional[float] = None

    class Config:
        from_attributes = True


class CertificateResultSchema(BaseModel):
    subject: Optional[str] = None
    common_name: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_remaining: Optional[int] = None
    sans: List[str] = []
    hostname_match: bool
    status: str
    signature_algorithm: Optional[str] = None
    key_size: Optional[str] = None

    class Config:
        from_attributes = True


class CipherResultSchema(BaseModel):
    protocol: str
    cipher: str
    strength: str
    status: Optional[str] = None
    evidence: Optional[str] = None

    class Config:
        from_attributes = True


class AssetSchema(BaseModel):
    id: str
    scan_id: str
    hostname: str
    source: Optional[str] = None
    status: str
    dns_resolved: bool
    ip_addresses: List[str] = []
    cname: Optional[str] = None
    dns_resolution_time_ms: Optional[float] = None
    http_status_code: Optional[int] = None
    https_status_code: Optional[int] = None
    http_response_time_ms: Optional[float] = None
    https_response_time_ms: Optional[float] = None
    server_header: Optional[str] = None
    http_redirect_url: Optional[str] = None
    has_hsts: Optional[bool] = None
    has_csp: Optional[bool] = None
    has_xfo: Optional[bool] = None
    has_xcto: Optional[bool] = None
    has_referrer_policy: Optional[bool] = None
    has_permissions_policy: Optional[bool] = None
    security_headers_score: Optional[int] = None
    tls_assessed: bool
    tls_grade: Optional[str] = None
    created_at: datetime
    tls_results: List[TLSResultSchema] = []
    cert_results: List[CertificateResultSchema] = []
    cipher_results: List[CipherResultSchema] = []
    header_results: List[HeaderResultSchema] = []

    class Config:
        from_attributes = True


# ─── Finding Schemas ──────────────────────────────────────────────────────────

class FindingSchema(BaseModel):
    id: str
    scan_id: str
    asset_hostname: Optional[str] = None
    category: Optional[str] = None
    severity: str
    title: str
    description: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ─── System Health Schemas ────────────────────────────────────────────────────

class ToolStatus(BaseModel):
    name: str
    available: bool
    version: Optional[str] = None
    error: Optional[str] = None


class SystemHealthSchema(BaseModel):
    status: str  # "healthy", "degraded", "unhealthy"
    scanner_mode: str
    tools: List[ToolStatus]
    database: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ─── SSE Event Schema ─────────────────────────────────────────────────────────

class ScanEvent(BaseModel):
    scan_id: str
    event_type: str  # phase_change, discovery, asset_update, finding, completed, error
    phase: Optional[str] = None
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
