import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


def _uuid():
    return str(uuid.uuid4())


# ─── Enums ────────────────────────────────────────────────────────────────────

class ScanStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    TARGET_VALIDATION = "TARGET_VALIDATION"
    THEHARVESTER_RUNNING = "THEHARVESTER_RUNNING"
    DISCOVERY_PARSING = "DISCOVERY_PARSING"
    SUBDOMAIN_VALIDATION = "SUBDOMAIN_VALIDATION"
    DNS_VALIDATION = "DNS_VALIDATION"
    HTTP_PROBING = "HTTP_PROBING"
    ACTIVE_ASSETS_IDENTIFIED = "ACTIVE_ASSETS_IDENTIFIED"
    TESTSSL_RUNNING = "TESTSSL_RUNNING"
    HEADER_ANALYSIS = "HEADER_ANALYSIS"
    RESULT_PROCESSING = "RESULT_PROCESSING"
    REPORT_GENERATION = "REPORT_GENERATION"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AssetStatus(str, enum.Enum):
    DISCOVERED = "DISCOVERED"
    DNS_VALID = "DNS_VALID"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    DNS_ONLY = "DNS_ONLY"
    HTTP_ERROR = "HTTP_ERROR"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CertStatus(str, enum.Enum):
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    EXPIRING_SOON = "EXPIRING_SOON"
    INVALID = "INVALID"
    HOSTNAME_MISMATCH = "HOSTNAME_MISMATCH"


class CipherStrength(str, enum.Enum):
    STRONG = "STRONG"
    WEAK = "WEAK"
    DEPRECATED = "DEPRECATED"
    PROBLEMATIC = "PROBLEMATIC"


# ─── Models ───────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=_uuid)
    target_domain = Column(String, nullable=False, index=True)
    scope = Column(String, nullable=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.QUEUED, nullable=False)
    mode = Column(String, default="real")  # "real" or "mock"
    sources = Column(String, nullable=True)  # comma-separated
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    theharvester_version = Column(String, nullable=True)
    testssl_version = Column(String, nullable=True)

    discoveries = relationship("Discovery", back_populates="scan", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    tool_executions = relationship("ToolExecution", back_populates="scan", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="scan", cascade="all, delete-orphan")


class Discovery(Base):
    __tablename__ = "discoveries"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    hostname = Column(String, nullable=False)
    domain = Column(String, nullable=False)
    source = Column(String, default="theHarvester")
    source_engine = Column(String, nullable=True)
    record_type = Column(String, default="hostname")
    ip_address = Column(String, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="discoveries")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    hostname = Column(String, nullable=False, index=True)
    source = Column(String, nullable=True)
    status = Column(Enum(AssetStatus), default=AssetStatus.DISCOVERED)

    # DNS
    dns_resolved = Column(Boolean, default=False)
    ip_addresses = Column(JSON, default=list)  # list of IPs
    cname = Column(String, nullable=True)
    dns_resolution_time_ms = Column(Float, nullable=True)

    # HTTP
    http_status_code = Column(Integer, nullable=True)
    https_status_code = Column(Integer, nullable=True)
    http_response_time_ms = Column(Float, nullable=True)
    https_response_time_ms = Column(Float, nullable=True)
    server_header = Column(String, nullable=True)
    http_redirect_url = Column(String, nullable=True)

    # Security headers
    has_hsts = Column(Boolean, nullable=True)
    has_csp = Column(Boolean, nullable=True)
    has_xfo = Column(Boolean, nullable=True)
    has_xcto = Column(Boolean, nullable=True)
    has_referrer_policy = Column(Boolean, nullable=True)
    has_permissions_policy = Column(Boolean, nullable=True)
    security_headers_score = Column(Integer, nullable=True)  # 0-100

    # TLS
    tls_assessed = Column(Boolean, default=False)
    tls_grade = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="assets")
    tls_results = relationship("TLSResult", back_populates="asset", cascade="all, delete-orphan")
    cert_results = relationship("CertificateResult", back_populates="asset", cascade="all, delete-orphan")
    cipher_results = relationship("CipherResult", back_populates="asset", cascade="all, delete-orphan")
    header_results = relationship("HeaderResult", back_populates="asset", cascade="all, delete-orphan")


class TLSResult(Base):
    __tablename__ = "tls_results"

    id = Column(String, primary_key=True, default=_uuid)
    asset_id = Column(String, ForeignKey("assets.id"), nullable=False, index=True)
    tls1_0_enabled = Column(Boolean, default=False)
    tls1_1_enabled = Column(Boolean, default=False)
    tls1_2_enabled = Column(Boolean, default=False)
    tls1_3_enabled = Column(Boolean, default=False)
    ssl2_enabled = Column(Boolean, default=False)
    ssl3_enabled = Column(Boolean, default=False)
    protocol_status = Column(String, default="OK")  # OK, WEAK, CRITICAL
    ip_address = Column(String, nullable=True)
    port = Column(Integer, default=443)
    execution_time_seconds = Column(Float, nullable=True)

    asset = relationship("Asset", back_populates="tls_results")


class CertificateResult(Base):
    __tablename__ = "certificate_results"

    id = Column(String, primary_key=True, default=_uuid)
    asset_id = Column(String, ForeignKey("assets.id"), nullable=False, index=True)
    subject = Column(String, nullable=True)
    common_name = Column(String, nullable=True)
    issuer = Column(String, nullable=True)
    serial_number = Column(String, nullable=True)
    valid_from = Column(String, nullable=True)
    valid_until = Column(String, nullable=True)
    days_remaining = Column(Integer, nullable=True)
    sans = Column(JSON, default=list)
    hostname_match = Column(Boolean, default=True)
    status = Column(Enum(CertStatus), default=CertStatus.VALID)
    signature_algorithm = Column(String, nullable=True)
    key_size = Column(String, nullable=True)

    asset = relationship("Asset", back_populates="cert_results")


class CipherResult(Base):
    __tablename__ = "cipher_results"

    id = Column(String, primary_key=True, default=_uuid)
    asset_id = Column(String, ForeignKey("assets.id"), nullable=False, index=True)
    protocol = Column(String, nullable=False)
    cipher = Column(String, nullable=False)
    strength = Column(Enum(CipherStrength), default=CipherStrength.STRONG)
    status = Column(String, nullable=True)
    evidence = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="cipher_results")


class HeaderResult(Base):
    __tablename__ = "header_results"

    id = Column(String, primary_key=True, default=_uuid)
    asset_id = Column(String, ForeignKey("assets.id"), nullable=False, index=True)
    header_name = Column(String, nullable=False)
    header_value = Column(Text, nullable=True)
    present = Column(Boolean, default=False)
    severity = Column(Enum(FindingSeverity), nullable=True)
    recommendation = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="header_results")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    asset_hostname = Column(String, nullable=True)
    category = Column(String, nullable=True)  # TLS, HEADER, CERT, CONFIG
    severity = Column(Enum(FindingSeverity), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    cve = Column(String, nullable=True)
    cwe = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")


class ToolExecution(Base):
    __tablename__ = "tool_executions"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    tool_name = Column(String, nullable=False)
    tool_version = Column(String, nullable=True)
    command = Column(Text, nullable=True)
    exit_code = Column(Integer, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    timed_out = Column(Boolean, default=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="tool_executions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True, index=True)
    event_type = Column(String, nullable=False)
    message = Column(Text, nullable=True)
    data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="audit_logs")
