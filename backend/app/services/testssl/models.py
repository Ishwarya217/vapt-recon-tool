from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class CertificateDetails(BaseModel):
    subject: Optional[str] = None
    common_name: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_remaining: Optional[int] = None
    sans: List[str] = Field(default_factory=list)
    hostname_match: bool = True
    status: str = "VALID"  # VALID, EXPIRED, EXPIRING_SOON, INVALID, HOSTNAME_MISMATCH
    signature_algorithm: Optional[str] = None
    key_size: Optional[str] = None


class ProtocolSupport(BaseModel):
    tls1_0: bool = False
    tls1_1: bool = False
    tls1_2: bool = False
    tls1_3: bool = False
    ssl2: bool = False
    ssl3: bool = False
    status: str = "OK"  # OK, WEAK, CRITICAL


class CipherDetails(BaseModel):
    protocol: str
    cipher: str
    strength: str  # STRONG, WEAK, DEPRECATED, PROBLEMATIC
    status: str
    evidence: str


class VulnerabilityFinding(BaseModel):
    id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    finding: str
    cve: Optional[str] = None
    cwe: Optional[str] = None


class TLSAssessmentResult(BaseModel):
    target: str
    ip_address: Optional[str] = None
    port: int = 443
    certificate: Optional[CertificateDetails] = None
    protocols: ProtocolSupport = Field(default_factory=ProtocolSupport)
    ciphers: List[CipherDetails] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    raw_json_output: Optional[str] = None
    execution_time_seconds: float = 0.0
