from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class DiscoveredItem(BaseModel):
    hostname: str
    domain: str
    source: str = "theHarvester"
    source_engine: str = "unknown"
    record_type: str = "hostname"
    ip_address: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    raw_evidence_ref: Optional[str] = None


class DiscoveryBatch(BaseModel):
    domain: str
    items: List[DiscoveredItem] = Field(default_factory=list)
    total_discovered: int = 0
    sources_used: List[str] = Field(default_factory=list)
    raw_json_output: Optional[str] = None
    raw_xml_output: Optional[str] = None
