import asyncio
import time
from typing import Dict, List, Optional
import dns.asyncresolver
from pydantic import BaseModel, Field


class DNSValidationResult(BaseModel):
    hostname: str
    resolved: bool = False
    status: str = "DNS_UNRESOLVED"
    ipv4_addresses: List[str] = Field(default_factory=list)
    ipv6_addresses: List[str] = Field(default_factory=list)
    cname_records: List[str] = Field(default_factory=list)
    resolution_time_ms: float = 0.0
    error: Optional[str] = None


class DNSValidator:
    """Asynchronous DNS resolver using dnspython."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def resolve_hostname(self, hostname: str) -> DNSValidationResult:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        start_time = time.time()
        ipv4_list: List[str] = []
        ipv6_list: List[str] = []
        cname_list: List[str] = []
        err_msg: Optional[str] = None

        # Resolve A records
        try:
            answers_a = await resolver.resolve(hostname, "A")
            for rdata in answers_a:
                ipv4_list.append(rdata.to_text())
        except Exception as e:
            err_msg = str(e)

        # Resolve AAAA records
        try:
            answers_aaaa = await resolver.resolve(hostname, "AAAA")
            for rdata in answers_aaaa:
                ipv6_list.append(rdata.to_text())
        except Exception:
            pass

        # Resolve CNAME records if appropriate
        try:
            answers_cname = await resolver.resolve(hostname, "CNAME")
            for rdata in answers_cname:
                cname_list.append(rdata.to_text().rstrip("."))
        except Exception:
            pass

        duration_ms = (time.time() - start_time) * 1000.0
        resolved = bool(ipv4_list or ipv6_list)
        status = "DNS_VALID" if resolved else "DNS_UNRESOLVED"

        return DNSValidationResult(
            hostname=hostname,
            resolved=resolved,
            status=status,
            ipv4_addresses=ipv4_list,
            ipv6_addresses=ipv6_list,
            cname_records=cname_list,
            resolution_time_ms=round(duration_ms, 2),
            error=err_msg if not resolved else None,
        )

    async def resolve_batch(self, hostnames: List[str]) -> List[DNSValidationResult]:
        tasks = [self.resolve_hostname(h) for h in hostnames]
        return await asyncio.gather(*tasks)
