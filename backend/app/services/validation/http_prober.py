import asyncio
import time
from typing import Dict, List, Optional
import httpx
from pydantic import BaseModel, Field


class HTTPProbeSingle(BaseModel):
    url: str
    scheme: str  # "http" or "https"
    reachable: bool = False
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    redirect_url: Optional[str] = None
    content_type: Optional[str] = None
    server_header: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    connection_error: Optional[str] = None


class HTTPProbeResult(BaseModel):
    hostname: str
    http_probe: Optional[HTTPProbeSingle] = None
    https_probe: Optional[HTTPProbeSingle] = None
    classification: str = "INACTIVE"  # ACTIVE, INACTIVE, DNS_ONLY, HTTP_ERROR
    primary_url: Optional[str] = None
    primary_scheme: Optional[str] = None


class HTTPProber:
    """Probes HTTP and HTTPS endpoints for discovered hostnames and classifies active assets."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def _probe_url(self, client: httpx.AsyncClient, url: str) -> HTTPProbeSingle:
        scheme = "https" if url.startswith("https://") else "http"
        start = time.time()

        try:
            response = await client.get(
                url,
                timeout=self.timeout,
                follow_redirects=False,
            )
            duration_ms = (time.time() - start) * 1000.0
            resp_headers = {k.lower(): v for k, v in response.headers.items()}

            return HTTPProbeSingle(
                url=url,
                scheme=scheme,
                reachable=True,
                status_code=response.status_code,
                response_time_ms=round(duration_ms, 2),
                redirect_url=resp_headers.get("location"),
                content_type=resp_headers.get("content-type"),
                server_header=resp_headers.get("server"),
                headers=resp_headers,
                connection_error=None,
            )
        except httpx.HTTPStatusError as e:
            duration_ms = (time.time() - start) * 1000.0
            resp_headers = {k.lower(): v for k, v in e.response.headers.items()} if e.response else {}
            return HTTPProbeSingle(
                url=url,
                scheme=scheme,
                reachable=True,
                status_code=e.response.status_code if e.response else None,
                response_time_ms=round(duration_ms, 2),
                headers=resp_headers,
                connection_error=str(e),
            )
        except Exception as exc:
            duration_ms = (time.time() - start) * 1000.0
            return HTTPProbeSingle(
                url=url,
                scheme=scheme,
                reachable=False,
                status_code=None,
                response_time_ms=round(duration_ms, 2),
                connection_error=str(exc),
            )

    async def probe_hostname(self, hostname: str) -> HTTPProbeResult:
        # Create unverified SSL client to reach custom/self-signed endpoints during VAPT
        async with httpx.AsyncClient(verify=False, headers={"User-Agent": "VAPT-Recon-Platform/1.0"}) as client:
            http_url = f"http://{hostname}"
            https_url = f"https://{hostname}"

            http_res, https_res = await asyncio.gather(
                self._probe_url(client, http_url),
                self._probe_url(client, https_url),
            )

        # Classification Logic:
        # Status code 200, 301, 302, 401, 403, 404, 500 are ALL evidence of an ACTIVE web service!
        is_active = (http_res.reachable and http_res.status_code is not None) or (
            https_res.reachable and https_res.status_code is not None
        )

        classification = "ACTIVE" if is_active else "INACTIVE"
        primary_url = None
        primary_scheme = None

        if https_res.reachable and https_res.status_code is not None:
            primary_url = https_url
            primary_scheme = "https"
        elif http_res.reachable and http_res.status_code is not None:
            primary_url = http_url
            primary_scheme = "http"

        return HTTPProbeResult(
            hostname=hostname,
            http_probe=http_res,
            https_probe=https_res,
            classification=classification,
            primary_url=primary_url,
            primary_scheme=primary_scheme,
        )

    async def probe_batch(self, hostnames: List[str]) -> List[HTTPProbeResult]:
        tasks = [self.probe_hostname(h) for h in hostnames]
        return await asyncio.gather(*tasks)
