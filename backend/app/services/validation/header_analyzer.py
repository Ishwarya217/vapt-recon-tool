from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class HeaderEvaluation(BaseModel):
    header_name: str
    status: str  # PRESENT, MISSING, WARNING, INFORMATIONAL
    value: Optional[str] = None
    severity: str  # HIGH, MEDIUM, LOW, INFO
    description: str
    recommendation: str


class HeaderAnalysisResult(BaseModel):
    hostname: str
    url: str
    evaluations: List[HeaderEvaluation] = Field(default_factory=list)
    missing_count: int = 0
    present_count: int = 0
    warning_count: int = 0


class HeaderAnalyzer:
    """Analyzes HTTP security headers for active assets."""

    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    @classmethod
    def analyze_headers(cls, hostname: str, url: str, headers: Dict[str, str]) -> HeaderAnalysisResult:
        evals: List[HeaderEvaluation] = []
        missing = 0
        present = 0
        warnings = 0

        # 1. Strict-Transport-Security (HSTS)
        hsts = headers.get("strict-transport-security")
        if hsts:
            present += 1
            if "max-age=" in hsts and int("".join(filter(str.isdigit, hsts.split("max-age=")[1].split(";")[0])) or "0") < 15768000:
                warnings += 1
                evals.append(
                    HeaderEvaluation(
                        header_name="Strict-Transport-Security",
                        status="WARNING",
                        value=hsts,
                        severity="LOW",
                        description="HSTS header max-age is under 6 months (15768000 seconds).",
                        recommendation="Increase max-age to at least 31536000 (1 year) and include includeSubDomains.",
                    )
                )
            else:
                evals.append(
                    HeaderEvaluation(
                        header_name="Strict-Transport-Security",
                        status="PRESENT",
                        value=hsts,
                        severity="INFO",
                        description="HSTS is properly configured.",
                        recommendation="Maintain HSTS header settings.",
                    )
                )
        else:
            missing += 1
            evals.append(
                HeaderEvaluation(
                    header_name="Strict-Transport-Security",
                    status="MISSING",
                    value=None,
                    severity="MEDIUM",
                    description="HTTP Strict Transport Security (HSTS) header is missing.",
                    recommendation="Enable HSTS with 'max-age=31536000; includeSubDomains'.",
                )
            )

        # 2. Content-Security-Policy (CSP)
        csp = headers.get("content-security-policy")
        if csp:
            present += 1
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                warnings += 1
                evals.append(
                    HeaderEvaluation(
                        header_name="Content-Security-Policy",
                        status="WARNING",
                        value=csp,
                        severity="LOW",
                        description="CSP header contains unsafe directives ('unsafe-inline' or 'unsafe-eval').",
                        recommendation="Remove unsafe directives and use nonces or hashes.",
                    )
                )
            else:
                evals.append(
                    HeaderEvaluation(
                        header_name="Content-Security-Policy",
                        status="PRESENT",
                        value=csp,
                        severity="INFO",
                        description="CSP header is present.",
                        recommendation="Periodically audit CSP rules.",
                    )
                )
        else:
            missing += 1
            evals.append(
                HeaderEvaluation(
                    header_name="Content-Security-Policy",
                    status="MISSING",
                    value=None,
                    severity="MEDIUM",
                    description="Content-Security-Policy (CSP) header is missing.",
                    recommendation="Implement a robust CSP policy restricting resource loading.",
                )
            )

        # 3. X-Frame-Options
        xfo = headers.get("x-frame-options")
        if xfo:
            present += 1
            evals.append(
                HeaderEvaluation(
                    header_name="X-Frame-Options",
                    status="PRESENT",
                    value=xfo,
                    severity="INFO",
                    description="X-Frame-Options clickjacking defense is enabled.",
                    recommendation="Ensure DENY or SAMEORIGIN is enforced.",
                )
            )
        else:
            missing += 1
            evals.append(
                HeaderEvaluation(
                    header_name="X-Frame-Options",
                    status="MISSING",
                    value=None,
                    severity="LOW",
                    description="X-Frame-Options header is missing (potential clickjacking vulnerability).",
                    recommendation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                )
            )

        # 4. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            present += 1
            evals.append(
                HeaderEvaluation(
                    header_name="X-Content-Type-Options",
                    status="PRESENT",
                    value=xcto,
                    severity="INFO",
                    description="MIME-sniffing prevention enabled.",
                    recommendation="Keep nosniff setting.",
                )
            )
        else:
            missing += 1
            evals.append(
                HeaderEvaluation(
                    header_name="X-Content-Type-Options",
                    status="MISSING",
                    value=xcto,
                    severity="LOW",
                    description="X-Content-Type-Options header missing or not set to nosniff.",
                    recommendation="Set X-Content-Type-Options: nosniff.",
                )
            )

        # 5. Information Disclosure Headers (Server / X-Powered-By)
        server = headers.get("server")
        if server:
            evals.append(
                HeaderEvaluation(
                    header_name="Server",
                    status="INFORMATIONAL",
                    value=server,
                    severity="INFO",
                    description=f"Server software banner exposed: {server}",
                    recommendation="Suppress or obscure granular version numbers in Server header.",
                )
            )

        x_powered = headers.get("x-powered-by")
        if x_powered:
            evals.append(
                HeaderEvaluation(
                    header_name="X-Powered-By",
                    status="WARNING",
                    value=x_powered,
                    severity="LOW",
                    description=f"Technology disclosure header present: {x_powered}",
                    recommendation="Remove X-Powered-By header from application server response.",
                )
            )

        return HeaderAnalysisResult(
            hostname=hostname,
            url=url,
            evaluations=evals,
            missing_count=missing,
            present_count=present,
            warning_count=warnings,
        )
