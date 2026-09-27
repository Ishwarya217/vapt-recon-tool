import os
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from backend.app.services.common.runner import ToolRunner, ToolExecutionResult


class TheHarvesterRunner:
    """Safe runner for the installed theHarvester CLI."""

    def __init__(self, python_executable: Optional[str] = None):
        venv_py = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".venv", "Scripts", "python.exe"))
        if not python_executable and os.path.exists(venv_py):
            python_executable = venv_py
        self.python_exec = python_executable or sys.executable
        self.runner = ToolRunner(default_timeout=300)

    VALID_SOURCES = {
        "apis-guru", "arquivo", "baidu", "bevigil", "brave", "bufferoverun", "builtwith",
        "censys", "certspotter", "commoncrawl", "criminalip", "crt-name", "crtsh", "dehashed",
        "dnsdb", "dnsdumpster", "duckduckgo", "dymo", "fofa", "fullhunt", "github-code", "gitlab",
        "hackertarget", "haveibeenpwned", "hibpverified", "hudsonrock", "hunter", "hunterhow",
        "intelx", "leakix", "leaklookup", "mojeek", "netlas", "onyphe", "otx", "pentesttools",
        "projectdiscovery", "rapiddns", "robtex", "rocketreach", "securityscorecard",
        "securityTrails", "sherlockeye", "shodan", "shodanct", "shodanInternetDB", "sourcegraph",
        "subdomainapi", "subdomaincenter", "subdomainfinderc99", "thc", "tomba", "urlscan",
        "virustotal", "waybackarchive", "whoisxml", "windvane", "yahoo", "zoomeye"
    }

    async def execute_discovery(
        self,
        domain: str,
        output_prefix: str,
        sources: Optional[List[str]] = None,
        limit: int = 500,
    ) -> Tuple[ToolExecutionResult, str, str]:
        """Runs theHarvester on domain writing structured JSON/JSONL output files."""
        valid_requested = []
        if sources:
            for s in sources:
                s_clean = s.strip().lower()
                if s_clean in self.VALID_SOURCES:
                    valid_requested.append(s_clean)

        if not valid_requested:
            valid_requested = ["hackertarget", "rapiddns", "crtsh", "certspotter", "otx", "urlscan", "duckduckgo", "baidu"]

        source_str = ",".join(valid_requested)

        # Safe argument array invoking theHarvester main entrypoint
        harvester_exe = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".venv", "Scripts", "theHarvester.exe"))
        if os.path.exists(self.python_exec):
            args = [
                self.python_exec,
                "-m",
                "theHarvester.theHarvester",
                "-d",
                domain,
                "-l",
                str(limit),
                "-b",
                source_str,
                "-f",
                output_prefix,
            ]
        elif os.path.exists(harvester_exe):
            args = [
                harvester_exe,
                "-d",
                domain,
                "-l",
                str(limit),
                "-b",
                source_str,
                "-f",
                output_prefix,
            ]
        else:
            args = [
                self.python_exec,
                "-c",
                "from theHarvester.theHarvester import main; main()",
                "-d",
                domain,
                "-l",
                str(limit),
                "-b",
                source_str,
                "-f",
                output_prefix,
            ]

        # Execute using ToolRunner
        result = await self.runner.run(args=args, timeout=300)

        json_file = f"{output_prefix}.json"
        jsonl_file = f"{output_prefix}.jsonl"

        return result, json_file, jsonl_file
