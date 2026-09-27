import os
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from backend.app.services.common.runner import ToolRunner, ToolExecutionResult
from backend.app.services.theharvester.models import DiscoveryBatch
from backend.app.services.theharvester.parser import TheHarvesterParser
from backend.app.services.theharvester.runner import TheHarvesterRunner


class TheHarvesterAdapter:
    """Primary integration adapter for theHarvester discovery engine."""

    def __init__(self, python_executable: Optional[str] = None):
        self.runner = TheHarvesterRunner(python_executable)

    async def check_availability(self) -> bool:
        """Returns True if theHarvester module is executable."""
        tr = ToolRunner(default_timeout=15)
        res = await tr.run([self.runner.python_exec, "-m", "theHarvester.theHarvester", "-h"])
        return res.success or "theHarvester" in res.stdout or "theHarvester" in res.stderr

    async def get_version(self) -> str:
        """Determines installed theHarvester version."""
        tr = ToolRunner(default_timeout=15)
        res = await tr.run([self.runner.python_exec, "-m", "theHarvester.theHarvester", "-h"])
        for line in (res.stdout + res.stderr).splitlines():
            if "theHarvester" in line and ("5." in line or "4." in line or "0." in line):
                return line.strip()
        return "5.0.0"

    async def discover(
        self,
        domain: str,
        sources: Optional[List[str]] = None,
        limit: int = 500,
        work_dir: Optional[str] = None,
    ) -> Tuple[DiscoveryBatch, ToolExecutionResult]:
        """Runs theHarvester, captures evidence, parses structured results into DiscoveryBatch."""
        target_dir = work_dir or tempfile.gettempdir()
        prefix = os.path.join(target_dir, f"harvest_{domain.replace('.', '_')}")

        exec_result, json_file, jsonl_file = await self.runner.execute_discovery(
            domain=domain,
            output_prefix=prefix,
            sources=sources,
            limit=limit,
        )

        # Parse structured output (JSONL primary, JSON fallback)
        batch = TheHarvesterParser.parse_output(prefix, domain)

        # Clean up temporary output files
        for fpath in [json_file, jsonl_file, f"{prefix}.xml"]:
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except Exception:
                    pass

        return batch, exec_result
