import asyncio
import os
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from backend.app.services.common.runner import ToolRunner, ToolExecutionResult


def to_posix_path(win_path: str) -> str:
    """Converts a Windows path (e.g. C:\\Users... or c:/Users...) to Git Bash POSIX path (/c/Users...)."""
    p = os.path.abspath(win_path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        drive = p[0].lower()
        p = f"/{drive}{p[2:]}"
    return p


class TestSSLRunner:
    """Safe runner for testssl.sh CLI via Git Bash on Windows or native bash on Linux."""

    def __init__(
        self,
        git_bash_path: str = r"C:\Program Files\Git\bin\bash.exe",
        testssl_script: Optional[str] = None,
    ):
        self.git_bash = git_bash_path
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
        self.script_path = testssl_script or os.path.join(repo_root, "tools", "testssl", "testssl.sh")
        self.tools_bin = os.path.join(repo_root, "tools", "bin")
        self.runner = ToolRunner(default_timeout=600)

    async def execute_scan(
        self,
        target: str,
        output_json_path: str,
        fast_mode: bool = True,
    ) -> ToolExecutionResult:
        """Executes testssl.sh against target writing structured JSON output."""
        target_uri = target if ":" in target else f"{target}:443"

        if os.path.exists(output_json_path):
            try:
                os.remove(output_json_path)
            except Exception:
                pass

        fast_flag = " --fast" if fast_mode else ""
        if sys.platform == "win32":
            script_posix = to_posix_path(self.script_path)
            tools_bin_posix = to_posix_path(self.tools_bin)
            json_posix = to_posix_path(output_json_path)

            bash_cmd = (
                f'export PATH="$PATH:{tools_bin_posix}"; '
                f'export OPENSSL=/mingw64/bin/openssl.exe; '
                f'export NXDNS="127.0.0.1:0"; '
                f'export TERM=xterm; '
                f'cd /tmp; '
                f'"{script_posix}" --quiet{fast_flag} --color 0 --ip one --overwrite '
                f'--jsonfile-pretty "{json_posix}" {target_uri}'
            )

            args = [self.git_bash, "-c", bash_cmd]
        else:
            args = [self.script_path, "--quiet"]
            if fast_mode:
                args.append("--fast")
            args.extend([
                "--color",
                "0",
                "--ip",
                "one",
                "--overwrite",
                "--jsonfile-pretty",
                output_json_path,
                target_uri,
            ])

        result = await self.runner.run(args=args, timeout=600)
        return result
