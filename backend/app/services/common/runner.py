import asyncio
import os
import subprocess
import time
from typing import Dict, List, Optional, Tuple


class ToolExecutionResult:
    def __init__(
        self,
        command: List[str],
        exit_code: int,
        stdout: str,
        stderr: str,
        duration_seconds: float,
        timed_out: bool = False,
    ):
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_seconds = duration_seconds
        self.timed_out = timed_out

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class ToolRunner:
    """Safe tool runner executing commands as argument arrays with timeout and output bounds."""

    def __init__(self, default_timeout: int = 300, max_output_bytes: int = 10 * 1024 * 1024):
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes

    def _run_subprocess_sync(
        self,
        args: List[str],
        cwd: Optional[str],
        env: Dict[str, str],
        exec_timeout: float,
    ) -> ToolExecutionResult:
        start_time = time.time()
        try:
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
            try:
                stdout_bytes, stderr_bytes = process.communicate(timeout=float(exec_timeout))
                duration = time.time() - start_time
                stdout = stdout_bytes[: self.max_output_bytes].decode("utf-8", errors="replace")
                stderr = stderr_bytes[: self.max_output_bytes].decode("utf-8", errors="replace")

                return ToolExecutionResult(
                    command=args,
                    exit_code=process.returncode or 0,
                    stdout=stdout,
                    stderr=stderr,
                    duration_seconds=duration,
                    timed_out=False,
                )
            except subprocess.TimeoutExpired:
                duration = time.time() - start_time
                try:
                    process.kill()
                    stdout_bytes, stderr_bytes = process.communicate()
                    stdout = stdout_bytes[: self.max_output_bytes].decode("utf-8", errors="replace")
                    stderr = stderr_bytes[: self.max_output_bytes].decode("utf-8", errors="replace")
                except Exception:
                    stdout = ""
                    stderr = ""
                return ToolExecutionResult(
                    command=args,
                    exit_code=-1,
                    stdout=stdout,
                    stderr=f"Tool execution timed out after {exec_timeout} seconds. {stderr}".strip(),
                    duration_seconds=duration,
                    timed_out=True,
                )
        except Exception as exc:
            duration = time.time() - start_time
            return ToolExecutionResult(
                command=args,
                exit_code=-1,
                stdout="",
                stderr=f"Subprocess execution error: {str(exc)}",
                duration_seconds=duration,
                timed_out=False,
            )

    async def run(
        self,
        args: List[str],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> ToolExecutionResult:
        if not args or not isinstance(args, list):
            raise ValueError("Arguments must be a non-empty list of strings")

        exec_timeout = timeout if timeout is not None else self.default_timeout

        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        harvester_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "tools", "theHarvester"))
        existing_pythonpath = merged_env.get("PYTHONPATH", "")
        merged_env["PYTHONPATH"] = f"{harvester_path};{existing_pythonpath}" if existing_pythonpath else harvester_path

        # Force unbuffered output where possible
        merged_env["PYTHONUNBUFFERED"] = "1"

        return await asyncio.to_thread(
            self._run_subprocess_sync, args, cwd, merged_env, exec_timeout
        )
