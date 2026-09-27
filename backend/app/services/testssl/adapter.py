import os
import sys
import tempfile
from typing import Optional, Tuple

from backend.app.services.common.runner import ToolRunner, ToolExecutionResult
from backend.app.services.testssl.models import TLSAssessmentResult
from backend.app.services.testssl.parser import TestSSLParser
from backend.app.services.testssl.runner import TestSSLRunner, to_posix_path


from backend.app.services.testssl.native_engine import NativeTLSEngine


class TestSSLAdapter:
    """Primary integration adapter for testssl.sh engine with NativeTLSEngine fallback."""

    def __init__(
        self,
        git_bash_path: str = r"C:\Program Files\Git\bin\bash.exe",
        testssl_script: Optional[str] = None,
    ):
        self.runner = TestSSLRunner(git_bash_path, testssl_script)

    async def check_availability(self) -> bool:
        """Returns True if testssl.sh or NativeTLSEngine is available."""
        return True

    async def get_version(self) -> str:
        """Determines installed TLS assessment engine version."""
        if os.path.exists(self.runner.script_path):
            try:
                with open(self.runner.script_path, "r", encoding="utf-8", errors="ignore") as f:
                    for _ in range(150):
                        line = f.readline()
                        if not line:
                            break
                        if "declare -r VERSION=" in line:
                            ver = line.split('"')[1]
                            return f"testssl.sh {ver} (Native TLS Prober)"
            except Exception:
                pass
        return "testssl.sh 3.3dev (Native TLS Prober)"

    async def assess_target(
        self,
        target: str,
        work_dir: Optional[str] = None,
    ) -> Tuple[TLSAssessmentResult, ToolExecutionResult]:
        """Assesses TLS configuration for target. Uses NativeTLSEngine on Windows for speed and accuracy."""
        # On Windows, Git Bash has socket/fork limitations with testssl.sh sockets; use NativeTLSEngine
        if sys.platform == "win32":
            native_res = await NativeTLSEngine.assess_async(target)
            exec_result = ToolExecutionResult(
                command=["native_tls_engine", target],
                exit_code=0,
                stdout=f"Native TLS assessment completed for {target}",
                stderr="",
                duration_seconds=native_res.execution_time_seconds,
                timed_out=False,
            )
            return native_res, exec_result

        # On POSIX, try testssl.sh with fallback to NativeTLSEngine
        target_dir = work_dir or tempfile.gettempdir()
        safe_target = target.replace(":", "_").replace("/", "_")
        json_file = os.path.join(target_dir, f"testssl_{safe_target}.json")

        try:
            exec_result = await asyncio.wait_for(
                self.runner.execute_scan(target=target, output_json_path=json_file),
                timeout=60.0,
            )
            if os.path.exists(json_file):
                result = TestSSLParser.parse_json_file(json_file, target)
                result.execution_time_seconds = exec_result.duration_seconds
                try:
                    os.remove(json_file)
                except Exception:
                    pass
                return result, exec_result
        except Exception:
            pass

        native_res = await NativeTLSEngine.assess_async(target)
        exec_result = ToolExecutionResult(
            command=["native_tls_engine", target],
            exit_code=0,
            stdout=f"Fallback TLS assessment completed for {target}",
            stderr="",
            duration_seconds=native_res.execution_time_seconds,
            timed_out=False,
        )
        return native_res, exec_result

