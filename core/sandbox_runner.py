"""
Isolated Sandbox Test Execution Engine.
Enforces zero shell=True, environment variable whitelisting,
process tree termination on Windows/POSIX, and optional Docker isolation.
"""

from __future__ import annotations
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


SAFE_ENV_KEYS = {
    "PATH",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "HOME",
    "TEMP",
    "TMP",
    "PYTHONPATH",
    "PYTHONHOME",
    "USERPROFILE",
    "COMSPEC",
    "PATHEXT",
    "WINDIR",
    "LANG",
    "LC_ALL",
    # Docker daemon connection & user profile paths
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "LOCALAPPDATA",
    "APPDATA",
    "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
}

BLOCKED_KEYWORD_PATTERNS = {
    "SECRET",
    "KEY",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "AUTH",
    "CRED",
    "API",
    "AWS",
    "GITHUB",
    "OPENAI",
    "ANTHROPIC",
    "GEMINI",
    "DATABASE_URL",
}


def build_whitelisted_env() -> Dict[str, str]:
    """
    Build a sanitized environment mapping containing only whitelisted system variables
    and stripping all sensitive credentials/tokens.
    """
    cleaned: Dict[str, str] = {}
    for key, val in os.environ.items():
        key_upper = key.upper()
        # Must match safe env whitelist
        if key_upper in SAFE_ENV_KEYS:
            # Must NOT contain secret keywords
            if not any(pattern in key_upper for pattern in BLOCKED_KEYWORD_PATTERNS):
                cleaned[key] = val
    return cleaned


def terminate_process_tree(proc: subprocess.Popen) -> None:
    """Terminate the process and all its children across Windows and POSIX."""
    try:
        if sys.platform == "win32":
            # taskkill /F /T /PID terminates child process tree forcefully
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
                timeout=5,
            )
        else:
            try:
                to_visit = [proc.pid]
                all_children: List[int] = []
                seen = {proc.pid}
                while to_visit:
                    curr = to_visit.pop()
                    res = subprocess.run(
                        ["pgrep", "-P", str(curr)],
                        capture_output=True,
                        text=True,
                        shell=False,
                        timeout=5,
                    )
                    if res.returncode == 0:
                        for p in res.stdout.split():
                            if p.isdigit():
                                ipid = int(p)
                                if ipid not in seen:
                                    seen.add(ipid)
                                    all_children.append(ipid)
                                    to_visit.append(ipid)
                for cpid in all_children:
                    try:
                        os.kill(cpid, 9)
                    except Exception:
                        pass
            except Exception:
                pass
            proc.kill()
    except Exception:
        pass


class SandboxRunner:
    """Safely executes code or tests in an isolated subprocess or Docker sandbox."""

    def __init__(self, default_timeout: int = 30):
        self.default_timeout = default_timeout

    def run_command(
        self,
        argv: List[str],
        cwd: Optional[str | Path] = None,
        timeout: Optional[int] = None,
        custom_env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute command with strict argv list and shell=False.
        """
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            raise ValueError("argv must be a list of strings. Raw strings with shell=True are forbidden.")

        timeout_sec = timeout if timeout is not None else self.default_timeout
        env = build_whitelisted_env()
        if custom_env:
            for k, v in custom_env.items():
                if not any(p in k.upper() for p in BLOCKED_KEYWORD_PATTERNS):
                    env[k] = v

        start_time = time.perf_counter()
        timed_out = False
        stdout_text = ""
        stderr_text = ""
        exit_code = -1

        proc: Optional[subprocess.Popen] = None
        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd) if cwd else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                shell=False,  # MANDATORY SECURITY INVARIANT
            )
            stdout_text, stderr_text = proc.communicate(timeout=timeout_sec)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            if proc:
                terminate_process_tree(proc)
                try:
                    stdout_text, stderr_text = proc.communicate(timeout=2)
                except Exception:
                    pass
            stderr_text += f"\n[Sandbox Timeout]: Execution exceeded {timeout_sec}s and was terminated."
            exit_code = 124  # Standard timeout exit code
        except Exception as exc:
            if proc and proc.poll() is None:
                terminate_process_tree(proc)
                try:
                    proc.communicate(timeout=2)
                except Exception:
                    pass
            stderr_text += f"\n[Sandbox Execution Error]: {str(exc)}"
            exit_code = 1
        finally:
            if proc:
                if proc.stdout and not getattr(proc.stdout, "closed", True):
                    try:
                        proc.stdout.close()
                    except Exception:
                        pass
                if proc.stderr and not getattr(proc.stderr, "closed", True):
                    try:
                        proc.stderr.close()
                    except Exception:
                        pass

        duration_ms = int((time.perf_counter() - start_time) * 1000)

        return {
            "success": exit_code == 0 and not timed_out,
            "exit_code": exit_code,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "argv": argv,
        }

    def run_docker(
        self,
        argv: List[str],
        mount_dir: Optional[str | Path] = None,
        image: str = "python:3.11-slim",
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run command inside Docker isolated container (--network none --read-only).
        """
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": "Docker CLI is not installed or not running in PATH.",
                "timed_out": False,
                "duration_ms": 0,
                "argv": argv,
            }

        docker_argv = [
            docker_bin,
            "run",
            "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "PYTHONUNBUFFERED=1",
            "--memory", "512m",
            "--cpus", "1.0",
        ]

        if mount_dir:
            mount_path = Path(mount_dir).resolve()
            # Normalize path with forward slashes for Docker volume syntax
            # Handle Windows drive letters (e.g. 'E:/...' -> '/e/...') to avoid invalid multi-colon volume specs
            if mount_path.drive:
                drive_letter = mount_path.drive[0].lower()
                path_without_drive = mount_path.as_posix()[len(mount_path.drive):]
                mount_posix = f"/{drive_letter}{path_without_drive}"
            else:
                mount_posix = mount_path.as_posix()
            docker_argv.extend(["-v", f"{mount_posix}:/app:ro", "-w", "/app"])

        docker_argv.append(image)
        docker_argv.extend(argv)

        return self.run_command(docker_argv, timeout=timeout)

    def run_python_test(
        self,
        test_file_path: str | Path,
        cwd: Optional[str | Path] = None,
        timeout: Optional[int] = None,
        sandbox_type: str = "subprocess",
    ) -> Dict[str, Any]:
        """
        Run a Python unit test using standard library unittest runner.
        """
        target = Path(test_file_path).resolve()
        if not target.exists():
            return {
                "success": False,
                "exit_code": 1,
                "stdout": "",
                "stderr": f"Test file not found: {target}",
                "timed_out": False,
                "duration_ms": 0,
                "argv": [],
            }

        work_dir = cwd if cwd else target.parent

        if sandbox_type == "docker":
            # Run via Docker container
            argv = ["python", "-m", "unittest", target.name, "-v"]
            return self.run_docker(argv=argv, mount_dir=work_dir, timeout=timeout)

        # Standard Subprocess Argv sandbox
        argv = [sys.executable, "-m", "unittest", str(target), "-v"]
        return self.run_command(argv=argv, cwd=work_dir, timeout=timeout)
