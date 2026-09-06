"""
Semgrep CLI Adapter for Multi-Language SAST Scanning.
Supports JavaScript/TypeScript, Go, Java, C/C++, and Python.
Safe execution: zero shell=True, environment-cleansed, timeout-protected.
"""

from __future__ import annotations
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


class SemgrepAdapter:
    """Adapter to orchestrate Semgrep CLI for multi-language static analysis."""

    def __init__(self, executable_path: Optional[str] = None):
        self.executable = executable_path or shutil.which("semgrep") or "semgrep"

    def is_available(self) -> bool:
        """Check if Semgrep CLI binary exists in PATH."""
        return shutil.which(self.executable) is not None

    def scan(
        self,
        target_path: str | Path,
        config: str = "auto",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """
        Run Semgrep CLI scan in JSON mode.
        Returns standardized findings structure.
        """
        target = Path(target_path).resolve()
        if not target.exists():
            return {
                "available": self.is_available(),
                "success": False,
                "error": f"Target path does not exist: {target}",
                "findings": [],
            }

        if not self.is_available():
            return {
                "available": False,
                "success": False,
                "error": "Semgrep CLI is not installed or not found in PATH. Pure-Python AST scanner is used as primary fallback.",
                "findings": [],
            }

        # Safe argv invocation (zero shell=True)
        argv = [
            self.executable,
            "scan",
            "--json",
            "--config",
            config,
            "--quiet",
            str(target),
        ]

        # Cleansed environment
        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "TEMP": os.environ.get("TEMP", ""),
            "TMP": os.environ.get("TMP", ""),
        }

        try:
            res = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                shell=False,
                env=safe_env,
                timeout=timeout,
            )
            raw_output = res.stdout.strip()
            if not raw_output and res.stderr:
                return {
                    "available": True,
                    "success": False,
                    "error": res.stderr.strip(),
                    "findings": [],
                }

            data = json.loads(raw_output) if raw_output else {}
            results = data.get("results", [])

            findings: List[Dict[str, Any]] = []
            for r in results:
                metadata = r.get("extra", {}).get("metadata", {})
                cwe = metadata.get("cwe", [])
                cwe_str = cwe[0] if isinstance(cwe, list) and cwe else (cwe if isinstance(cwe, str) else "CWE-Unknown")

                findings.append({
                    "tool": "semgrep",
                    "rule_id": r.get("check_id"),
                    "cwe_id": cwe_str,
                    "file_path": r.get("path"),
                    "line_number": r.get("start", {}).get("line"),
                    "end_line": r.get("end", {}).get("line"),
                    "message": r.get("extra", {}).get("message", ""),
                    "severity": r.get("extra", {}).get("severity", "WARNING"),
                    "lines": r.get("extra", {}).get("lines", ""),
                })

            return {
                "available": True,
                "success": True,
                "total_findings": len(findings),
                "findings": findings,
            }

        except subprocess.TimeoutExpired:
            return {
                "available": True,
                "success": False,
                "error": f"Semgrep scan timed out after {timeout} seconds.",
                "findings": [],
            }
        except Exception as exc:
            return {
                "available": True,
                "success": False,
                "error": f"Failed to execute Semgrep: {str(exc)}",
                "findings": [],
            }
