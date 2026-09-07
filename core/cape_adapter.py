"""
Dynamic Sandbox Integration Adapter (CAPEv2 / Cuckoo REST API).
Allows Blue Team agents to submit suspicious binaries to an external isolated
dynamic analysis sandbox, poll analysis status, and retrieve behavioral reports
(C2 network traffic, API logs, dropped files, and triggered signatures).
Provides graceful fallback when an external sandbox is not configured.
"""

from __future__ import annotations
import json
import os
import ssl
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union


class CapeSandboxAdapter:
    """REST API Client for CAPEv2 and Cuckoo Dynamic Malware Analysis Sandboxes."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        transport: Optional[Callable[[urllib.request.Request], Any]] = None,
        verify_ssl: bool = True,
    ):
        """
        Initialize CAPE/Cuckoo REST API adapter.
        
        Args:
            api_url: Base URL of sandbox REST API (e.g. 'https://cape.example.com').
                     Falls back to CAPE_API_URL environment variable.
            api_key: API authorization token.
                     Falls back to CAPE_API_KEY environment variable.
            transport: Optional custom HTTP opener/transport for testing & mocking.
            verify_ssl: Whether to verify SSL certificates (can be disabled via CAPE_VERIFY_SSL=0).
        """
        raw_url = api_url or os.environ.get("CAPE_API_URL", "")
        self.api_url = raw_url.rstrip("/") if raw_url else ""
        self.api_key = api_key or os.environ.get("CAPE_API_KEY", "")

        env_verify = os.environ.get("CAPE_VERIFY_SSL", "").strip().lower()
        if env_verify in ("0", "false", "no"):
            self.verify_ssl = False
        else:
            self.verify_ssl = verify_ssl

        if not self.verify_ssl:
            self._ssl_context: Optional[ssl.SSLContext] = ssl._create_unverified_context()
        else:
            self._ssl_context = None

        if transport:
            self._transport = transport
        else:
            def _default_transport(req: urllib.request.Request) -> Any:
                if self._ssl_context is not None:
                    return urllib.request.urlopen(req, context=self._ssl_context)
                return urllib.request.urlopen(req)
            self._transport = _default_transport

    def is_configured(self) -> bool:
        """Check if an external dynamic sandbox endpoint is configured."""
        return bool(self.api_url)

    def get_status_summary(self) -> Dict[str, Any]:
        """Return connectivity configuration status."""
        return {
            "configured": self.is_configured(),
            "api_url": self.api_url if self.is_configured() else None,
            "has_api_key": bool(self.api_key),
            "engine": "CAPEv2 / Cuckoo Sandbox REST API v2",
        }

    def submit_file(
        self,
        file_path: str | Path,
        tags: Optional[str] = None,
        timeout_sec: int = 120,
        poll_interval: float = 2.0,
        poll_completion: bool = True,
    ) -> Dict[str, Any]:
        """
        Submit a binary artifact to the dynamic sandbox and await analysis report.

        Args:
            file_path: Path to target file on disk.
            tags: Optional environment tags (e.g. 'win10', 'x64', 'office').
            timeout_sec: Maximum time to wait for sandbox execution (default: 120s).
            poll_interval: Seconds between status polling requests (default: 2.0s).
            poll_completion: If True, blocks until report is ready or timeout occurs.
                             If False, returns immediately with task_id for non-blocking polling.

        Returns:
            Structured dictionary with analysis findings or graceful fallback guidance.
        """
        if not file_path:
            return {
                "success": False,
                "error": "file_path parameter is required.",
                "configured": self.is_configured(),
            }

        target = Path(file_path).resolve()
        if not target.is_file():
            return {
                "success": False,
                "error": f"Target file not found: {target}",
                "configured": self.is_configured(),
            }

        if not self.is_configured():
            return {
                "success": False,
                "configured": False,
                "error": "External dynamic analysis sandbox is not configured.",
                "advisory": (
                    "To enable dynamic detonation, set CAPE_API_URL (e.g., 'https://cape.example.com') "
                    "and CAPE_API_KEY environment variables. Air-gapped pure-Python static triage "
                    "(mcp_triage_binary) remains active."
                ),
                "setup_guide": {
                    "env_vars": ["CAPE_API_URL", "CAPE_API_KEY"],
                    "default_endpoint": "/api/v2/tasks/create/file/",
                    "fallback_tool": "mcp_triage_binary",
                },
                "target_file": str(target),
            }

        # Submit task
        sub_res = self._submit_task(target, tags=tags)
        if not sub_res.get("success"):
            return sub_res

        task_id = sub_res["task_id"]

        # Non-blocking async submission: return immediately
        if not poll_completion:
            return {
                "success": True,
                "task_id": task_id,
                "status": "pending",
                "target_file": str(target),
                "poll_completion": False,
                "message": f"Task {task_id} submitted successfully to dynamic sandbox. Use check_task_status(task_id={task_id}) to poll progress.",
            }

        # Poll status until finished or timeout
        start_time = time.time()
        while time.time() - start_time < timeout_sec:
            status_res = self._poll_task_status(task_id)
            if not status_res.get("success"):
                return status_res

            status_str = status_res.get("status", "").lower()
            if status_str in ("reported", "completed", "success"):
                # Fetch full behavioral report
                return self._fetch_report(task_id, target)
            elif status_str in ("failed", "failure"):
                return {
                    "success": False,
                    "task_id": task_id,
                    "status": "failed",
                    "error": f"Sandbox task {task_id} failed during detonation.",
                    "target_file": str(target),
                }

            time.sleep(poll_interval)

        return {
            "success": False,
            "task_id": task_id,
            "status": "timeout",
            "error": f"Dynamic sandbox analysis timed out after {timeout_sec} seconds (task {task_id}).",
            "target_file": str(target),
        }

    def check_task_status(
        self,
        task_id: int | str,
        target_file: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        """
        Check the status of an active or completed dynamic sandbox task non-blockingly.
        If analysis is finished ('reported', 'completed', 'success'), retrieves the full behavioral report.
        """
        if not self.is_configured():
            return {
                "success": False,
                "configured": False,
                "error": "External dynamic analysis sandbox is not configured.",
                "advisory": (
                    "To enable dynamic detonation, set CAPE_API_URL and CAPE_API_KEY environment variables."
                ),
                "task_id": task_id,
            }

        status_res = self._poll_task_status(task_id)
        if not status_res.get("success"):
            return status_res

        status_str = status_res.get("status", "pending").lower()
        target_path = Path(target_file).resolve() if target_file else Path(f"task_{task_id}.bin")

        if status_str in ("reported", "completed", "success"):
            report = self._fetch_report(task_id, target_path)
            if not report.get("success"):
                return report
            report["status"] = status_str
            report["completed"] = True
            return report
        elif status_str in ("failed", "failure"):
            return {
                "success": False,
                "task_id": task_id,
                "status": "failed",
                "error": f"Sandbox task {task_id} failed during detonation.",
                "target_file": str(target_path),
            }

        return {
            "success": True,
            "task_id": task_id,
            "status": status_str,
            "completed": False,
            "message": f"Sandbox task {task_id} is currently '{status_str}'.",
            "target_file": str(target_path),
        }

    def _submit_task(self, target: Path, tags: Optional[str] = None) -> Dict[str, Any]:
        """POST binary file to /api/v2/tasks/create/file/."""
        endpoint = f"{self.api_url}/api/v2/tasks/create/file/"
        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
        
        try:
            file_bytes = target.read_bytes()
        except OSError as exc:
            return {"success": False, "error": f"Failed to read file: {exc}"}

        body = bytearray()
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="file"; filename="{target.name}"\r\n'.encode("utf-8"))
        body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
        body.extend(file_bytes)
        body.extend(b"\r\n")

        if tags:
            body.extend(f"--{boundary}\r\n".encode("utf-8"))
            body.extend(b'Content-Disposition: form-data; name="tags"\r\n\r\n')
            body.extend(f"{tags}\r\n".encode("utf-8"))

        body.extend(f"--{boundary}--\r\n".encode("utf-8"))

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "CookieCyberTeam-CAPEAdapter/1.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Token {self.api_key}"

        req = urllib.request.Request(endpoint, data=bytes(body), headers=headers, method="POST")

        try:
            with self._transport(req) as resp:
                status_code = resp.status if hasattr(resp, "status") else 200
                resp_data = json.loads(resp.read().decode("utf-8"))
                
                # Support multiple CAPEv2 / Cuckoo response formats
                task_id = None
                if isinstance(resp_data, dict):
                    if "task_id" in resp_data:
                        task_id = resp_data["task_id"]
                    elif "task_ids" in resp_data and isinstance(resp_data["task_ids"], list) and resp_data["task_ids"]:
                        task_id = resp_data["task_ids"][0]
                    elif "data" in resp_data:
                        data_val = resp_data["data"]
                        if isinstance(data_val, dict):
                            task_ids = data_val.get("task_ids", [])
                            if task_ids:
                                task_id = task_ids[0]
                            elif "task_id" in data_val:
                                task_id = data_val["task_id"]
                        elif isinstance(data_val, (int, str)):
                            task_id = data_val
                        elif isinstance(data_val, list) and data_val:
                            task_id = data_val[0]

                if task_id is None:
                    return {
                        "success": False,
                        "error": f"Unexpected response format from sandbox API: {resp_data}",
                    }

                return {"success": True, "task_id": task_id, "endpoint": endpoint}

        except urllib.error.HTTPError as he:
            err_body = he.read().decode("utf-8", errors="replace") if hasattr(he, "read") else ""
            return {
                "success": False,
                "error": f"HTTP {he.code} {he.reason}: {err_body}",
                "status_code": he.code,
            }
        except urllib.error.URLError as ue:
            return {"success": False, "error": f"Connection failed to sandbox endpoint {endpoint}: {ue.reason}"}
        except Exception as exc:
            return {"success": False, "error": f"Sandbox submission encountered unexpected error: {str(exc)}"}

    def _poll_task_status(self, task_id: Union[int, str]) -> Dict[str, Any]:
        """Query /api/v2/tasks/view/{task_id}/ or /tasks/status/{task_id}/ for execution state."""
        endpoint = f"{self.api_url}/api/v2/tasks/view/{task_id}/"
        headers = {"User-Agent": "CookieCyberTeam-CAPEAdapter/1.0"}
        if self.api_key:
            headers["Authorization"] = f"Token {self.api_key}"

        req = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with self._transport(req) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                status = "pending"
                if isinstance(resp_data, dict):
                    task_info = resp_data.get("data", resp_data)
                    if isinstance(task_info, str):
                        status = task_info
                    elif isinstance(task_info, dict):
                        if "task" in task_info and isinstance(task_info["task"], dict):
                            status = task_info["task"].get("status", "pending")
                        else:
                            status = task_info.get("status", "pending")

                return {"success": True, "status": status, "task_id": task_id}

        except urllib.error.HTTPError as he:
            return {"success": False, "error": f"HTTP {he.code} polling status for task {task_id}"}
        except Exception as exc:
            return {"success": False, "error": f"Status polling failed: {str(exc)}"}

    def _fetch_report(self, task_id: Union[int, str], target: Path) -> Dict[str, Any]:
        """Retrieve full JSON report from /api/v2/tasks/get/report/{task_id}/ and synthesize IOCs."""
        endpoint = f"{self.api_url}/api/v2/tasks/get/report/{task_id}/"
        headers = {"User-Agent": "CookieCyberTeam-CAPEAdapter/1.0"}
        if self.api_key:
            headers["Authorization"] = f"Token {self.api_key}"

        req = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with self._transport(req) as resp:
                raw_report = json.loads(resp.read().decode("utf-8"))

            # Synthesize behavioral intelligence from report
            network = raw_report.get("network", {})
            c2_traffic = {
                "hosts": network.get("hosts", []),
                "domains": [d.get("domain") for d in network.get("domains", []) if isinstance(d, dict)],
                "http": [
                    f"{h.get('method', 'GET')} {h.get('uri', '')}"
                    for h in network.get("http", []) if isinstance(h, dict)
                ],
                "dns": [
                    f"{d.get('request', '')} -> {d.get('answers', [])}"
                    for d in network.get("dns", []) if isinstance(d, dict)
                ],
            }

            behavior = raw_report.get("behavior", {})
            summary = behavior.get("summary", {})
            api_calls = {
                "files_written": summary.get("write_files", []),
                "files_deleted": summary.get("delete_files", []),
                "keys_written": summary.get("write_keys", []),
                "mutexes": summary.get("mutexes", []),
                "processes_created": summary.get("guid_list", []),
            }

            dropped = [
                {
                    "name": d.get("name", "unknown"),
                    "sha256": d.get("sha256", ""),
                    "size": d.get("size", 0),
                    "type": d.get("type", ""),
                }
                for d in raw_report.get("dropped", []) if isinstance(d, dict)
            ]

            signatures = [
                {
                    "name": s.get("name", ""),
                    "description": s.get("description", ""),
                    "severity": s.get("severity", 1),
                }
                for s in raw_report.get("signatures", []) if isinstance(s, dict)
            ]

            return {
                "success": True,
                "task_id": task_id,
                "status": "reported",
                "target_file": str(target),
                "malscore": raw_report.get("malscore", 0.0),
                "c2_traffic": c2_traffic,
                "behavioral_summary": api_calls,
                "dropped_files": dropped,
                "signatures": signatures,
                "raw_report_available": True,
            }

        except Exception as exc:
            return {
                "success": False,
                "task_id": task_id,
                "error": f"Failed to retrieve report for task {task_id}: {str(exc)}",
            }
