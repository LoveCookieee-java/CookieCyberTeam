"""
Unit tests for CapeSandboxAdapter (CAPEv2 / Cuckoo Sandbox REST API Client).
Verifies configuration status, file validation, task creation, status polling,
report parsing, timeout handling, and network error handling.
"""

import io
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from core.cape_adapter import CapeSandboxAdapter


class MockHTTPResponse:
    """Mock urllib response object."""

    def __init__(self, data: dict, status: int = 200, reason: str = "OK"):
        self._raw = json.dumps(data).encode("utf-8")
        self.status = status
        self.reason = reason

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class TestCapeSandboxAdapter(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = Path(self.temp_dir.name) / "suspicious.exe"
        self.test_file.write_bytes(b"MZ\x90\x00test_payload")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_unconfigured_status(self):
        """Adapter defaults to unconfigured if no URL is provided."""
        adapter = CapeSandboxAdapter(api_url="", api_key="")
        self.assertFalse(adapter.is_configured())
        summary = adapter.get_status_summary()
        self.assertFalse(summary["configured"])
        self.assertIsNone(summary["api_url"])
        self.assertFalse(summary["has_api_key"])

    def test_unconfigured_submit_file_returns_fallback_guide(self):
        """Unconfigured submission returns graceful fallback instructions."""
        adapter = CapeSandboxAdapter(api_url="", api_key="")
        res = adapter.submit_file(self.test_file)
        self.assertFalse(res["success"])
        self.assertFalse(res["configured"])
        self.assertIn("CAPE_API_URL", res["advisory"])
        self.assertEqual(res["setup_guide"]["fallback_tool"], "mcp_triage_binary")

    def test_nonexistent_file_error(self):
        """Nonexistent target file returns error before attempting network requests."""
        adapter = CapeSandboxAdapter(api_url="https://cape.local", api_key="secret")
        res = adapter.submit_file("does_not_exist.exe")
        self.assertFalse(res["success"])
        self.assertIn("not found", res["error"].lower())

    def test_successful_submission_polling_and_report(self):
        """Test full cycle: POST task, poll status, and retrieve report with mocked transport."""
        calls = []

        def mock_transport(req: urllib.request.Request):
            url = req.full_url
            calls.append((req.get_method(), url))
            
            if "/api/v2/tasks/create/file/" in url:
                return MockHTTPResponse({"error": False, "data": {"task_ids": [42]}})
            elif "/api/v2/tasks/view/42/" in url:
                return MockHTTPResponse({"error": False, "data": {"status": "reported"}})
            elif "/api/v2/tasks/get/report/42/" in url:
                return MockHTTPResponse({
                    "malscore": 8.5,
                    "network": {
                        "hosts": ["185.220.101.5"],
                        "domains": [{"domain": "malicious-c2.example.com"}],
                        "http": [{"method": "POST", "uri": "https://malicious-c2.example.com/gate.php"}],
                        "dns": [{"request": "malicious-c2.example.com", "answers": ["185.220.101.5"]}],
                    },
                    "behavior": {
                        "summary": {
                            "write_files": ["C:\\Windows\\Temp\\dropped_rat.exe"],
                            "write_keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Persistence"],
                            "mutexes": ["Global\\MALWARE_MUTEX_01"],
                        }
                    },
                    "dropped": [
                        {"name": "dropped_rat.exe", "sha256": "abcdef1234567890", "size": 1024, "type": "PE32"}
                    ],
                    "signatures": [
                        {"name": "creates_remote_thread", "description": "Injects code into remote process", "severity": 3}
                    ],
                })
            raise ValueError(f"Unexpected URL: {url}")

        adapter = CapeSandboxAdapter(
            api_url="https://cape.sandbox.local",
            api_key="token_12345",
            transport=mock_transport,
        )
        self.assertTrue(adapter.is_configured())

        res = adapter.submit_file(self.test_file, tags="win10", timeout_sec=10, poll_interval=0.01)
        self.assertTrue(res["success"])
        self.assertEqual(res["task_id"], 42)
        self.assertEqual(res["status"], "reported")
        self.assertEqual(res["malscore"], 8.5)

        # Verify C2 intelligence extraction
        c2 = res["c2_traffic"]
        self.assertIn("malicious-c2.example.com", c2["domains"])
        self.assertIn("185.220.101.5", c2["hosts"])
        self.assertTrue(any("POST https://malicious-c2.example.com/gate.php" in h for h in c2["http"]))

        # Verify behavioral summary
        behavior = res["behavioral_summary"]
        self.assertIn("C:\\Windows\\Temp\\dropped_rat.exe", behavior["files_written"])
        self.assertIn("Global\\MALWARE_MUTEX_01", behavior["mutexes"])

        # Verify dropped files and signatures
        self.assertEqual(len(res["dropped_files"]), 1)
        self.assertEqual(res["dropped_files"][0]["name"], "dropped_rat.exe")
        self.assertEqual(res["signatures"][0]["name"], "creates_remote_thread")

    def test_polling_timeout(self):
        """When status never transitions to completed, timeout is returned gracefully."""
        def mock_transport(req: urllib.request.Request):
            url = req.full_url
            if "/api/v2/tasks/create/file/" in url:
                return MockHTTPResponse({"task_id": 99})
            elif "/api/v2/tasks/view/99/" in url:
                return MockHTTPResponse({"data": {"status": "running"}})
            raise ValueError(url)

        adapter = CapeSandboxAdapter(
            api_url="https://cape.sandbox.local",
            transport=mock_transport,
        )

        res = adapter.submit_file(self.test_file, timeout_sec=0.1, poll_interval=0.02)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "timeout")
        self.assertIn("timed out", res["error"])

    def test_task_failure_status(self):
        """When task execution status is failed, reports failure cleanly."""
        def mock_transport(req: urllib.request.Request):
            url = req.full_url
            if "/api/v2/tasks/create/file/" in url:
                return MockHTTPResponse({"task_id": 88})
            elif "/api/v2/tasks/view/88/" in url:
                return MockHTTPResponse({"data": {"status": "failed"}})
            raise ValueError(url)

        adapter = CapeSandboxAdapter(
            api_url="https://cape.sandbox.local",
            transport=mock_transport,
        )

        res = adapter.submit_file(self.test_file, timeout_sec=5, poll_interval=0.01)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "failed")
        self.assertIn("failed", res["error"])

    def test_http_error_handling(self):
        """HTTP error responses are handled without raising uncaught exceptions."""
        def mock_transport(req: urllib.request.Request):
            raise urllib.error.HTTPError(
                url=req.full_url,
                code=401,
                msg="Unauthorized",
                hdrs={},
                fp=io.BytesIO(b'{"error": "Invalid API token"}'),
            )

        adapter = CapeSandboxAdapter(
            api_url="https://cape.sandbox.local",
            api_key="bad_token",
            transport=mock_transport,
        )

        res = adapter.submit_file(self.test_file)
        self.assertFalse(res["success"])
        self.assertIn("HTTP 401", res["error"])

    def test_network_connection_error_handling(self):
        """Network unreachable errors (URLError) are caught and returned as structured errors."""
        def mock_transport(req: urllib.request.Request):
            raise urllib.error.URLError("Connection refused [WinError 10061]")

        adapter = CapeSandboxAdapter(
            api_url="https://unreachable-sandbox.test",
            transport=mock_transport,
        )

        res = adapter.submit_file(self.test_file)
        self.assertFalse(res["success"])
        self.assertIn("Connection failed", res["error"])

    def test_none_file_path_validation(self):
        """Passing None or empty string to submit_file returns clean error instead of TypeError."""
        adapter = CapeSandboxAdapter(api_url="https://cape.local")
        res_none = adapter.submit_file(None)
        self.assertFalse(res_none["success"])
        self.assertIn("file_path parameter is required", res_none["error"])

        res_empty = adapter.submit_file("")
        self.assertFalse(res_empty["success"])
        self.assertIn("file_path parameter is required", res_empty["error"])

    def test_alternative_submission_response_formats(self):
        """Verify handling of top-level task_ids list and integer data responses."""
        # Format 1: top-level task_ids
        def mock_transport_1(req: urllib.request.Request):
            url = req.full_url
            if "/api/v2/tasks/create/file/" in url:
                return MockHTTPResponse({"task_ids": [101]})
            elif "/api/v2/tasks/view/101/" in url:
                return MockHTTPResponse({"data": {"status": "reported"}})
            elif "/api/v2/tasks/get/report/101/" in url:
                return MockHTTPResponse({"malscore": 5.0, "network": {}, "behavior": {}, "dropped": [], "signatures": []})
            raise ValueError(url)

        adapter1 = CapeSandboxAdapter(api_url="https://cape.local", transport=mock_transport_1)
        res1 = adapter1.submit_file(self.test_file, timeout_sec=5, poll_interval=0.01)
        self.assertTrue(res1["success"])
        self.assertEqual(res1["task_id"], 101)

        # Format 2: integer data
        def mock_transport_2(req: urllib.request.Request):
            url = req.full_url
            if "/api/v2/tasks/create/file/" in url:
                return MockHTTPResponse({"error": False, "data": 202})
            elif "/api/v2/tasks/view/202/" in url:
                return MockHTTPResponse({"data": {"task": {"status": "completed"}}})
            elif "/api/v2/tasks/get/report/202/" in url:
                return MockHTTPResponse({"malscore": 3.0, "network": {}, "behavior": {}, "dropped": [], "signatures": []})
            raise ValueError(url)

        adapter2 = CapeSandboxAdapter(api_url="https://cape.local", transport=mock_transport_2)
        res2 = adapter2.submit_file(self.test_file, timeout_sec=5, poll_interval=0.01)
        self.assertTrue(res2["success"])
        self.assertEqual(res2["task_id"], 202)

    def test_ssl_verification_toggle(self):
        """Verify that verify_ssl=False and CAPE_VERIFY_SSL env var initializes SSL context."""
        adapter_default = CapeSandboxAdapter(api_url="https://cape.local", verify_ssl=True)
        self.assertTrue(adapter_default.verify_ssl)
        self.assertIsNone(adapter_default._ssl_context)

        adapter_insecure = CapeSandboxAdapter(api_url="https://cape.local", verify_ssl=False)
        self.assertFalse(adapter_insecure.verify_ssl)
        self.assertIsNotNone(adapter_insecure._ssl_context)


if __name__ == "__main__":
    unittest.main()
