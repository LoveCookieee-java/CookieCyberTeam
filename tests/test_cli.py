"""
Unit tests for Standalone Headless CLI (core/cli.py).
Tests scan, triage, contain, and quarantine subcommands.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from core.cli import main


class TestCLI(unittest.TestCase):

    def test_cli_scan_clean_directory(self):
        """Verify CLI scan returns exit code 0 when no critical findings exceed threshold."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            f = Path(tmp_dir) / "clean.py"
            f.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["scan", "--path", str(tmp_dir), "--fail-on", "high"])

            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            self.assertTrue(data["success"])
            self.assertEqual(data["total_findings"], 0)

    def test_cli_scan_vulnerable_file_triggers_gate(self):
        """Verify CLI scan exits with code 1 when findings meet or exceed --fail-on threshold."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            f = Path(tmp_dir) / "vuln.py"
            f.write_text("import os\ndef exec_input(u):\n    os.system('cat ' + u)\n", encoding="utf-8")

            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with redirect_stdout(out_buf), redirect_stderr(err_buf):
                code = main(["scan", "--path", str(f), "--fail-on", "high"])

            self.assertEqual(code, 1)
            data = json.loads(out_buf.getvalue())
            self.assertGreaterEqual(data["total_findings"], 1)
            self.assertIn("[SECURITY GATE FAIL]", err_buf.getvalue())

    def test_cli_scan_sarif_format(self):
        """Verify CLI scan exports valid SARIF format."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            f = Path(tmp_dir) / "app.py"
            f.write_text("import os\ndef run(cmd): os.system(cmd)\n", encoding="utf-8")

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["scan", "--path", str(f), "--format", "sarif"])

            self.assertEqual(code, 0)
            sarif_data = json.loads(buf.getvalue())
            self.assertEqual(sarif_data["version"], "2.1.0")
            self.assertIn("runs", sarif_data)

    def test_cli_triage_command(self):
        """Verify CLI triage analyzes binary artifact and outputs SOC findings."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            bin_file = Path(tmp_dir) / "sample.exe"
            # Mock PE header with URL IOC
            mock_data = b"MZ" + (b"\x00" * 0x3A) + b"\x80\x00\x00\x00" + (b"\x00" * 0x40) + b"PE\x00\x00\x4c\x01" + (b"\x00" * 100) + b"http://malicious-c2.test/download\x00"
            bin_file.write_bytes(mock_data)

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["triage", "--file", str(bin_file)])

            self.assertEqual(code, 0)
            res = json.loads(buf.getvalue())
            self.assertTrue(res["success"])
            self.assertEqual(res["header"]["format"], "PE")
            self.assertGreaterEqual(len(res["iocs"]["urls"]), 1)

    def test_cli_contain_command(self):
        """Verify CLI contain outputs multi-platform firewall rules."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["contain", "--target", "198.51.100.77", "--rule-type", "block", "--port", "9001"])

        self.assertEqual(code, 0)
        res = json.loads(buf.getvalue())
        self.assertTrue(res["success"])
        self.assertIn("windows_netsh", res)
        self.assertIn("linux_iptables", res)
        self.assertIn("9001", res["windows_netsh"])

    def test_cli_quarantine_command(self):
        """Verify CLI quarantine moves file into vault and outputs manifest."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample = Path(tmp_dir) / "bad_dropper.dll"
            sample.write_bytes(b"MALICIOUS_DLL_PAYLOAD_TEST")

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["quarantine", "--file", str(sample)])

            self.assertEqual(code, 0)
            res = json.loads(buf.getvalue())
            self.assertTrue(res["success"])
            self.assertFalse(sample.exists())
            self.assertTrue(Path(res["quarantine_path"]).is_file())

    def test_cli_scan_multiple_positional_paths(self):
        """Verify CLI scan works with positional file paths as passed by pre-commit."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            f1 = Path(tmp_dir) / "f1.py"
            f1.write_text("def ok(): return 1\n", encoding="utf-8")
            f2 = Path(tmp_dir) / "f2.py"
            f2.write_text("def ok2(): return 2\n", encoding="utf-8")

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["scan", str(f1), str(f2)])

            self.assertEqual(code, 0)
            res = json.loads(buf.getvalue())
            self.assertTrue(res["success"])
            self.assertEqual(res["total_findings"], 0)


if __name__ == "__main__":
    unittest.main()
