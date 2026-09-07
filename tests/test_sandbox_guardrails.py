"""
Unit tests for Sandbox Runner & Safe Patching Guardrails.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

from core.guardrails import (
    GuardrailViolation,
    SafePatchManager,
    calculate_diff_stats,
)
from core.sandbox_runner import (
    SandboxRunner,
    build_whitelisted_env,
)
from core.tool_indexer import ToolchainIndexer


class TestSandboxRunner(unittest.TestCase):

    def setUp(self):
        self.runner = SandboxRunner(default_timeout=5)

    def test_environment_whitelisting_strips_secrets(self):
        """Ensure sensitive tokens and keys are completely removed from runner environment."""
        os.environ["AWS_SECRET_ACCESS_KEY"] = "super_secret_aws_key_12345"
        os.environ["OPENAI_API_KEY"] = "sk-test-token-value-67890"
        os.environ["DATABASE_URL"] = "postgres://admin:pass@localhost:5432/db"

        cleaned_env = build_whitelisted_env()
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", cleaned_env)
        self.assertNotIn("OPENAI_API_KEY", cleaned_env)
        self.assertNotIn("DATABASE_URL", cleaned_env)

    def test_forbidden_raw_string_argv(self):
        """Arbitrary raw strings without argv list are strictly rejected."""
        with self.assertRaises(ValueError):
            self.runner.run_command("echo test")  # type: ignore

    def test_safe_command_execution(self):
        """Verify normal safe argv execution."""
        res = self.runner.run_command([sys.executable, "-c", "print('hello from sandbox')"])
        self.assertTrue(res["success"])
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("hello from sandbox", res["stdout"])
        self.assertFalse(res["timed_out"])

    def test_timeout_and_process_termination(self):
        """Test timeout triggers clean termination."""
        # 1-second timeout on a 10-second sleep
        script = "import time; time.sleep(10)"
        res = self.runner.run_command([sys.executable, "-c", script], timeout=1)
        self.assertFalse(res["success"])
        self.assertTrue(res["timed_out"])
        self.assertIn("[Sandbox Timeout]", res["stderr"])

    def test_docker_sandbox_fallback(self):
        """Docker mode returns structured error if daemon is not running."""
        res = self.runner.run_docker(argv=["python", "-V"])
        # Either succeeds if docker daemon running, or returns clear error message
        self.assertIn("argv", res)

    def test_docker_windows_volume_mount_syntax(self):
        """Verify Windows drive letters are converted to /drive/path format to prevent Docker colon errors."""
        res = self.runner.run_docker(argv=["python", "-V"], mount_dir=r"E:\AI\CookieAgent")
        # Check that the volume argument was normalized
        argv_str = " ".join(res["argv"])
        if "-v" in res["argv"]:
            v_idx = res["argv"].index("-v")
            v_spec = res["argv"][v_idx + 1]
            # Must NOT start with "E:"
            self.assertFalse(v_spec.startswith("E:"), f"Invalid Docker volume spec on Windows: {v_spec}")
            self.assertTrue(v_spec.startswith("/e/") or v_spec.startswith("/"), f"Expected posix volume format: {v_spec}")

    def test_docker_env_whitelist_keys(self):
        """Verify Docker and platform runtime environment variables are preserved in whitelist."""
        os.environ["DOCKER_HOST"] = "tcp://localhost:2375"
        os.environ["DOCKER_CONFIG"] = "/etc/docker"
        os.environ["DOCKER_CONTEXT"] = "default"
        os.environ["DOCKER_TLS_VERIFY"] = "1"
        os.environ["DOCKER_CERT_PATH"] = "/certs"

        env = build_whitelisted_env()
        self.assertEqual(env.get("DOCKER_HOST"), "tcp://localhost:2375")
        self.assertEqual(env.get("DOCKER_CONFIG"), "/etc/docker")
        self.assertEqual(env.get("DOCKER_CONTEXT"), "default")
        self.assertEqual(env.get("DOCKER_TLS_VERIFY"), "1")
        self.assertEqual(env.get("DOCKER_CERT_PATH"), "/certs")


class TestSafePatchGuardrails(unittest.TestCase):

    def setUp(self):
        self.manager = SafePatchManager(diff_cap=50)

    def test_diff_stats_calculation(self):
        """Verify unified diff calculation logic."""
        orig = "line 1\nline 2\nline 3\n"
        mod = "line 1\nline 2 modified\nline 3\nline 4 added\n"
        stats = calculate_diff_stats(orig, mod)
        self.assertEqual(stats["added"], 2)
        self.assertEqual(stats["deleted"], 1)
        self.assertEqual(stats["total_changed"], 3)

    def test_diff_cap_gate_rejection(self):
        """Modifications exceeding 50 lines must be rejected."""
        orig = "line\n" * 10
        # 60 additions
        mod = orig + ("new line\n" * 60)
        with self.assertRaises(GuardrailViolation) as ctx:
            self.manager.check_diff_cap(orig, mod)
        self.assertEqual(ctx.exception.gate_name, "Diff Cap Gate")
        self.assertIn("Diff cap exceeded", ctx.exception.message)

    def test_syntax_preflight_gate_rejection(self):
        """Invalid Python syntax must be rejected before saving."""
        orig = "def safe():\n    pass\n"
        broken_syntax = "def broken():\n    this is completely invalid python syntax ::::\n"
        with self.assertRaises(GuardrailViolation) as ctx:
            self.manager.check_syntax_and_zero_regression(orig, broken_syntax)
        self.assertEqual(ctx.exception.gate_name, "Syntax Pre-Flight Gate")

    def test_zero_regression_sast_gate_rejection(self):
        """Patch introducing a new vulnerability must be rejected immediately."""
        orig = (
            "def handle_request(param):\n"
            "    return param.upper()\n"
        )
        # Patch attempts to fix or change code but introduces CWE-78
        regressive_patch = (
            "import os\n"
            "def handle_request(param):\n"
            "    os.system('log ' + param)\n"
            "    return param.upper()\n"
        )
        with self.assertRaises(GuardrailViolation) as ctx:
            self.manager.check_syntax_and_zero_regression(orig, regressive_patch)
        self.assertEqual(ctx.exception.gate_name, "Zero-Regression SAST Gate")
        self.assertIn("CWE-78", ctx.exception.message)

    def test_zero_regression_catches_duplicate_vulnerabilities(self):
        """Zero-Regression SAST Gate must catch newly added vulnerabilities even if that CWE already existed."""
        orig = (
            "import os\n"
            "def run_a(x):\n"
            "    os.system('cat ' + x)\n"
        )
        # Patch keeps first vulnerability and introduces a second CWE-78
        regressive_patch = (
            "import os\n"
            "def run_a(x):\n"
            "    os.system('cat ' + x)\n"
            "def run_b(y):\n"
            "    os.system('echo ' + y)\n"
        )
        with self.assertRaises(GuardrailViolation) as ctx:
            self.manager.check_syntax_and_zero_regression(orig, regressive_patch)
        self.assertEqual(ctx.exception.gate_name, "Zero-Regression SAST Gate")
        self.assertIn("CWE-78", ctx.exception.message)

    def test_find_git_root_and_subdirectory_branch_isolation(self):
        """Verify find_git_root locates repository from a deeply nested subpath."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir) / "my_repo"
            nested = repo_dir / "sub" / "deep"
            nested.mkdir(parents=True)
            (repo_dir / ".git").mkdir()
            subfile = nested / "worker.py"

            from core.guardrails import find_git_root
            found = find_git_root(subfile)
            self.assertEqual(found, repo_dir.resolve())

    def test_env_whitelist_preserves_home_and_systemdrive(self):
        """Verify essential runtime keys like SYSTEMDRIVE or HOME are preserved when present."""
        os.environ["SYSTEMDRIVE"] = "C:"
        cleaned = build_whitelisted_env()
        self.assertIn("SYSTEMDRIVE", cleaned)

    def test_safe_patch_application(self):
        """Verify successful safe patch application."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / "service.py"
            # Original code with SQLi
            orig_code = (
                "import sqlite3\n"
                "def query_user(cur, uid):\n"
                "    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
            )
            tmp_path.write_text(orig_code, encoding="utf-8")

            # Safe fix using parameterized query
            fixed_code = (
                "import sqlite3\n"
                "def query_user(cur, uid):\n"
                "    cur.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"
            )

            res = self.manager.apply_safe_patch(tmp_path, fixed_code, task_id="fix-sqli")
            self.assertTrue(res["success"])
            self.assertEqual(res["regression_stats"]["resolved_findings_count"], 1)

            # Verify on-disk file was updated
            saved_content = tmp_path.read_text(encoding="utf-8")
            self.assertEqual(saved_content, fixed_code)

    def test_residual_findings_reported_on_partial_fix(self):
        """Verify residual_findings in regression_stats details any vulnerabilities that still remain."""
        orig = (
            "import os\n"
            "import sqlite3\n"
            "def run_both(x, uid, cur):\n"
            "    os.system(x)\n"  # CWE-78
            "    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"  # CWE-89
        )
        # Patch fixes SQLi but leaves CWE-78 command injection
        partial_fix = (
            "import os\n"
            "import sqlite3\n"
            "def run_both(x, uid, cur):\n"
            "    os.system(x)\n"  # CWE-78 remains
            "    cur.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"
        )
        stats = self.manager.check_syntax_and_zero_regression(orig, partial_fix)
        self.assertTrue(stats["passed"])
        self.assertEqual(stats["original_findings_count"], 2)
        self.assertEqual(stats["patched_findings_count"], 1)
        self.assertEqual(stats["resolved_findings_count"], 1)
        self.assertIn("residual_findings", stats)
        self.assertEqual(len(stats["residual_findings"]), 1)
        self.assertEqual(stats["residual_findings"][0]["cwe_id"], "CWE-78")

    def test_single_committer_gate_rejection(self):
        """Verify Single-Committer gate rejects commits from workers and only accepts Lead Orchestrator."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / "test.py"
            tmp_path.write_text("x = 1\n", encoding="utf-8")

            # Non-Lead Orchestrator committer must raise GuardrailViolation
            with self.assertRaises(GuardrailViolation) as ctx:
                self.manager.apply_safe_patch(
                    tmp_path,
                    "x = 2\n",
                    task_id="patch-1",
                    committer="Patch Developer",
                )
            self.assertIn("Single-Committer Gate Violation", str(ctx.exception))

            # Default or explicit 'Lead Orchestrator' succeeds
            res = self.manager.apply_safe_patch(
                tmp_path,
                "x = 2\n",
                task_id="patch-1",
                committer="Lead Orchestrator",
            )
            self.assertTrue(res["success"])


class TestToolchainIndexer(unittest.TestCase):

    def setUp(self):
        self.indexer = ToolchainIndexer()

    def test_discover_tools_and_markdown(self):
        """Verify host tools discovery and markdown formatting."""
        data = self.indexer.discover()
        self.assertIn("tools", data)
        self.assertIn("available_tools", data)
        md = self.indexer.to_markdown()
        self.assertIn("# Host Defensive & Reverse Engineering Toolchain Index", md)

    def test_run_diagnostic_tool_whitelist_and_metachar_rejection(self):
        """Verify run_diagnostic_tool rejects unwhitelisted tools and dangerous characters."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_file = Path(tmp_dir) / "sample.bin"
            sample_file.write_bytes(b"HELLO_WORLD_TEST")

            # 1. Reject unwhitelisted tool
            res1 = self.indexer.run_diagnostic_tool("rm", sample_file)
            self.assertFalse(res1["success"])
            self.assertIn("not in allowed diagnostic whitelist", res1["error"])

            # 2. Reject metacharacters in arguments
            res2 = self.indexer.run_diagnostic_tool("strings", sample_file, args=["-n", "4; ls"])
            self.assertFalse(res2["success"])
            self.assertIn("forbidden shell metacharacters", res2["error"])

            # 3. Reject non-existent file
            res3 = self.indexer.run_diagnostic_tool("strings", "non_existent_file.bin")
            self.assertFalse(res3["success"])
            self.assertIn("not found", res3["error"])

    def test_run_diagnostic_tool_metrics(self):
        """Verify run_diagnostic_tool execution returns duration_ms and duration_sec."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_file = Path(tmp_dir) / "sample.bin"
            sample_file.write_bytes(b"HELLO_DIAGNOSTIC_WORLD\x00")

            from unittest.mock import patch
            mock_res = {
                "success": True,
                "exit_code": 0,
                "stdout": "HELLO_DIAGNOSTIC_WORLD",
                "stderr": "",
                "timed_out": False,
                "duration_ms": 150,
                "argv": ["strings", str(sample_file)],
            }
            with patch("shutil.which", return_value="strings"):
                with patch("core.sandbox_runner.SandboxRunner.run_command", return_value=mock_res):
                    res = self.indexer.run_diagnostic_tool("strings", sample_file)
                    self.assertTrue(res["success"])
                    self.assertEqual(res["duration_ms"], 150)
                    self.assertEqual(res["duration_sec"], 0.15)
                    self.assertEqual(res["exit_code"], 0)
                    self.assertFalse(res["timed_out"])


if __name__ == "__main__":
    unittest.main()
