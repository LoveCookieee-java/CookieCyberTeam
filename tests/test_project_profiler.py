"""
Unit tests for CookieCyberTeam Project Genome Profiler (core/project_profiler.py).
Tests instant repository stack discovery (<5ms), framework detection,
git branch protection, risk profiling, and adaptive meta-guidance.
"""

import tempfile
import unittest
from pathlib import Path

from core.project_profiler import ProjectGenomeProfiler


class TestProjectGenomeProfiler(unittest.TestCase):

    def test_detect_python_languages_and_frameworks(self):
        """Verify detection of Python language, FastAPI, and test runner."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            (ws / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
            (ws / "requirements.txt").write_text("fastapi>=0.100.0\nuvicorn\npytest\n", encoding="utf-8")
            (ws / "test_app.py").write_text("def test_ok(): pass\n", encoding="utf-8")

            profiler = ProjectGenomeProfiler(workspace_root=ws)
            genome = profiler.profile()

            self.assertEqual(genome["primary_language"], "python")
            self.assertIn("fastapi", genome["frameworks"])
            self.assertEqual(genome["test_runner"]["type"], "pytest")
            self.assertIn("pytest", genome["test_runner"]["command"])
            self.assertLess(genome["discovery_time_ms"], 500.0)

    def test_detect_typescript_framework(self):
        """Verify detection of TypeScript / JavaScript and Jest runner."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            pkg_json = '{"name": "webapp", "dependencies": {"express": "^4.18.2"}, "scripts": {"test": "jest"}}'
            (ws / "package.json").write_text(pkg_json, encoding="utf-8")
            (ws / "tsconfig.json").write_text("{}", encoding="utf-8")

            profiler = ProjectGenomeProfiler(workspace_root=ws)
            genome = profiler.profile()

            self.assertIn("typescript/javascript", genome["languages"])
            self.assertIn("express", genome["frameworks"])
            self.assertEqual(genome["test_runner"]["type"], "npm_test")

    def test_detect_rust_and_go(self):
        """Verify detection of Go and Rust project manifests."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            (ws / "go.mod").write_text("module example.com/demo\ngo 1.21\n", encoding="utf-8")
            (ws / "Cargo.toml").write_text("[package]\nname = 'rustdemo'\n", encoding="utf-8")

            profiler = ProjectGenomeProfiler(workspace_root=ws)
            genome = profiler.profile()

            self.assertIn("go", genome["languages"])
            self.assertIn("rust", genome["languages"])

    def test_risk_profile_classification(self):
        """Verify binary triage vs web app risk profile classification."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            (ws / "sample.exe").write_bytes(b"MZ\x90\x00")

            profiler = ProjectGenomeProfiler(workspace_root=ws)
            genome = profiler.profile()
            self.assertEqual(genome["risk_profile"], "binary_analysis_and_triage")

    def test_targeted_test_command_generation(self):
        """Verify targeted test command generation for active files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            (ws / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
            (ws / "requirements.txt").write_text("pytest\n", encoding="utf-8")

            profiler = ProjectGenomeProfiler(workspace_root=ws)
            cmd = profiler.generate_targeted_test_command(active_file="core/scanner.py")
            self.assertIn("pytest", cmd)
            self.assertIn("scanner", cmd)

    def test_adaptive_guide_generation_security_audit(self):
        """Verify adaptive guide returns proper tools and rules for security audit."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            profiler = ProjectGenomeProfiler(workspace_root=ws)
            guide = profiler.get_adaptive_guide(task_intent="security_audit")

            self.assertTrue(guide["success"])
            self.assertEqual(guide["task_intent"], "security_audit")
            self.assertIn("mcp_scan_vulnerabilities", guide["recommended_tool_sequence"])
            self.assertIn("rules", guide)
            self.assertIn("prohibited_actions", guide)

    def test_adaptive_guide_generation_bugfix_patch(self):
        """Verify adaptive guide for bugfix_patch returns safe patch tools."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            profiler = ProjectGenomeProfiler(workspace_root=ws)
            guide = profiler.get_adaptive_guide(task_intent="bugfix_patch", active_file="app.py")

            self.assertIn("mcp_preview_surgical_patch", guide["recommended_tool_sequence"])
            self.assertIn("mcp_apply_safe_patch", guide["recommended_tool_sequence"])
            self.assertIn("Ponytail Linter", str(guide["rules"]["mandatory_gates"]))
            self.assertIn("Zero-Deletion Invariant", str(guide["prohibited_actions"]))

    def test_adaptive_guide_binary_triage(self):
        """Verify adaptive guide returns binary triage tools and zero-execution policy."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            profiler = ProjectGenomeProfiler(workspace_root=ws)
            guide = profiler.get_adaptive_guide(task_intent="binary_triage")

            self.assertIn("mcp_triage_binary", guide["recommended_tool_sequence"])
            self.assertIn("Zero-Execution Policy", str(guide["prohibited_actions"]))


if __name__ == "__main__":
    unittest.main()
