"""
Unit tests for CookieCyberTeam Supply Chain Analysis Engine (core/sca_scanner.py).
Tests offline OSV database matching, manifest parsing (requirements.txt,
pyproject.toml, poetry.lock), and vulnerability remediation reporting.
"""

import tempfile
import unittest
from pathlib import Path

from core.sca_scanner import SCAScanner, is_version_vulnerable


class TestSCAScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = SCAScanner()

    def test_semver_vulnerability_checker(self):
        """Verify semantic version vulnerability comparison."""
        self.assertTrue(is_version_vulnerable("2.30.0", "2.31.0"))
        self.assertFalse(is_version_vulnerable("2.31.0", "2.31.0"))
        self.assertFalse(is_version_vulnerable("2.32.0", "2.31.0"))
        self.assertTrue(is_version_vulnerable("5.3.1", "5.4"))

    def test_parse_requirements_txt(self):
        """Verify requirements.txt parsing for pinned and unpinned packages."""
        req_content = """
# Production dependencies
requests==2.28.1
urllib3>=1.26.0, <2.0.0
flask == 2.2.2
pyyaml == 5.3.1 # vulnerable
securepkg==1.0.0
"""
        deps = self.scanner.parse_requirements_txt(req_content)
        self.assertEqual(deps.get("requests"), "2.28.1")
        self.assertEqual(deps.get("flask"), "2.2.2")
        self.assertEqual(deps.get("pyyaml"), "5.3.1")
        self.assertEqual(deps.get("securepkg"), "1.0.0")

    def test_parse_pyproject_toml(self):
        """Verify pyproject.toml dependencies extraction."""
        toml_content = """
[project]
name = "demo"
dependencies = [
    "requests>=2.28.0",
    "cryptography==41.0.1",
    "jinja2 == 3.1.2",
]
"""
        deps = self.scanner.parse_pyproject_toml(toml_content)
        self.assertEqual(deps.get("requests"), "2.28.0")
        self.assertEqual(deps.get("cryptography"), "41.0.1")
        self.assertEqual(deps.get("jinja2"), "3.1.2")

    def test_scan_vulnerable_dependencies(self):
        """Verify OSV matching flags known vulnerable libraries."""
        deps = {
            "requests": "2.28.1",  # CVE-2023-32681 (vulnerable below 2.31.0)
            "pyyaml": "5.3.1",     # CVE-2020-14343 (vulnerable below 5.4)
            "clean_library": "1.0.0",
        }
        findings = self.scanner.scan_dependencies(deps, source_file="requirements.txt")
        self.assertEqual(len(findings), 2)

        vuln_pkgs = {f.package_name for f in findings}
        self.assertIn("requests", vuln_pkgs)
        self.assertIn("pyyaml", vuln_pkgs)

        req_vuln = next(f for f in findings if f.package_name == "requests")
        self.assertEqual(req_vuln.cve_id, "CVE-2023-32681")
        self.assertEqual(req_vuln.severity, "High")
        self.assertIn("Upgrade requests to >= 2.31.0", req_vuln.to_dict()["remediation"])

    def test_scan_clean_dependencies(self):
        """Verify clean dependencies produce 0 findings."""
        deps = {
            "requests": "2.31.0",
            "pyyaml": "6.0.1",
            "urllib3": "2.0.7",
        }
        findings = self.scanner.scan_dependencies(deps)
        self.assertEqual(len(findings), 0)

    def test_audit_workspace_full_flow(self):
        """Verify audit_workspace discovers manifests and returns consolidated report."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            (ws / "requirements.txt").write_text("requests==2.28.1\n", encoding="utf-8")
            (ws / "pyproject.toml").write_text("[project]\ndependencies = ['pyyaml==5.3']\n", encoding="utf-8")

            report = self.scanner.audit_workspace(workspace_root=ws)
            self.assertTrue(report["success"])
            self.assertEqual(report["total_dependencies_checked"], 2)
            self.assertEqual(report["vulnerability_count"], 2)
            self.assertEqual(len(report["manifest_files"]), 2)


if __name__ == "__main__":
    unittest.main()
