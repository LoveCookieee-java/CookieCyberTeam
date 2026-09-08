"""
Unit tests for Repository Configuration Engine (core/config.py).
Tests .cookiecyber.toml and cookiecyber.json parsing, fallback handling,
and integration with SafePatchManager and ASTScanner.
"""

import json
import tempfile
import unittest
from pathlib import Path

from core.ast_scanner import ASTScanner
from core.config import (
    CookieCyberConfig,
    DEFAULT_DIFF_CAP_LIMIT,
    DEFAULT_NEW_FILE_CAP_LIMIT,
    DEFAULT_RESTRICTED_BRANCHES,
    DEFAULT_EXCLUDE_DIRS,
    DEFAULT_SHANNON_ENTROPY_THRESHOLD,
    DEFAULT_CVSS_VERSION,
)
from core.guardrails import SafePatchManager, GuardrailViolation


class TestCookieCyberConfig(unittest.TestCase):

    def test_default_config_values(self):
        """Verify standard default configuration values."""
        cfg = CookieCyberConfig()
        self.assertEqual(cfg.diff_cap_limit, 50)
        self.assertEqual(cfg.new_file_cap_limit, 250)
        self.assertIn("main", cfg.restricted_branches)
        self.assertIn("master", cfg.restricted_branches)
        self.assertIn("vendor", cfg.exclude_dirs)
        self.assertIn("node_modules", cfg.exclude_dirs)
        self.assertEqual(cfg.shannon_entropy_threshold, 7.5)
        self.assertEqual(cfg.cvss_version, "3.1")

    def test_load_from_toml_file(self):
        """Verify parsing configuration from .cookiecyber.toml."""
        toml_content = """
# CookieCyberTeam Repository Configuration
diff_cap_limit = 80
new_file_cap_limit = 400
restricted_branches = ["main", "staging", "deploy"]
exclude_dirs = ["vendor", "third_party", "external"]
shannon_entropy_threshold = 7.8
cvss_version = "4.0"
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            toml_path = Path(tmp_dir) / ".cookiecyber.toml"
            toml_path.write_text(toml_content, encoding="utf-8")

            cfg = CookieCyberConfig.load_from_file(toml_path)
            self.assertEqual(cfg.diff_cap_limit, 80)
            self.assertEqual(cfg.new_file_cap_limit, 400)
            self.assertEqual(cfg.restricted_branches, {"main", "staging", "deploy"})
            self.assertIn("third_party", cfg.exclude_dirs)
            self.assertEqual(cfg.shannon_entropy_threshold, 7.8)
            self.assertEqual(cfg.cvss_version, "4.0")
            self.assertEqual(cfg.config_source, str(toml_path.resolve()))

    def test_load_from_json_file(self):
        """Verify parsing configuration from cookiecyber.json."""
        json_data = {
            "diff_cap_limit": 60,
            "new_file_cap_limit": 300,
            "restricted_branches": ["production", "release-candidate"],
            "exclude_dirs": ["deps", "build_out"],
            "shannon_entropy_threshold": 7.2,
            "cvss_version": "3.1",
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = Path(tmp_dir) / "cookiecyber.json"
            json_path.write_text(json.dumps(json_data), encoding="utf-8")

            cfg = CookieCyberConfig.load_from_file(json_path)
            self.assertEqual(cfg.diff_cap_limit, 60)
            self.assertEqual(cfg.new_file_cap_limit, 300)
            self.assertIn("production", cfg.restricted_branches)
            self.assertIn("deps", cfg.exclude_dirs)
            self.assertEqual(cfg.shannon_entropy_threshold, 7.2)

    def test_load_from_repo_hierarchy(self):
        """Verify automatic discovery of .cookiecyber.toml from nested child directory."""
        with tempfile.TemporaryDirectory() as repo_dir:
            repo_path = Path(repo_dir)
            toml_path = repo_path / ".cookiecyber.toml"
            toml_path.write_text("diff_cap_limit = 45\ncvss_version = '4.0'\n", encoding="utf-8")

            child_dir = repo_path / "src" / "deeply" / "nested"
            child_dir.mkdir(parents=True, exist_ok=True)

            cfg = CookieCyberConfig.load_from_repo(child_dir)
            self.assertEqual(cfg.diff_cap_limit, 45)
            self.assertEqual(cfg.cvss_version, "4.0")

    def test_safepatch_manager_config_integration(self):
        """Verify SafePatchManager honors custom diff cap and branch configuration."""
        custom_cfg = CookieCyberConfig(
            diff_cap_limit=20,
            restricted_branches={"trunk", "golden"},
        )
        manager = SafePatchManager(config=custom_cfg)
        self.assertEqual(manager.diff_cap, 20)
        self.assertIn("trunk", manager.restricted_branches)

        # Diff cap violation with custom limit (20)
        orig_code = "a = 1\n"
        mod_code = "".join([f"var_{i} = {i}\n" for i in range(25)])

        with self.assertRaises(GuardrailViolation) as ctx:
            manager.check_diff_cap(orig_code, mod_code, is_new_file=False)
        self.assertIn("Diff Cap Gate", ctx.exception.gate_name)

    def test_ast_scanner_config_integration(self):
        """Verify ASTScanner honors exclude_dirs and cvss_version from configuration."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            vendor_dir = root / "vendor"
            vendor_dir.mkdir(parents=True, exist_ok=True)
            vendor_file = vendor_dir / "insecure.py"
            vendor_file.write_text("import os\ndef run(x): os.system(x)\n", encoding="utf-8")

            src_dir = root / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            src_file = src_dir / "app.py"
            src_file.write_text("import os\ndef run(x): os.system(x)\n", encoding="utf-8")

            custom_cfg = CookieCyberConfig(
                exclude_dirs={"vendor"},
                cvss_version="4.0",
            )
            scanner = ASTScanner(config=custom_cfg)

            # 1. vendor file must be excluded
            self.assertTrue(scanner.is_path_excluded(vendor_file))
            vendor_findings = scanner.scan_file(vendor_file)
            self.assertEqual(len(vendor_findings), 0)

            # 2. Directory scan must exclude vendor/
            all_findings = scanner.scan_directory(root)
            found_files = {Path(f.file_path).name for f in all_findings}
            self.assertIn("app.py", found_files)
            self.assertNotIn("insecure.py", found_files)

            # 3. CVSS version 4.0 used
            if all_findings:
                self.assertIn("CVSS:4.0", all_findings[0].cvss_vector)

    def test_parse_simple_toml_trailing_comments(self):
        """Verify trailing comments on strings and arrays do not corrupt parsed values."""
        toml_content = """
# Config with comments
diff_cap_limit = 42 # maximum diff lines
cvss_version = "4.0" # modern CVSS standard
restricted_branches = ["main", "prod"] # production targets
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir) / ".cookiecyber.toml"
            p.write_text(toml_content, encoding="utf-8")
            cfg = CookieCyberConfig.load_from_file(p)
            self.assertEqual(cfg.diff_cap_limit, 42)
            self.assertEqual(cfg.cvss_version, "4.0")
            self.assertEqual(cfg.restricted_branches, {"main", "prod"})

    def test_load_from_repo_with_file_path(self):
        """Verify load_from_repo correctly resolves parent when passed a file path."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir)
            cfg_file = repo / ".cookiecyber.toml"
            cfg_file.write_text("diff_cap_limit = 35\n", encoding="utf-8")
            src_file = repo / "main.py"
            src_file.write_text("print('hello')", encoding="utf-8")

            cfg = CookieCyberConfig.load_from_repo(src_file)
            self.assertEqual(cfg.diff_cap_limit, 35)

    def test_tool_cookiecyber_section_support(self):
        """Verify pyproject-style [tool.cookiecyber] sections are parsed."""
        toml_content = """
[tool.cookiecyber]
diff_cap_limit = 25
cvss_version = "4.0"
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir) / ".cookiecyber.toml"
            p.write_text(toml_content, encoding="utf-8")
            cfg = CookieCyberConfig.load_from_file(p)
            self.assertEqual(cfg.diff_cap_limit, 25)
            self.assertEqual(cfg.cvss_version, "4.0")

    def test_parse_toml_array_with_embedded_commas(self):
        """Verify TOML array parsing handles string literals with embedded commas correctly."""
        toml_content = """
exclude_dirs = ["vendor,old", "node_modules", 'third, party, libs']
restricted_branches = ["main", "feature/comma,branch"]
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir) / ".cookiecyber.toml"
            p.write_text(toml_content, encoding="utf-8")
            cfg = CookieCyberConfig.load_from_file(p)
            self.assertIn("vendor,old", cfg.exclude_dirs)
            self.assertIn("node_modules", cfg.exclude_dirs)
            self.assertIn("third, party, libs", cfg.exclude_dirs)
            self.assertIn("feature/comma,branch", cfg.restricted_branches)

    def test_parse_toml_multiline_array(self):
        """Verify TOML array split across multiple lines is parsed cleanly."""
        toml_content = """
exclude_dirs = [
    "vendor",
    "node_modules",
    "custom_cache"
]
restricted_branches = [
    "main",
    "prod",
]
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir) / ".cookiecyber.toml"
            p.write_text(toml_content, encoding="utf-8")
            cfg = CookieCyberConfig.load_from_file(p)
            self.assertIn("vendor", cfg.exclude_dirs)
            self.assertIn("node_modules", cfg.exclude_dirs)
            self.assertIn("custom_cache", cfg.exclude_dirs)
            self.assertIn("main", cfg.restricted_branches)
            self.assertIn("prod", cfg.restricted_branches)

    def test_diff_cap_free_and_unlimited_modes(self):
        """Verify 'free', 'unlimited', 0, and negative numbers permit unlimited lines."""
        # 1. Direct model normalization
        cfg_free = CookieCyberConfig(diff_cap_limit="free", new_file_cap_limit="free")
        self.assertEqual(cfg_free.diff_cap_limit, "free")
        self.assertEqual(cfg_free.new_file_cap_limit, "free")

        cfg_unlimited = CookieCyberConfig(diff_cap_limit="unlimited", new_file_cap_limit="unlimited")
        self.assertEqual(cfg_unlimited.diff_cap_limit, "free")
        self.assertEqual(cfg_unlimited.new_file_cap_limit, "free")

        cfg_zero = CookieCyberConfig(diff_cap_limit=0, new_file_cap_limit=-1)
        self.assertEqual(cfg_zero.diff_cap_limit, "free")
        self.assertEqual(cfg_zero.new_file_cap_limit, "free")

        # 2. TOML file with free mode
        toml_content = """
diff_cap_limit = "free"
new_file_cap_limit = "free"
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir) / ".cookiecyber.toml"
            p.write_text(toml_content, encoding="utf-8")
            cfg_toml = CookieCyberConfig.load_from_file(p)
            self.assertEqual(cfg_toml.diff_cap_limit, "free")
            self.assertEqual(cfg_toml.new_file_cap_limit, "free")

        # 3. SafePatchManager with free mode allows arbitrary diff lengths
        manager_free = SafePatchManager(diff_cap="free", new_file_cap="free")
        orig_code = "line = 1\n"
        huge_patch = "line = 1\n" + "".join([f"mod_{i} = {i}\n" for i in range(500)])
        stats = manager_free.check_diff_cap(orig_code, huge_patch, is_new_file=False)
        self.assertEqual(stats["effective_limit"], "free")
        self.assertEqual(stats["total_changed"], 500)

        # 4. Custom raised limit (e.g. 200 lines) allows 150 lines without error
        manager_raised = SafePatchManager(diff_cap=200)
        raised_patch = "line = 1\n" + "".join([f"mod_{i} = {i}\n" for i in range(150)])
        stats_raised = manager_raised.check_diff_cap(orig_code, raised_patch, is_new_file=False)
        self.assertEqual(stats_raised["effective_limit"], 200)
        self.assertEqual(stats_raised["total_changed"], 150)


if __name__ == "__main__":
    unittest.main()

