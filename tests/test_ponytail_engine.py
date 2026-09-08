"""
Unit tests for the Ponytail Minimalist Engineering Engine.
Tests DietrichGebert/ponytail integration:
- 7-Rung Decision Ladder
- Polyglot stdlib and native platform equivalents
- AST YAGNI detectors (stateless utility classes, shallow wrappers, dead code)
- NPM dependency auditing (native JS/TS alternatives)
- Ponytail intensity modes (ultra, full, lite, off) and diff caps
- Gate 1.5 Ponytail Linter integration in SafePatchManager
- MCP Tools: mcp_ponytail_review, mcp_ponytail_audit, mcp_ponytail_debt
- MCP Resource: mcp://rules/ponytail-ladder
- MCP Prompts: mcp_prompt_ponytail_review, mcp_prompt_ponytail_minimalist
- Project Genome Profiler Ponytail playbooks and recommendations
"""

import ast
import json
import tempfile
import unittest
from pathlib import Path

from core.platform_native import (
    PYTHON_STDLIB_EQUIVALENTS,
    JAVASCRIPT_NATIVE_EQUIVALENTS,
    is_stateless_utility_class,
    is_shallow_wrapper_function,
    audit_ast_yagni,
    audit_npm_dependencies,
    get_stdlib_equivalent,
    get_js_native_equivalent,
)
from core.config import (
    CookieCyberConfig,
    PONYTAIL_DIFF_LIMITS,
    PONYTAIL_MODES,
)
from core.guardrails import (
    SafePatchManager,
    GuardrailViolation,
    check_ponytail_linter,
)
from core.project_profiler import ProjectGenomeProfiler
from server import CookieCyberMCPServer


class TestPlatformNativeEquivalents(unittest.TestCase):
    """Test standard library and native equivalents mapping."""

    def test_python_stdlib_equivalents_coverage(self):
        """Verify common 3rd-party packages have stdlib mappings."""
        self.assertIn("requests", PYTHON_STDLIB_EQUIVALENTS)
        self.assertIn("pytz", PYTHON_STDLIB_EQUIVALENTS)
        self.assertIn("simplejson", PYTHON_STDLIB_EQUIVALENTS)
        self.assertIn("mock", PYTHON_STDLIB_EQUIVALENTS)
        self.assertIn("six", PYTHON_STDLIB_EQUIVALENTS)
        self.assertIn("attrs", PYTHON_STDLIB_EQUIVALENTS)
        self.assertIn("pathlib2", PYTHON_STDLIB_EQUIVALENTS)

        equiv = get_stdlib_equivalent("requests")
        self.assertEqual(equiv, "urllib.request")

    def test_javascript_native_equivalents_coverage(self):
        """Verify common npm packages have native JS/TS mappings."""
        self.assertIn("lodash", JAVASCRIPT_NATIVE_EQUIVALENTS)
        self.assertIn("underscore", JAVASCRIPT_NATIVE_EQUIVALENTS)
        self.assertIn("moment", JAVASCRIPT_NATIVE_EQUIVALENTS)
        self.assertIn("axios", JAVASCRIPT_NATIVE_EQUIVALENTS)
        self.assertIn("chalk", JAVASCRIPT_NATIVE_EQUIVALENTS)
        self.assertIn("rimraf", JAVASCRIPT_NATIVE_EQUIVALENTS)
        self.assertIn("mkdirp", JAVASCRIPT_NATIVE_EQUIVALENTS)

        equiv = get_js_native_equivalent("lodash")
        self.assertIsNotNone(equiv)
        self.assertIn("Array.prototype", equiv)


class TestAstYagniDetectors(unittest.TestCase):
    """Test AST-level YAGNI analysis functions."""

    def test_stateless_utility_class_detection(self):
        """Detect classes that only have static/class methods and no instance state."""
        code_static = """
class MathUtils:
    @staticmethod
    def add(a, b):
        return a + b
    @classmethod
    def multiply(cls, a, b):
        return a * b
"""
        tree = ast.parse(code_static)
        class_node = tree.body[0]
        self.assertTrue(is_stateless_utility_class(class_node))

    def test_stateful_class_not_flagged(self):
        """Class with __init__ or instance state must not be flagged."""
        code_stateful = """
class Counter:
    def __init__(self):
        self.count = 0
    def increment(self):
        self.count += 1
        return self.count
"""
        tree = ast.parse(code_stateful)
        class_node = tree.body[0]
        self.assertFalse(is_stateless_utility_class(class_node))

    def test_empty_or_pass_class_not_flagged(self):
        """Classes with pass or no methods (e.g. exception classes) not flagged."""
        code_empty = "class CustomError(Exception): pass"
        tree = ast.parse(code_empty)
        class_node = tree.body[0]
        self.assertFalse(is_stateless_utility_class(class_node))

    def test_shallow_wrapper_function_detection(self):
        """Detect one-liner functions that trivially forward to another function."""
        code_wrapper = """
def fetch_json(url):
    return requests.get(url)
"""
        tree = ast.parse(code_wrapper)
        func_node = tree.body[0]
        self.assertTrue(is_shallow_wrapper_function(func_node))

    def test_meaningful_function_not_shallow_wrapper(self):
        """Functions with control flow, multiple statements, or transformations are not shallow wrappers."""
        code_meaningful = """
def fetch_user(user_id):
    if not user_id:
        raise ValueError("Invalid user_id")
    url = f"https://api.internal/users/{user_id}"
    return requests.get(url).json()
"""
        tree = ast.parse(code_meaningful)
        func_node = tree.body[0]
        self.assertFalse(is_shallow_wrapper_function(func_node))

    def test_shallow_wrapper_variadic_args(self):
        """Detect shallow wrapper functions that forward *args and **kwargs."""
        code_variadic = """
def forward(*args, **kwargs):
    return delegate(*args, **kwargs)
"""
        tree = ast.parse(code_variadic)
        func_node = tree.body[0]
        self.assertEqual(is_shallow_wrapper_function(func_node), "delegate")

    def test_shallow_wrapper_attribute_target_and_same_name(self):
        """Detect shallow wrapper functions that delegate to module or attribute with same name."""
        code_attr = """
def dumps(obj):
    return json.dumps(obj)
"""
        tree = ast.parse(code_attr)
        func_node = tree.body[0]
        self.assertEqual(is_shallow_wrapper_function(func_node), "json.dumps")

    def test_recursive_function_not_shallow_wrapper(self):
        """Self-recursive functions must not be flagged as external wrappers."""
        code_recurse = """
def factorial(n):
    return factorial(n)
"""
        tree = ast.parse(code_recurse)
        func_node = tree.body[0]
        self.assertIsNone(is_shallow_wrapper_function(func_node))

    def test_audit_ast_yagni_full_report(self):
        """Test comprehensive audit_ast_yagni analysis on AST tree."""
        code = """
class TextHelper:
    @staticmethod
    def trim(s):
        return s.strip()

def call_trim(s):
    return trim(s)
"""
        tree = ast.parse(code)
        findings = audit_ast_yagni(tree)
        self.assertGreater(len(findings), 0)

        # Check for yagni finding on stateless utility class
        yagni_findings = [f for f in findings if f["tag"] == "yagni:"]
        self.assertTrue(any("TextHelper" in f["message"] for f in yagni_findings))

        # Check for shrink finding on shallow wrapper
        shrink_findings = [f for f in findings if f["tag"] == "shrink:"]
        self.assertTrue(any("call_trim" in f["message"] for f in shrink_findings))

    def test_check_ponytail_linter_respects_all_exports(self):
        """Symbols listed in __all__ are recognized as public and not flagged as dead code in Gate 1.5."""
        orig = ""
        patched = """
__all__ = ["public_api"]

def public_api():
    return "ok"
"""
        # Should not raise GuardrailViolation
        check_ponytail_linter(orig, patched, file_path="api.py")


class TestNpmDependencyAuditing(unittest.TestCase):
    """Test auditing of npm dependencies in package.json."""

    def test_audit_npm_dependencies_detects_unneeded(self):
        """Audit package.json containing lodash, axios, chalk."""
        package_json = {
            "name": "test-app",
            "dependencies": {
                "lodash": "^4.17.21",
                "axios": "^1.6.0",
                "react": "^18.0.0"
            },
            "devDependencies": {
                "rimraf": "^5.0.0",
                "typescript": "^5.0.0"
            }
        }
        findings = audit_npm_dependencies(package_json)
        self.assertEqual(len(findings), 3)  # lodash, axios, rimraf
        pkgs = {f["package"] for f in findings}
        self.assertIn("lodash", pkgs)
        self.assertIn("axios", pkgs)
        self.assertIn("rimraf", pkgs)
        self.assertNotIn("react", pkgs)
        self.assertNotIn("typescript", pkgs)


class TestPonytailConfigAndModes(unittest.TestCase):
    """Test Ponytail configuration and intensity mode definitions."""

    def test_diff_limits_per_mode(self):
        """Verify diff caps match the specifications."""
        self.assertEqual(PONYTAIL_DIFF_LIMITS["ultra"], (25, 150))
        self.assertEqual(PONYTAIL_DIFF_LIMITS["full"], (50, 250))
        self.assertEqual(PONYTAIL_DIFF_LIMITS["lite"], (80, 400))
        self.assertEqual(PONYTAIL_DIFF_LIMITS["off"], ("free", "free"))

    def test_config_initialization_with_mode(self):
        """Test CookieCyberConfig initializes diff caps according to ponytail_mode."""
        cfg_ultra = CookieCyberConfig(ponytail_mode="ultra")
        self.assertEqual(cfg_ultra.diff_cap_limit, 25)
        self.assertEqual(cfg_ultra.new_file_cap_limit, 150)

        cfg_lite = CookieCyberConfig(ponytail_mode="lite")
        self.assertEqual(cfg_lite.diff_cap_limit, 80)
        self.assertEqual(cfg_lite.new_file_cap_limit, 400)

        cfg_off = CookieCyberConfig(ponytail_mode="off")
        self.assertEqual(cfg_off.diff_cap_limit, "free")
        self.assertEqual(cfg_off.new_file_cap_limit, "free")
        self.assertFalse(cfg_off.enable_ponytail_linter)

    def test_config_to_dict_includes_ponytail(self):
        """Verify to_dict exposes ponytail attributes."""
        cfg = CookieCyberConfig(ponytail_mode="full", enable_ponytail_linter=True)
        d = cfg.to_dict()
        self.assertEqual(d["ponytail_mode"], "full")
        self.assertTrue(d["enable_ponytail_linter"])


class TestGate15PonytailGuardrails(unittest.TestCase):
    """Test Gate 1.5 Ponytail Linter enforcement within SafePatchManager."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_safe_patch_enforces_ultra_diff_cap(self):
        """Ultra mode (<=25 lines) rejects patches that exceed 25 lines."""
        cfg = CookieCyberConfig(ponytail_mode="ultra")
        mgr = SafePatchManager(config=cfg)

        orig_code = "print('hello')\n"
        # Generate 28 lines of changes
        patched_code = "\n".join([f"line_{i} = {i}" for i in range(28)]) + "\n"

        target_file = self.repo_path / "app.py"
        target_file.write_text(orig_code, encoding="utf-8")

        with self.assertRaises(GuardrailViolation) as ctx:
            mgr.apply_safe_patch(
                target_file_path=str(target_file),
                patched_content=patched_code,
                repo_path=str(self.repo_path),
            )
        self.assertIn("Diff Cap Gate Violation", str(ctx.exception))
        self.assertIn("limit: 25", str(ctx.exception))

    def test_safe_patch_rejects_unlisted_stdlib_replaceable_dependency(self):
        """Gate 1.5 rejects patches importing packages with stdlib equivalents."""
        cfg = CookieCyberConfig(ponytail_mode="full")
        mgr = SafePatchManager(config=cfg)

        target_file = self.repo_path / "service.py"
        target_file.write_text("def work(): pass\n", encoding="utf-8")

        patched_code = (
            "import simplejson\n"
            "def work():\n"
            "    return simplejson.dumps({'status': 'ok'})\n"
        )

        with self.assertRaises(GuardrailViolation) as ctx:
            mgr.apply_safe_patch(
                target_file_path=str(target_file),
                patched_content=patched_code,
                repo_path=str(self.repo_path),
            )
        self.assertIn("Gate 1.5 Ponytail Linter Violation", str(ctx.exception))
        self.assertIn("simplejson", str(ctx.exception))
        self.assertIn("json", str(ctx.exception))

    def test_safe_patch_passes_valid_clean_patch(self):
        """Clean patch with stdlib compliance and within diff cap passes all gates."""
        cfg = CookieCyberConfig(ponytail_mode="full")
        mgr = SafePatchManager(config=cfg)

        target_file = self.repo_path / "util.py"
        orig_code = "def add(a, b):\n    return a - b\n"
        target_file.write_text(orig_code, encoding="utf-8")

        # Fix subtraction to addition
        patched_code = "def add(a, b):\n    return a + b\n"

        result = mgr.apply_safe_patch(
            target_file_path=str(target_file),
            patched_content=patched_code,
            repo_path=str(self.repo_path),
        )
        self.assertTrue(result["success"])
        self.assertEqual(target_file.read_text(encoding="utf-8"), patched_code)

    def test_package_json_delta_allows_preexisting_dependencies(self):
        """Modifying an existing package.json containing unneeded dependencies does not block if none newly added."""
        orig_pj = json.dumps({
            "name": "my-app",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.21"}
        })
        patched_pj = json.dumps({
            "name": "my-app",
            "version": "1.0.1",
            "dependencies": {"lodash": "^4.17.21"},
            "scripts": {"build": "tsc"}
        })
        # Should not raise GuardrailViolation in full mode
        check_ponytail_linter(orig_pj, patched_pj, file_path="package.json", mode="full")

    def test_package_json_delta_rejects_new_unneeded_dependencies(self):
        """Adding a new unneeded dependency to an existing package.json is rejected."""
        orig_pj = json.dumps({
            "name": "my-app",
            "dependencies": {"react": "^18.0.0"}
        })
        patched_pj = json.dumps({
            "name": "my-app",
            "dependencies": {"react": "^18.0.0", "lodash": "^4.17.21"}
        })
        with self.assertRaises(GuardrailViolation):
            check_ponytail_linter(orig_pj, patched_pj, file_path="package.json", mode="full")

    def test_js_ts_scoped_package_resolution(self):
        """Scoped packages like @scope/pkg are properly extracted and checked against package.json."""
        orig_code = ""
        patched_code = "import { helper } from '@company/utils/helper';\n"
        pkg_json = self.repo_path / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"@company/utils": "^1.0.0"}}), encoding="utf-8")

        # In full mode, since @company/utils is in package.json, should pass without violation
        check_ponytail_linter(orig_code, patched_code, file_path="src/index.ts", repo_path=self.repo_path, mode="full")


class TestPonytailMCPInterfaces(unittest.TestCase):
    """Test Ponytail tools, resources, and prompts via MCP Server."""

    def setUp(self):
        self.server = CookieCyberMCPServer(db_path=":memory:")

    def tearDown(self):
        self.server.close()

    def test_mcp_ponytail_review_tool(self):
        """Verify mcp_ponytail_review detects YAGNI violations and formats output."""
        code_to_review = (
            "import requests\n"
            "class StringHelper:\n"
            "    @staticmethod\n"
            "    def strip_text(t):\n"
            "        return t.strip()\n"
        )
        res = self.server.handle_request({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "mcp_ponytail_review",
                "arguments": {"code": code_to_review, "mode": "full"},
            },
        })
        self.assertNotIn("error", res)
        text_payload = res["result"]["content"][0]["text"]
        data = json.loads(text_payload)
        self.assertTrue(data["success"])
        self.assertGreater(data["total_findings"], 0)
        self.assertIn("findings", data)
        self.assertIn("potential_loc_savings", data)

    def test_mcp_ponytail_audit_tool(self):
        """Verify mcp_ponytail_audit audits workspace files."""
        res = self.server.handle_request({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "mcp_ponytail_audit",
                "arguments": {"path": "core", "mode": "full"},
            },
        })
        self.assertNotIn("error", res)
        data = json.loads(res["result"]["content"][0]["text"])
        self.assertTrue(data["success"])
        self.assertIn("files_audited", data)
        self.assertIn("findings", data)

    def test_mcp_ponytail_debt_tool(self):
        """Verify mcp_ponytail_debt finds ponytail comments."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            f1 = Path(tmp_dir) / "sample.py"
            f1.write_text("# ponytail: Replace custom parser with json.loads\ndef parse(): pass\n", encoding="utf-8")
            f2 = Path(tmp_dir) / "sample.js"
            f2.write_text("// ponytail: Replace lodash debounce with native setTimeout\n", encoding="utf-8")

            res = self.server.handle_request({
                "jsonrpc": "2.0",
                "id": 103,
                "method": "tools/call",
                "params": {
                    "name": "mcp_ponytail_debt",
                    "arguments": {"path": tmp_dir},
                },
            })
            self.assertNotIn("error", res)
            data = json.loads(res["result"]["content"][0]["text"])
            self.assertTrue(data["success"])
            self.assertEqual(data["total_debt_items"], 2)
            self.assertEqual(len(data["debt_items"]), 2)

    def test_mcp_ponytail_resource(self):
        """Verify mcp://rules/ponytail-ladder resource returns markdown ladder."""
        res = self.server.handle_request({
            "jsonrpc": "2.0",
            "id": 104,
            "method": "resources/read",
            "params": {"uri": "mcp://rules/ponytail-ladder"},
        })
        self.assertNotIn("error", res)
        contents = res["result"]["contents"][0]
        self.assertEqual(contents["uri"], "mcp://rules/ponytail-ladder")
        self.assertIn("Decision Ladder", contents["text"])
        self.assertIn("urllib.request", contents["text"])
        self.assertIn("Intensity Modes", contents["text"])

    def test_mcp_ponytail_prompts(self):
        """Verify Ponytail review and minimalist prompts."""
        p_rev = self.server.handle_request({
            "jsonrpc": "2.0",
            "id": 105,
            "method": "prompts/get",
            "params": {
                "name": "mcp_prompt_ponytail_review",
                "arguments": {"target_file": "core/helper.py"},
            },
        })
        self.assertNotIn("error", p_rev)
        text_rev = p_rev["result"]["messages"][0]["content"]["text"]
        self.assertIn("Lazy Senior Dev", text_rev)
        self.assertIn("core/helper.py", text_rev)

        p_min = self.server.handle_request({
            "jsonrpc": "2.0",
            "id": 106,
            "method": "prompts/get",
            "params": {
                "name": "mcp_prompt_ponytail_minimalist",
                "arguments": {"task_description": "Implement caching", "target_file": "cache.py", "mode": "ultra"},
            },
        })
        self.assertNotIn("error", p_min)
        text_min = p_min["result"]["messages"][0]["content"]["text"]
        self.assertIn("Shortest working diff wins", text_min)
        self.assertIn("ultra", text_min)

    def test_tool_ponytail_review_does_not_flag_called_helper_as_dead_code(self):
        """Functions called by other functions within the same file (refs > 0) must not be flagged as dead code."""
        code = """
__all__ = ["main"]

def helper():
    return 42

def unused_func():
    return 99

def main():
    return helper()
"""
        res = self.server.tool_ponytail_review({"code": code, "file_path": "app.py", "mode": "full"})
        dead_names = [f["name"] for f in res.get("findings", []) if f.get("type") == "potential_dead_code"]
        self.assertNotIn("helper", dead_names)
        self.assertNotIn("main", dead_names)
        self.assertIn("unused_func", dead_names)


class TestProjectGenomeProfilerPonytail(unittest.TestCase):
    """Test Project Genome Profiler Ponytail playbooks and recommendations."""

    def test_profiler_playbooks_include_simplification(self):
        profiler = ProjectGenomeProfiler()
        guide_simple = profiler.get_adaptive_guide(task_intent="code_simplification")
        self.assertIn("mcp_ponytail_review", guide_simple["recommended_tool_sequence"])

        guide_arch = profiler.get_adaptive_guide(task_intent="architecture_audit")
        self.assertIn("mcp_ponytail_audit", guide_arch["recommended_tool_sequence"])
        self.assertIn("mcp_ponytail_debt", guide_arch["recommended_tool_sequence"])

    def test_profiler_adaptive_guide_with_ponytail(self):
        profiler = ProjectGenomeProfiler()
        guide = profiler.get_adaptive_guide(task_intent="code_exploration")
        self.assertTrue(any("Gate 1.5 (Ponytail Linter)" in g for g in guide["active_guardrails"]))

    def test_adaptive_guide_with_new_task_intents_via_mcp(self):
        """Verify mcp_adaptive_guide tool handles code_simplification and architecture_audit intents."""
        server = CookieCyberMCPServer(db_path=":memory:")
        try:
            res_simp = server.handle_request({
                "jsonrpc": "2.0",
                "id": 110,
                "method": "tools/call",
                "params": {
                    "name": "mcp_adaptive_guide",
                    "arguments": {"task_intent": "code_simplification"},
                },
            })
            self.assertNotIn("error", res_simp)
            data_simp = json.loads(res_simp["result"]["content"][0]["text"])
            self.assertIn("mcp_ponytail_review", data_simp["playbook"])

            res_arch = server.handle_request({
                "jsonrpc": "2.0",
                "id": 111,
                "method": "tools/call",
                "params": {
                    "name": "mcp_adaptive_guide",
                    "arguments": {"task_intent": "architecture_audit"},
                },
            })
            self.assertNotIn("error", res_arch)
            data_arch = json.loads(res_arch["result"]["content"][0]["text"])
            self.assertIn("mcp_ponytail_audit", data_arch["playbook"])
        finally:
            server.close()

    def test_ponytail_audit_case_insensitive_exclusion_and_max_files(self):
        """Verify case-insensitive exclusion and max_files safeguard in audit."""
        server = CookieCyberMCPServer(db_path=":memory:")
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                root = Path(tmp_dir)
                vendor = root / "Vendor"
                vendor.mkdir()
                (vendor / "bad.py").write_text("import requests\n", encoding="utf-8")
                (root / "good1.py").write_text("x = 1\n", encoding="utf-8")
                (root / "good2.py").write_text("y = 2\n", encoding="utf-8")

                res = server.tool_ponytail_audit({"path": tmp_dir, "max_files": 1})
                self.assertTrue(res["success"])
                self.assertLessEqual(res["files_audited"], 1)
                # Ensure Vendor directory was completely skipped
                audited = res["ranked_files"]
                self.assertFalse(any("vendor" in item["file"].lower() for item in audited))
        finally:
            server.close()

    def test_ponytail_debt_case_insensitive_exclusion(self):
        """Verify case-insensitive folder exclusion in debt scanner."""
        server = CookieCyberMCPServer(db_path=":memory:")
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                root = Path(tmp_dir)
                nm = root / "Node_Modules"
                nm.mkdir()
                (nm / "ignored.js").write_text("// ponytail: in node_modules\n", encoding="utf-8")
                (root / "kept.py").write_text("# ponytail: in root\n", encoding="utf-8")

                res = server.tool_ponytail_debt({"path": tmp_dir, "max_files": 10})
                self.assertTrue(res["success"])
                self.assertEqual(res["total_debt_items"], 1)
                self.assertEqual(res["debt_items"][0]["description"], "in root")
        finally:
            server.close()

    def test_committer_token_capacity_bounded_growth(self):
        """Verify SafePatchManager caps active committer tokens at 500 to prevent memory leaks."""
        manager = SafePatchManager(enforce_token=True)
        for _ in range(505):
            manager.generate_committer_token("Lead Orchestrator")
        self.assertLessEqual(len(manager._committer_tokens), 500)
        self.assertEqual(manager._tokens_issued, 505)


if __name__ == "__main__":
    unittest.main()
