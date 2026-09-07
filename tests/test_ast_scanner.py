"""
Unit tests for Pure-Python AST SAST Scanner & Semgrep Adapter.
"""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from core.ast_scanner import ASTScanner, calculate_shannon_entropy
from core.semgrep_adapter import SemgrepAdapter


class TestASTScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = ASTScanner()

    def test_shannon_entropy_calculation(self):
        """Test entropy calculation logic."""
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        self.assertEqual(calculate_shannon_entropy("aaaa"), 0.0)
        # Random token has high entropy >= 3.5
        token = "4f8a2b1c9e0d3f7a6b5c4d3e2f1a0b9c"
        entropy = calculate_shannon_entropy(token)
        self.assertGreaterEqual(entropy, 3.0)

    def test_cwe78_command_injection(self):
        """Verify CWE-78 detection across os.system and subprocess shell=True."""
        code = (
            "import os\n"
            "import subprocess\n"
            "def exec_user_input(arg):\n"
            "    os.system('ls ' + arg)\n"
            "    subprocess.run('echo hello', shell=True)\n"
            "    subprocess.call(['safe', 'binary'])\n"  # Safe
        )
        findings = self.scanner.scan_code(code)
        cwe78 = [f for f in findings if f.cwe_id == "CWE-78"]
        self.assertEqual(len(cwe78), 2)
        self.assertEqual(cwe78[0].severity, "Critical")

    def test_cwe78_import_aliasing(self):
        """Verify alias resolution for CWE-78 detection."""
        code = (
            "import os as host_os\n"
            "from os import system as sys_call\n"
            "import subprocess as sp\n"
            "def run_aliases(x):\n"
            "    host_os.system(x)\n"
            "    sys_call(x)\n"
            "    sp.Popen(x, shell=True)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe78 = [f for f in findings if f.cwe_id == "CWE-78"]
        self.assertEqual(len(cwe78), 3)

    def test_cwe89_sql_injection_local_taint(self):
        """Verify CWE-89 detection for direct f-strings and tainted query variables."""
        code = (
            "import sqlite3\n"
            "conn = sqlite3.connect(':memory:')\n"
            "cur = conn.cursor()\n"
            "def get_user(uid, uname):\n"
            "    # Direct f-string injection\n"
            "    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
            "    # Tainted variable concatenation\n"
            "    sql = 'SELECT * FROM users WHERE name = ' + uname\n"
            "    cur.execute(sql)\n"
            "    # Safe parameterized query\n"
            "    cur.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertEqual(len(cwe89), 2)
        self.assertEqual(cwe89[0].severity, "Critical")

    def test_cwe95_code_eval_injection(self):
        """Verify CWE-95 eval/exec injection detection."""
        code = (
            "def dynamic_calc(expr):\n"
            "    return eval(expr)\n"
            "def run_script(blob):\n"
            "    exec(blob)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe95 = [f for f in findings if f.cwe_id == "CWE-95"]
        self.assertEqual(len(cwe95), 2)

    def test_cwe502_insecure_deserialization(self):
        """Verify CWE-502 pickle and yaml detection."""
        code = (
            "import pickle\n"
            "import yaml\n"
            "def load_state(payload):\n"
            "    data1 = pickle.loads(payload)\n"
            "    data2 = yaml.load(payload)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe502 = [f for f in findings if f.cwe_id == "CWE-502"]
        self.assertEqual(len(cwe502), 2)

    def test_cwe798_hardcoded_credentials(self):
        """Verify CWE-798 secret detection using Shannon Entropy & keywords."""
        code = (
            "API_KEY = 'ghp_0123456789abcdefghijklmnopqrstuvwxyz'\n"
            "user_secret_token = '9f8b7c6d5e4a3b2c1d0f9e8d7c6b5a4'\n"
            "welcome_message = 'Welcome to the secure portal!'\n"
        )
        findings = self.scanner.scan_code(code)
        cwe798 = [f for f in findings if f.cwe_id == "CWE-798"]
        self.assertEqual(len(cwe798), 2)

    def test_cwe295_disabled_ssl_verification(self):
        """Verify CWE-295 verify=False detection."""
        code = (
            "import requests\n"
            "import ssl\n"
            "def fetch_data():\n"
            "    requests.get('https://example.com', verify=False)\n"
            "    ctx = ssl._create_unverified_context()\n"
            "    requests.get('https://example.com', verify=True)\n"  # Safe
        )
        findings = self.scanner.scan_code(code)
        cwe295 = [f for f in findings if f.cwe_id == "CWE-295"]
        self.assertEqual(len(cwe295), 2)

    def test_delta_scanning_filter(self):
        """Verify that Delta Scanning filters out findings outside modified lines."""
        code = (
            "import os\n"                                # Line 1
            "def func1(x):\n"                            # Line 2
            "    os.system(x)\n"                         # Line 3 (CWE-78)
            "def func2(y):\n"                            # Line 4
            "    return eval(y)\n"                       # Line 5 (CWE-95)
        )
        # Scan full code
        all_findings = self.scanner.scan_code(code)
        self.assertEqual(len(all_findings), 2)

        # Delta scan only Line 3 (modified lines: {3})
        delta_findings = self.scanner.scan_code(code, modified_lines={3})
        self.assertEqual(len(delta_findings), 1)
        self.assertEqual(delta_findings[0].line_number, 3)
        self.assertEqual(delta_findings[0].cwe_id, "CWE-78")

    def test_semgrep_adapter_graceful_fallback(self):
        """Verify Semgrep adapter handles missing binary or non-zero runs gracefully."""
        adapter = SemgrepAdapter(executable_path="non_existent_semgrep_bin")
        self.assertFalse(adapter.is_available())
        res = adapter.scan(Path("server.py"))
        self.assertFalse(res["available"])
        self.assertFalse(res["success"])
        self.assertIn("not installed", res["error"])

    def test_annassign_type_annotated_secret_and_sqli(self):
        """Verify CWE-798 and CWE-89 detection in type-annotated assignments (AnnAssign)."""
        code = (
            "API_KEY: str = 'ghp_0123456789abcdefghijklmnopqrstuvwxyz'\n"
            "query: str = f'SELECT * FROM users WHERE id = {uid}'\n"
            "cur.execute(query)\n"
        )
        findings = self.scanner.scan_code(code)
        cwes = {f.cwe_id for f in findings}
        self.assertIn("CWE-798", cwes)
        self.assertIn("CWE-89", cwes)

    def test_format_string_sqli_and_executemany(self):
        """Verify CWE-89 detection using .format() and cursor.executemany/executescript."""
        code = (
            "cur.execute('SELECT * FROM users WHERE id = {}'.format(user_id))\n"
            "sql = 'SELECT * FROM users WHERE name = {}'.format(user_name)\n"
            "cur.executemany(sql, [(1,)])\n"
            "cur.executescript('DROP TABLE users; SELECT * FROM logs WHERE tag = ' + tag)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertGreaterEqual(len(cwe89), 3)

    def test_subprocess_getoutput_and_yaml_unsafe_load(self):
        """Verify CWE-78 subprocess.getoutput and CWE-502 yaml.unsafe_load detection."""
        code = (
            "import subprocess\n"
            "import yaml\n"
            "out = subprocess.getoutput('cat ' + file_name)\n"
            "data = yaml.unsafe_load(raw_data)\n"
        )
        findings = self.scanner.scan_code(code)
        cwes = {f.cwe_id for f in findings}
        self.assertIn("CWE-78", cwes)
        self.assertIn("CWE-502", cwes)

    def test_untracked_file_delta_scan(self):
        """Verify untracked files scan 100% of lines (modified_lines=None) instead of returning 0 findings."""
        code = "import os\ndef run(x):\n    os.system(x)\n"
        with patch("subprocess.run") as mock_sub:
            # git ls-files --error-unmatch returns 1 (untracked)
            mock_sub.return_value = MagicMock(returncode=1, stdout="")
            with patch("pathlib.Path.read_text", return_value=code):
                with patch("pathlib.Path.is_file", return_value=True):
                    with patch("pathlib.Path.exists", return_value=True):
                        findings = self.scanner.scan_git_diff("untracked_module.py")
                        cwe78 = [f for f in findings if f.cwe_id == "CWE-78"]
                        self.assertEqual(len(cwe78), 1)

    def test_taint_cleared_on_reassignment(self):
        """Verify reassigning tainted variable to a static constant clears taint, while alias reassign propagates it."""
        code = (
            "import sqlite3\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "def test_taint(user_input):\n"
            "    q = 'SELECT * FROM users WHERE id = ' + user_input\n"
            "    q = 'SELECT * FROM users WHERE id = 1'\n"  # Cleared taint
            "    cur.execute(q)\n"  # Safe, should NOT flag
            "    q2 = 'SELECT * FROM users WHERE name = ' + user_input\n"
            "    alias = q2\n"  # Propagated taint
            "    cur.execute(alias)\n"  # Vulnerable, should flag
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertEqual(len(cwe89), 1)
        self.assertEqual(cwe89[0].line_number, 9)

    def test_static_string_binop_not_flagged_sqli(self):
        """Verify concatenating static string literals does not produce false positive CWE-89."""
        code = (
            "import sqlite3\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "def static_query():\n"
            "    q = 'SELECT id, name ' + 'FROM users ' + 'WHERE active = 1'\n"
            "    cur.execute(q)\n"
            "    cur.execute('SELECT count(*) ' + 'FROM logs')\n"
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertEqual(len(cwe89), 0)

    def test_walrus_named_expr_sqli_and_secrets(self):
        """Verify walrus operator := detection for hardcoded secrets and SQL injection."""
        code = (
            "import sqlite3\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "def check_session(uid):\n"
            "    if (secret := 'ghp_0123456789abcdefghijklmnopqrstuvwxyz'):\n"
            "        pass\n"
            "    if cur.execute(q := f'SELECT * FROM users WHERE id = {uid}'):\n"
            "        return True\n"
        )
        findings = self.scanner.scan_code(code)
        cwes = {f.cwe_id for f in findings}
        self.assertIn("CWE-798", cwes)
        self.assertIn("CWE-89", cwes)

    def test_sqli_taint_propagation_with_concat_and_kwargs(self):
        """Verify taint is preserved across concatenations without SQL keywords and with kwargs."""
        code = (
            "import sqlite3\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "def query_user(uid):\n"
            "    q = f'SELECT * FROM users WHERE id = {uid}'\n"
            "    q = q + ' AND active = 1'\n"
            "    cur.execute(operation=q)\n"
            "    cur.execute(q + ' LIMIT 5')\n"
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertEqual(len(cwe89), 2)


if __name__ == "__main__":
    unittest.main()
