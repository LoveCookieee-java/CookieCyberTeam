"""
Unit tests for Pure-Python AST SAST Scanner & Semgrep Adapter.
"""

import ast
import tempfile
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

    def test_cwe22_path_traversal_and_zip_slip(self):
        """Verify CWE-22 detection in open(), os.path.join(), and archive extractall()."""
        code = (
            "import os\n"
            "import zipfile\n"
            "import tarfile\n"
            "def read_file(user_input):\n"
            "    open('/var/data/' + user_input)\n"             # Line 5: Path concat in open
            "    open(f'/var/data/{user_input}')\n"             # Line 6: f-string in open
            "    os.path.join('/safe/dir', user_input)\n"       # Line 7: os.path.join with user_input
            "    open('/safe/dir/fixed.txt')\n"                 # Safe
            "def unpack_archives(zname, tname):\n"
            "    with zipfile.ZipFile(zname) as zf:\n"
            "        zf.extractall('/tmp/dest')\n"              # Line 11: Zip Slip (no filter)
            "    with tarfile.open(tname) as tf:\n"
            "        tf.extractall('/tmp/dest')\n"              # Line 13: Tar Slip (no filter)
            "def safe_unpack(zname):\n"
            "    with zipfile.ZipFile(zname) as zf:\n"
            "        zf.extractall('/tmp', members=[])\n"       # Safe
        )
        findings = self.scanner.scan_code(code)
        cwe22 = [f for f in findings if f.cwe_id == "CWE-22"]
        self.assertEqual(len(cwe22), 5)
        for f in cwe22:
            self.assertEqual(f.severity, "Critical")
            self.assertEqual(f.cwe_id, "CWE-22")

    def test_cwe327_and_cwe328_broken_cryptography(self):
        """Verify CWE-328 (weak hashes md5/sha1) and CWE-327 (DES, AES ECB)."""
        code = (
            "import hashlib\n"
            "from Crypto.Cipher import AES, DES\n"
            "def test_crypto(key, data):\n"
            "    h1 = hashlib.md5(data).hexdigest()\n"                  # Line 4: CWE-328
            "    h2 = hashlib.sha1(data).digest()\n"                    # Line 5: CWE-328
            "    cipher_des = DES.new(key)\n"                           # Line 6: CWE-327
            "    cipher_ecb = AES.new(key, mode=AES.MODE_ECB)\n"        # Line 7: CWE-327
            "    safe_h = hashlib.sha256(data).digest()\n"              # Safe
            "    safe_aes = AES.new(key, mode=AES.MODE_GCM)\n"          # Safe
        )
        findings = self.scanner.scan_code(code)
        cwe328 = [f for f in findings if f.cwe_id == "CWE-328"]
        cwe327 = [f for f in findings if f.cwe_id == "CWE-327"]
        self.assertEqual(len(cwe328), 2)
        self.assertEqual(len(cwe327), 2)

    def test_cwe377_insecure_temporary_file(self):
        """Verify CWE-377 detection for tempfile.mktemp()."""
        code = (
            "import tempfile\n"
            "def make_temp():\n"
            "    path = tempfile.mktemp()\n"                         # Line 3: CWE-377
            "    with tempfile.NamedTemporaryFile() as safe_temp:\n" # Safe
            "        pass\n"
        )
        findings = self.scanner.scan_code(code)
        cwe377 = [f for f in findings if f.cwe_id == "CWE-377"]
        self.assertEqual(len(cwe377), 1)
        self.assertEqual(cwe377[0].line_number, 3)

    def test_cwe352_csrf_protection_disabled(self):
        """Verify CWE-352 detection for @csrf_exempt routes in Django/Flask."""
        code = (
            "def csrf_exempt(func): return func\n"
            "@csrf_exempt\n"
            "def insecure_payment_endpoint(request):\n"
            "    return {'status': 'processed'}\n"
            "def safe_payment_endpoint(request):\n"
            "    return {'status': 'safe'}\n"
        )
        findings = self.scanner.scan_code(code)
        cwe352 = [f for f in findings if f.cwe_id == "CWE-352"]
        self.assertEqual(len(cwe352), 1)
        self.assertIn("insecure_payment_endpoint", cwe352[0].description)

    def test_ai_ml_insecure_deserialization(self):
        """Verify CWE-502 detection for PyTorch, Joblib, NumPy allow_pickle, Dill, Cloudpickle."""
        code = (
            "import torch\n"
            "import joblib\n"
            "import numpy as np\n"
            "import dill\n"
            "import cloudpickle\n"
            "def load_models(raw_bytes):\n"
            "    m1 = torch.load('weights.pt')\n"                       # Insecure: omits weights_only
            "    m2 = torch.load('weights.pt', weights_only=False)\n"   # Insecure: weights_only=False
            "    m3 = torch.load('weights.pt', weights_only=True)\n"    # Safe
            "    j1 = joblib.load('classifier.joblib')\n"               # Insecure: joblib uses pickle
            "    arr1 = np.load('data.npy', allow_pickle=True)\n"       # Insecure: allow_pickle=True
            "    arr2 = np.load('data.npy')\n"                          # Safe: allow_pickle=False default
            "    d1 = dill.loads(raw_bytes)\n"                          # Insecure: dill
            "    c1 = cloudpickle.loads(raw_bytes)\n"                   # Insecure: cloudpickle
        )
        findings = self.scanner.scan_code(code)
        cwe502 = [f for f in findings if f.cwe_id == "CWE-502"]
        # Expect 5 insecure AI/ML calls: 2 torch, 1 joblib, 1 np allow_pickle, 1 dill, 1 cloudpickle = 6
        self.assertEqual(len(cwe502), 6)

    def test_scope_aware_lexical_taint_isolation(self):
        """Verify that lexical scope stack isolates function taints without cross-function bleeding."""
        code = (
            "import sqlite3\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "def func_a(tainted_input):\n"
            "    sql = 'SELECT * FROM users WHERE id = ' + tainted_input\n"
            "    cur.execute(sql)\n"                                # Line 5: Vulnerable (CWE-89)
            "def func_b():\n"
            "    sql = 'SELECT * FROM users WHERE id = 1'\n"        # Local safe constant
            "    cur.execute(sql)\n"                                # Line 8: Safe (MUST NOT flag!)
            "def func_c(unrelated):\n"
            "    x = 'safe'\n"
            "    cur.execute('SELECT count(*) FROM users')\n"       # Safe
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertEqual(len(cwe89), 1)
        self.assertEqual(cwe89[0].line_number, 5)

    def test_sarif_v210_export(self):
        """Verify OASIS SARIF v2.1.0 generation conformance."""
        code = (
            "import os\n"
            "def run_cmd(user_input):\n"
            "    os.system(user_input)\n"
        )
        findings = self.scanner.scan_code(code, file_path="app/views.py")
        self.assertEqual(len(findings), 1)

        sarif = self.scanner.to_sarif(findings)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0.json", sarif["$schema"])
        self.assertEqual(len(sarif["runs"]), 1)

        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "CookieCyberTeam-AST-Scanner")
        self.assertEqual(len(run["results"]), 1)

        result = run["results"][0]
        self.assertEqual(result["ruleId"], "CWE-78")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app/views.py")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 3)

    def test_cross_taint_isolation_sql_and_path(self):
        """Verify that SQL taint and path taint are strictly isolated and do not cross-trigger sinks."""
        code = (
            "import sqlite3, os\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "def test_isolation(user_input, uid):\n"
            "    path = os.path.join('/tmp', user_input)\n"       # CWE-22 on os.path.join
            "    cur.execute(path)\n"                              # Should NOT be flagged as CWE-89!
            "    sql = f'SELECT * FROM users WHERE id = {uid}'\n"  # SQL taint
            "    open(sql)\n"                                      # Should NOT be flagged as CWE-22!
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        cwe22 = [f for f in findings if f.cwe_id == "CWE-22"]
        # cur.execute(path) must NOT be flagged as SQL injection
        self.assertEqual(len(cwe89), 0)
        # open(sql) must NOT be flagged as Path traversal (only line 4 os.path.join is flagged)
        self.assertEqual(len(cwe22), 1)
        self.assertEqual(cwe22[0].line_number, 4)

    def test_path_taint_variable_propagation_and_pathlib(self):
        """Verify dynamic path variable assignment propagation and pathlib file reads."""
        code = (
            "from pathlib import Path\n"
            "def process_files(user_input):\n"
            "    p1 = '/var/data/' + user_input\n"
            "    open(p1)\n"                                      # Line 4: CWE-22 via concat
            "    p2 = f'/var/data/{user_input}'\n"
            "    open(p2)\n"                                      # Line 6: CWE-22 via f-string
            "    Path('/var/' + user_input).read_text()\n"        # Line 7: CWE-22 via Path.read_text
            "    safe_p = '/var/data/fixed.txt'\n"
            "    open(safe_p)\n"                                  # Line 9: Safe
        )
        findings = self.scanner.scan_code(code)
        cwe22 = [f for f in findings if f.cwe_id == "CWE-22"]
        self.assertEqual(len(cwe22), 3)
        lines = {f.line_number for f in cwe22}
        self.assertEqual(lines, {4, 6, 7})

    def test_global_and_nonlocal_taint_propagation(self):
        """Verify global and nonlocal declarations propagate taint across lexical scopes."""
        code = (
            "import sqlite3\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "query_var = 'safe'\n"
            "def pollute(user_input):\n"
            "    global query_var\n"
            "    query_var = f'SELECT * FROM users WHERE id = {user_input}'\n"
            "def execute_query():\n"
            "    cur.execute(query_var)\n"                        # Line 8: CWE-89 via global taint
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertEqual(len(cwe89), 1)
        self.assertEqual(cwe89[0].line_number, 8)

    def test_flask_csrf_exempt_decorator(self):
        """Verify @csrf.exempt (Flask-WTF) is detected for CWE-352."""
        code = (
            "class DummyCSRF:\n"
            "    def exempt(self, f): return f\n"
            "csrf = DummyCSRF()\n"
            "@csrf.exempt\n"
            "def api_webhook(request):\n"
            "    return {'status': 'ok'}\n"
        )
        findings = self.scanner.scan_code(code)
        cwe352 = [f for f in findings if f.cwe_id == "CWE-352"]
        self.assertEqual(len(cwe352), 1)

    def test_numpy_load_positional_allow_pickle(self):
        """Verify numpy.load with positional allow_pickle=True is detected for CWE-502."""
        code = (
            "import numpy as np\n"
            "def load_arr(f):\n"
            "    return np.load(f, None, True)\n"                 # Positional allow_pickle=True
        )
        findings = self.scanner.scan_code(code)
        cwe502 = [f for f in findings if f.cwe_id == "CWE-502"]
        self.assertEqual(len(cwe502), 1)

    def test_hashlib_new_keyword_name(self):
        """Verify hashlib.new(name='md5') keyword argument is detected for CWE-328."""
        code = (
            "import hashlib\n"
            "def get_hash(data):\n"
            "    return hashlib.new(name='md5', data=data)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe328 = [f for f in findings if f.cwe_id == "CWE-328"]
        self.assertEqual(len(cwe328), 1)

    def test_sarif_safe_with_none_values(self):
        """Verify to_sarif handles findings with None file_path or None line_number gracefully."""
        dummy_finding = {
            "cwe_id": "CWE-78",
            "title": "Command Injection",
            "description": "test",
            "file_path": None,
            "line_number": None,
            "severity": "High",
            "cvss_score": 8.0,
            "cvss_vector": "",
            "code_snippet": "os.system(x)",
            "remediation": "safe",
        }
        sarif = self.scanner.to_sarif([dummy_finding])
        self.assertEqual(sarif["version"], "2.1.0")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "<unknown>")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 1)


    def test_closure_nested_scope_taint_propagation(self):
        """Verify closures in nested functions correctly inherit outer tainted variables."""
        code = (
            "import sqlite3\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "def outer_service(user_id):\n"
            "    query = f'SELECT * FROM accounts WHERE id = {user_id}'\n"
            "    def inner_runner():\n"
            "        cur.execute(query)\n"                         # Line 6: Vulnerable (closed-over taint)
            "    inner_runner()\n"
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertEqual(len(cwe89), 1)
        self.assertEqual(cwe89[0].line_number, 6)

    def test_tuple_unpacking_taint_and_credential(self):
        """Verify tuple/list unpacking propagates taint and flags credentials."""
        code = (
            "import sqlite3\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "def handle_data(uid):\n"
            "    q1, q2 = f'SELECT * FROM users WHERE id = {uid}', 'SELECT * FROM users'\n"
            "    cur.execute(q1)\n"                                # Line 5: Vulnerable
            "    cur.execute(q2)\n"                                # Line 6: Safe
            "    api_key, label = 'ghp_0123456789abcdefghijklmnopqrstuvwxyz', 'normal_val'\n" # Line 7: CWE-798
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        cwe798 = [f for f in findings if f.cwe_id == "CWE-798"]
        self.assertEqual(len(cwe89), 1)
        self.assertEqual(cwe89[0].line_number, 5)
        self.assertEqual(len(cwe798), 1)
        self.assertEqual(cwe798[0].line_number, 7)

    def test_pathlib_div_path_traversal(self):
        """Verify open(Path(...) / user_input) path traversal detection."""
        code = (
            "from pathlib import Path\n"
            "def load_custom_file(user_input):\n"
            "    open(Path('/data') / user_input)\n"              # Line 3: CWE-22
        )
        findings = self.scanner.scan_code(code)
        cwe22 = [f for f in findings if f.cwe_id == "CWE-22"]
        self.assertEqual(len(cwe22), 1)
        self.assertEqual(cwe22[0].line_number, 3)


    def test_numeric_division_not_treated_as_path_taint(self):
        """Numeric division must never be treated as a path expression or taint variables."""
        code = (
            "def compute_stats(total, count):\n"
            "    ratio = total / count\n"
            "    factor = 100 / 2\n"
            "    return ratio, factor\n"
        )
        findings = self.scanner.scan_code(code)
        cwe22 = [f for f in findings if f.cwe_id == "CWE-22"]
        self.assertEqual(len(cwe22), 0)

    def test_pathlib_assigned_variable_div_path_traversal(self):
        """Path variable assigned Path(...) followed by / user_input must flag CWE-22."""
        code = (
            "from pathlib import Path\n"
            "def load_file(user_input):\n"
            "    base_dir = Path('/var/data')\n"
            "    full_path = base_dir / user_input\n"
            "    open(full_path)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe22 = [f for f in findings if f.cwe_id == "CWE-22"]
        self.assertEqual(len(cwe22), 1)
        self.assertEqual(cwe22[0].line_number, 5)

    def test_starred_assignment_unpacking_taint(self):
        """Verify starred targets in assignments unpack and track taint properly."""
        code = (
            "import sqlite3\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "def process_batch(uid):\n"
            "    first, *rest = 'safe', f'SELECT * FROM users WHERE id = {uid}'\n"
            "    cur.execute(rest[0])\n"
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertEqual(len(cwe89), 1)
        self.assertEqual(cwe89[0].line_number, 5)

    def test_nonlocal_parameter_binding_across_nested_scopes(self):
        """Verify nonlocal variable binds to outer parameter even if not previously assigned."""
        code = (
            "import sqlite3\n"
            "cur = sqlite3.connect(':memory:').cursor()\n"
            "def outer(query):\n"
            "    def middle():\n"
            "        def inner(user_input):\n"
            "            nonlocal query\n"
            "            query = f'SELECT * FROM users WHERE id = {user_input}'\n"
            "        inner(123)\n"
            "        cur.execute(query)\n"
            "    middle()\n"
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertEqual(len(cwe89), 1)
        self.assertEqual(cwe89[0].line_number, 9)

    def test_sarif_rule_index_and_sanitized_name(self):
        """Verify SARIF results contain ruleIndex and rules have sanitized PascalCase names."""
        code = "import os\ndef run(c): os.system(c)\n"
        findings = self.scanner.scan_code(code, file_path="run.py")
        sarif = self.scanner.to_sarif(findings)
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertRegex(rule["name"], r"^[A-Za-z0-9_]+$")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["ruleIndex"], 0)

    @unittest.skipUnless(hasattr(ast, "Match"), "ast.Match requires Python 3.10+")
    def test_match_case_scope_hoisting_nonlocal(self):
        """Verify global and nonlocal declarations inside pattern matching blocks are discovered."""
        code = (
            "import os\n"
            "def outer(action):\n"
            "    cmd = 'echo safe'\n"
            "    def inner(val):\n"
            "        match val:\n"
            "            case 1:\n"
            "                nonlocal cmd\n"
            "                cmd = f'rm {val}'\n"
            "            case _:\n"
            "                pass\n"
            "        os.system(cmd)\n"
            "    inner(1)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe78 = [f for f in findings if f.cwe_id == "CWE-78"]
        self.assertEqual(len(cwe78), 1)
        self.assertEqual(cwe78[0].line_number, 11)

    def test_scan_file_pep263_coding_cookie_and_non_utf8(self):
        """Verify scan_file parses Python files with PEP 263 Latin-1 coding cookie correctly."""
        code_bytes = (
            b"# -*- coding: latin-1 -*-\n"
            b"# Comment with Latin-1 character: \xe9\n"
            b"import os\n"
            b"def run(cmd):\n"
            b"    os.system(cmd)\n"
        )
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tf:
            tf.write(code_bytes)
            tf_path = Path(tf.name)
        try:
            findings = self.scanner.scan_file(tf_path)
            cwe78 = [f for f in findings if f.cwe_id == "CWE-78"]
            self.assertEqual(len(cwe78), 1)
        finally:
            try:
                tf_path.unlink()
            except Exception:
                pass


    def test_cwe611_xxe_etree_parse(self):
        """Verify CWE-611 XML External Entity (XXE) is flagged for xml.etree.ElementTree.parse."""
        code = "import xml.etree.ElementTree as ET\ntree = ET.parse('user_supplied.xml')\n"
        findings = self.scanner.scan_code(code)
        cwe611 = [f for f in findings if f.cwe_id == "CWE-611"]
        self.assertEqual(len(cwe611), 1)
        self.assertIn("XXE", cwe611[0].title)

    def test_cwe611_xxe_minidom_parse(self):
        """Verify CWE-611 is flagged for xml.dom.minidom.parse."""
        code = "import xml.dom.minidom\ndoc = xml.dom.minidom.parse('data.xml')\n"
        findings = self.scanner.scan_code(code)
        cwe611 = [f for f in findings if f.cwe_id == "CWE-611"]
        self.assertEqual(len(cwe611), 1)

    def test_cwe611_xxe_defusedxml_not_flagged(self):
        """Verify defusedxml parser is recognized as safe and NOT flagged."""
        code = "import defusedxml.ElementTree as ET\ntree = ET.parse('safe.xml')\n"
        findings = self.scanner.scan_code(code)
        cwe611 = [f for f in findings if f.cwe_id == "CWE-611"]
        self.assertEqual(len(cwe611), 0)

    def test_cwe918_ssrf_requests_get_tainted_url(self):
        """Verify CWE-918 SSRF is flagged when requests.get uses dynamic formatted url."""
        code = (
            "import requests\n"
            "def fetch(domain):\n"
            "    url = f'https://{domain}/api'\n"
            "    return requests.get(url)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe918 = [f for f in findings if f.cwe_id == "CWE-918"]
        self.assertEqual(len(cwe918), 1)
        self.assertIn("SSRF", cwe918[0].title)

    def test_cwe918_ssrf_urllib_request_urlopen(self):
        """Verify CWE-918 is flagged when urllib.request.urlopen calls dynamic destination."""
        code = (
            "import urllib.request\n"
            "def retrieve(path):\n"
            "    target = 'http://internal.service/' + path\n"
            "    return urllib.request.urlopen(target)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe918 = [f for f in findings if f.cwe_id == "CWE-918"]
        self.assertEqual(len(cwe918), 1)

    def test_cwe918_ssrf_metadata_ip_flagged(self):
        """Verify hardcoded cloud metadata IP (169.254.169.254) is flagged as SSRF."""
        code = "import requests\nresp = requests.get('http://169.254.169.254/latest/meta-data/')\n"
        findings = self.scanner.scan_code(code)
        cwe918 = [f for f in findings if f.cwe_id == "CWE-918"]
        self.assertEqual(len(cwe918), 1)
        self.assertIn("cloud metadata", cwe918[0].description)

    def test_cwe918_ssrf_static_url_not_flagged(self):
        """Verify requests to benign static URLs are NOT flagged as SSRF."""
        code = "import requests\nresp = requests.get('https://api.github.com/zen')\n"
        findings = self.scanner.scan_code(code)
        cwe918 = [f for f in findings if f.cwe_id == "CWE-918"]
        self.assertEqual(len(cwe918), 0)

    def test_cwe1336_jinja2_template_injection(self):
        """Verify CWE-1336 SSTI is flagged when jinja2.Template is initialized with dynamic string."""
        code = (
            "import jinja2\n"
            "def render(user_input):\n"
            "    tmpl = 'Hello ' + user_input\n"
            "    return jinja2.Template(tmpl).render()\n"
        )
        findings = self.scanner.scan_code(code)
        cwe1336 = [f for f in findings if f.cwe_id == "CWE-1336"]
        self.assertEqual(len(cwe1336), 1)
        self.assertIn("SSTI", cwe1336[0].title)

    def test_cwe1336_flask_render_template_string(self):
        """Verify flask.render_template_string is flagged when given non-constant template."""
        code = (
            "import flask\n"
            "def show(content):\n"
            "    return flask.render_template_string(content)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe1336 = [f for f in findings if f.cwe_id == "CWE-1336"]
        self.assertEqual(len(cwe1336), 1)

    def test_cwe943_nosql_injection_mongodb(self):
        """Verify CWE-943 NoSQL injection is flagged for dynamic $where query in collection.find."""
        code = (
            "def get_user(db, name):\n"
            "    return db.users.find({'$where': 'this.name == \"' + name + '\"'})\n"
        )
        findings = self.scanner.scan_code(code)
        cwe943 = [f for f in findings if f.cwe_id == "CWE-943"]
        self.assertEqual(len(cwe943), 1)
        self.assertIn("NoSQL", cwe943[0].title)

    def test_cwe400_redos_nested_quantifiers(self):
        """Verify CWE-400 ReDoS is flagged for catastrophic backtracking regex pattern."""
        code = "import re\npattern = re.compile(r'^(a+)+$')\n"
        findings = self.scanner.scan_code(code)
        cwe400 = [f for f in findings if f.cwe_id == "CWE-400"]
        self.assertEqual(len(cwe400), 1)
        self.assertIn("ReDoS", cwe400[0].title)

    def test_cwe400_redos_safe_regex_not_flagged(self):
        """Verify linear safe regex patterns are NOT flagged as ReDoS."""
        code = "import re\npattern = re.compile(r'^[a-zA-Z0-9_-]+$')\n"
        findings = self.scanner.scan_code(code)
        cwe400 = [f for f in findings if f.cwe_id == "CWE-400"]
        self.assertEqual(len(cwe400), 0)

    def test_call_graph_inter_procedural_sink_detection(self):
        """Verify Call Graph Pass 1 identifies sink contracts and flags tainted argument flow."""
        code = (
            "import sqlite3\n"
            "def db_exec(query_str):\n"
            "    conn = sqlite3.connect(':memory:')\n"
            "    conn.execute(query_str)\n"
            "\n"
            "def handler(user_id):\n"
            "    raw_sql = 'SELECT * FROM users WHERE id = ' + user_id\n"
            "    db_exec(raw_sql)\n"
        )
        findings = self.scanner.scan_code(code)
        inter_proc = [f for f in findings if "Inter-Procedural" in f.title]
        self.assertGreaterEqual(len(inter_proc), 1)
        self.assertEqual(inter_proc[0].cwe_id, "CWE-89")

    def test_cwe89_instance_field_taint_propagation(self):
        """Verify instance attribute self.sql_query receives and propagates SQL taint."""
        code = (
            "import sqlite3\n"
            "class Repository:\n"
            "    def set_filter(self, val):\n"
            "        self.query = 'SELECT * FROM items WHERE name = ' + val\n"
            "    def execute(self):\n"
            "        conn = sqlite3.connect(':memory:')\n"
            "        conn.execute(self.query)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe89 = [f for f in findings if f.cwe_id == "CWE-89"]
        self.assertGreaterEqual(len(cwe89), 1)

    def test_cwe22_tarfile_extractall_without_members(self):
        """Verify unvalidated tarfile.extractall() is flagged as CWE-22 Zip Slip."""
        code = "import tarfile\ntar = tarfile.open('archive.tar')\ntar.extractall('/opt/app')\n"
        findings = self.scanner.scan_code(code)
        cwe22 = [f for f in findings if f.cwe_id == "CWE-22"]
        self.assertEqual(len(cwe22), 1)
        self.assertIn("extractall", cwe22[0].description.lower())

    def test_cwe327_des_broken_cryptography(self):
        """Verify deprecated DES algorithm is flagged as CWE-327."""
        code = "from Crypto.Cipher import DES\ncipher = DES.new(b'12345678')\n"
        findings = self.scanner.scan_code(code)
        cwe327 = [f for f in findings if f.cwe_id == "CWE-327"]
        self.assertEqual(len(cwe327), 1)

    def test_cwe798_high_entropy_secret_flagged(self):
        """Verify high entropy secret string literal is flagged as CWE-798."""
        code = "API_TOKEN = 'sk-aB3dE5gH7iJ9kL1mN3oP5qR7sT9uV1wX'\n"
        findings = self.scanner.scan_code(code)
        cwe798 = [f for f in findings if f.cwe_id == "CWE-798"]
        self.assertEqual(len(cwe798), 1)

    def test_cwe798_low_entropy_identifier_not_flagged(self):
        """Verify low-entropy placeholder identifier is NOT flagged as CWE-798."""
        code = "user_role = 'administrator_role'\n"
        findings = self.scanner.scan_code(code)
        cwe798 = [f for f in findings if f.cwe_id == "CWE-798"]
        self.assertEqual(len(cwe798), 0)

    def test_scan_directory_exclude_dirs_respected(self):
        """Verify scan_directory skips subdirectories matching exclude_dirs."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            clean_dir = p / "clean"
            clean_dir.mkdir()
            (clean_dir / "good.py").write_text("x = 1\n", encoding="utf-8")

            ignored_dir = p / ".git"
            ignored_dir.mkdir()
            (ignored_dir / "bad.py").write_text("import os\nos.system('calc')\n", encoding="utf-8")

            findings = self.scanner.scan_directory(p)
            cwe78 = [f for f in findings if f.cwe_id == "CWE-78"]
            # Ignored because .git is in exclude_dirs
            self.assertEqual(len(cwe78), 0)

    def test_scan_file_not_found_raises(self):
        """Verify scan_file raises FileNotFoundError for non-existent target."""
        with self.assertRaises(FileNotFoundError):
            self.scanner.scan_file("non_existent_path_xyz_123.py")

    def test_findings_to_sarif_multiple_cwes(self):
        """Verify findings_to_sarif converts multiple distinct findings with valid rules and indices."""
        code = (
            "import os\n"
            "import pickle\n"
            "def run(cmd, data):\n"
            "    os.system(cmd)\n"
            "    pickle.loads(data)\n"
        )
        findings = self.scanner.scan_code(code)
        sarif = self.scanner.to_sarif(findings)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "CookieCyberTeam-AST-Scanner")
        self.assertGreaterEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 2)
        self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 2)

    def test_cwe798_attribute_assignment_flagged(self):
        """Verify attribute assignment self.api_key = '...' is flagged as CWE-798."""
        code = (
            "class Client:\n"
            "    def __init__(self):\n"
            "        self.api_key = 'sk-aB3dE5gH7iJ9kL1mN3oP5qR7sT9uV1wX'\n"
        )
        findings = self.scanner.scan_code(code)
        cwe798 = [f for f in findings if f.cwe_id == "CWE-798"]
        self.assertEqual(len(cwe798), 1)

    def test_yaml_load_safe_loader_positional_not_flagged(self):
        """Verify yaml.load(data, yaml.SafeLoader) is not flagged as CWE-502."""
        code = (
            "import yaml\n"
            "def parse_config(data):\n"
            "    return yaml.load(data, yaml.SafeLoader)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe502 = [f for f in findings if f.cwe_id == "CWE-502"]
        self.assertEqual(len(cwe502), 0)

    def test_cwe22_pathlib_write_text_and_write_bytes(self):
        """Verify pathlib write_text and write_bytes with untrusted path is flagged as CWE-22."""
        code = (
            "from pathlib import Path\n"
            "def save_file(user_filename, data):\n"
            "    target = Path('/uploads') / user_filename\n"
            "    target.write_text(data)\n"
        )
        findings = self.scanner.scan_code(code)
        cwe22 = [f for f in findings if f.cwe_id == "CWE-22"]
        self.assertGreaterEqual(len(cwe22), 1)


if __name__ == "__main__":
    unittest.main()


