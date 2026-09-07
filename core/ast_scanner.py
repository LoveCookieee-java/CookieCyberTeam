"""
Pure-Python AST SAST (Static Application Security Testing) Engine.
Zero external dependencies. Features:
- Import aliasing tracking (resolves renamed/aliased imports)
- CWE-78 (OS Command Injection)
- CWE-89 (SQL Injection with Local Taint Tracking)
- CWE-95 (Code Injection / Eval)
- CWE-502 (Insecure Deserialization)
- CWE-798 (Hard-coded Credentials via Shannon Entropy & Patterns)
- CWE-295 (Improper Certificate Validation)
- True Git Delta Scanning Engine (scan only modified diff lines)
- Standard CVSS v3.1 Base Score enrichment
"""

from __future__ import annotations
import ast
import math
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.cvss_calculator import cvss_for_cwe


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon Entropy of a string: H(s) = -sum(p * log2(p))."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


@dataclass
class Finding:
    cwe_id: str
    title: str
    description: str
    file_path: str
    line_number: int
    severity: str
    cvss_score: float
    cvss_vector: str
    code_snippet: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
        }


class ASTScannerVisitor(ast.NodeVisitor):
    """
    AST Visitor implementing deep security checks with alias resolution
    and local taint tracking.
    """

    SQL_KEYWORDS = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "WHERE", "UNION", "FROM", "TABLE"}
    SECRET_VAR_KEYWORDS = {"secret", "key", "token", "password", "passwd", "api_key", "apikey", "auth", "cred", "private"}
    SECRET_PREFIXES = ("ghp_", "glpat-", "sk-", "AKIA", "ASIA", "eyJh", "bearer ")

    def __init__(self, source_lines: List[str], file_path: str = "<unknown>"):
        self.source_lines = source_lines
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Alias table: map local name -> fully-qualified canonical target
        # e.g. "my_os" -> "os", "sys_exec" -> "os.system"
        self.aliases: Dict[str, str] = {}

        # Local taint table: variable_name -> taint_type ("sql", "untrusted")
        self.tainted_vars: Dict[str, str] = {}

    def _get_code_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _resolve_call_name(self, node: ast.AST) -> str:
        """Resolve chained attributes or names taking imports into account."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            base = self._resolve_call_name(node.value)
            canonical = f"{base}.{node.attr}"
            return self.aliases.get(canonical, canonical)
        return ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                self.aliases[alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            target_name = alias.asname if alias.asname else alias.name
            self.aliases[target_name] = full_name
        self.generic_visit(node)

    def _check_assign_target_and_value(self, target: ast.AST, value: Optional[ast.AST], lineno: int) -> None:
        if isinstance(target, ast.Name):
            var_name = target.id.lower()
            if value and isinstance(value, ast.Constant) and isinstance(value.value, str):
                val_str = value.value
                is_suspicious_var = any(kw in var_name for kw in self.SECRET_VAR_KEYWORDS)
                has_secret_prefix = any(val_str.lower().startswith(p.lower()) for p in self.SECRET_PREFIXES)
                entropy = calculate_shannon_entropy(val_str)

                if (is_suspicious_var and len(val_str) >= 8 and not val_str.startswith("http")) or \
                   (has_secret_prefix and len(val_str) >= 16) or \
                   (is_suspicious_var and len(val_str) >= 16 and entropy >= 3.0):
                    cvss = cvss_for_cwe("CWE-798")
                    self.findings.append(Finding(
                        cwe_id="CWE-798",
                        title="Use of Hard-coded Credentials",
                        description=f"Variable '{target.id}' is assigned a high-entropy or sensitive secret literal.",
                        file_path=self.file_path,
                        line_number=lineno,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        code_snippet=self._get_code_snippet(lineno),
                        remediation="Store secrets in environment variables or a secure key management vault.",
                    ))

            # Track local taint for SQL queries with alias preservation & clearing
            if value and self._is_potential_sql_expr(value):
                self.tainted_vars[target.id] = "sql"
            elif value and self._references_tainted_var(value):
                self.tainted_vars[target.id] = "sql"
            else:
                self.tainted_vars.pop(target.id, None)

    def _references_tainted_var(self, node: ast.AST) -> bool:
        """Check if an AST expression references any currently tainted variable."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted_vars:
                return True
        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check for CWE-798 and SQL taint in standard variable assignments
        for target in node.targets:
            self._check_assign_target_and_value(target, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        # Check for CWE-798 and SQL taint in type-annotated assignments (Python 3.6+)
        self._check_assign_target_and_value(node.target, node.value, node.lineno)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        # Check for CWE-798 and SQL taint in walrus operator assignments (x := expr)
        self._check_assign_target_and_value(node.target, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # Track augmented assignments (e.g. sql += user_input)
        if isinstance(node.target, ast.Name):
            if self._is_potential_sql_expr(node.value) or node.target.id in self.tainted_vars:
                self.tainted_vars[node.target.id] = "sql"
        self.generic_visit(node)

    def _is_pure_static_constant_binop(self, node: ast.AST) -> bool:
        """Recursively check if a BinOp (Add) tree consists purely of Constant nodes."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._is_pure_static_constant_binop(node.left) and self._is_pure_static_constant_binop(node.right)
        return False

    def _is_potential_sql_expr(self, node: ast.AST) -> bool:
        """Check if an expression creates a SQL statement via f-string, concat, format, or %."""
        if isinstance(node, ast.NamedExpr):
            return self._is_potential_sql_expr(node.value)
        if isinstance(node, ast.JoinedStr):
            # Formatted f-string: check if contains SQL keywords
            raw_text = ""
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    raw_text += part.value
            words = set(re.findall(r"\b[A-Za-z]+\b", raw_text.upper()))
            if words & self.SQL_KEYWORDS and any(isinstance(p, ast.FormattedValue) for p in node.values):
                return True
        elif isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                # Static string concat false positive elimination
                if self._is_pure_static_constant_binop(node):
                    return False
                raw_text = self._extract_string_literals(node)
                words = set(re.findall(r"\b[A-Za-z]+\b", raw_text.upper()))
                if words & self.SQL_KEYWORDS:
                    return True
            elif isinstance(node.op, ast.Mod):
                # % formatting
                raw_text = self._extract_string_literals(node)
                words = set(re.findall(r"\b[A-Za-z]+\b", raw_text.upper()))
                if words & self.SQL_KEYWORDS:
                    return True
        elif isinstance(node, ast.Call):
            # String .format(...) call on SQL query template
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                raw_text = self._extract_string_literals(node.func.value)
                words = set(re.findall(r"\b[A-Za-z]+\b", raw_text.upper()))
                if words & self.SQL_KEYWORDS and (node.args or node.keywords):
                    return True
        return False

    def _extract_string_literals(self, node: ast.AST) -> str:
        text = ""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                text += " " + sub.value
        return text

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._resolve_call_name(node.func)

        # 1. CWE-78: OS Command Injection
        # os.system, os.popen, os.exec*, os.spawn*, subprocess.getoutput, subprocess.getstatusoutput
        if (
            func_name in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput")
            or func_name.startswith("os.exec")
            or func_name.startswith("os.spawn")
        ):
            cvss = cvss_for_cwe("CWE-78")
            self.findings.append(Finding(
                cwe_id="CWE-78",
                title="Improper Neutralization of Special Elements used in an OS Command",
                description=f"Dangerous system execution function '{func_name}' detected. Vulnerable to command injection.",
                file_path=self.file_path,
                line_number=node.lineno,
                severity=cvss["severity"],
                cvss_score=cvss["base_score"],
                cvss_vector=cvss["vector_string"],
                code_snippet=self._get_code_snippet(node.lineno),
                remediation="Use subprocess.run() with argv list and shell=False.",
            ))

        # subprocess calls with shell=True
        if func_name in (
            "subprocess.run", "subprocess.Popen", "subprocess.call",
            "subprocess.check_call", "subprocess.check_output"
        ):
            for kw in node.keywords:
                if kw.arg == "shell":
                    # Check if shell is True
                    if isinstance(kw.value, ast.Constant) and bool(kw.value.value) is True:
                        cvss = cvss_for_cwe("CWE-78")
                        self.findings.append(Finding(
                            cwe_id="CWE-78",
                            title="OS Command Injection via Subprocess shell=True",
                            description=f"Call to '{func_name}' explicitly enables 'shell=True', exposing command injection risk.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            code_snippet=self._get_code_snippet(node.lineno),
                            remediation="Set shell=False and pass arguments as a list of strings (argv).",
                        ))

        # 2. CWE-89: SQL Injection
        # Checks calls like cursor.execute(query), db.execute(...), executemany, executescript
        if (
            func_name.endswith((".execute", ".executemany", ".executescript"))
            or func_name in ("execute", "executemany", "executescript")
        ):
            first_arg = None
            if node.args:
                first_arg = node.args[0]
            elif node.keywords:
                for kw in node.keywords:
                    if kw.arg in ("query", "sql", "operation", "statement") or first_arg is None:
                        first_arg = kw.value
                        if kw.arg in ("query", "sql", "operation", "statement"):
                            break

            if first_arg is not None:
                unwrapped_arg = first_arg.value if isinstance(first_arg, ast.NamedExpr) else first_arg
                is_sqli = False
                # Direct f-string, concat, or format in execute()
                if self._is_potential_sql_expr(unwrapped_arg):
                    is_sqli = True
                # Tainted variable passed in execute()
                elif isinstance(unwrapped_arg, ast.Name) and unwrapped_arg.id in self.tainted_vars:
                    is_sqli = True
                elif self._references_tainted_var(unwrapped_arg):
                    is_sqli = True

                if is_sqli:
                    cvss = cvss_for_cwe("CWE-89")
                    self.findings.append(Finding(
                        cwe_id="CWE-89",
                        title="SQL Injection via Unsanitized Formatting",
                        description=f"Dynamic string formatting detected in SQL execution call '{func_name}'.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        code_snippet=self._get_code_snippet(node.lineno),
                        remediation="Use parameterized queries with placeholders (? or %s) rather than string interpolation.",
                    ))

        # 3. CWE-95: Code Injection / Eval
        if func_name in ("eval", "exec", "compile"):
            # If argument is not a static constant, flag it
            if node.args and not (len(node.args) == 1 and isinstance(node.args[0], ast.Constant)):
                cvss = cvss_for_cwe("CWE-95")
                self.findings.append(Finding(
                    cwe_id="CWE-95",
                    title="Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)",
                    description=f"Direct call to dynamic code execution function '{func_name}' with non-constant input.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    severity=cvss["severity"],
                    cvss_score=cvss["base_score"],
                    cvss_vector=cvss["vector_string"],
                    code_snippet=self._get_code_snippet(node.lineno),
                    remediation="Avoid eval/exec. Use ast.literal_eval() for safe data deserialization or explicit mapping.",
                ))

        # 4. CWE-502: Insecure Deserialization
        if func_name in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load", "shelve.open", "yaml.unsafe_load"):
            cvss = cvss_for_cwe("CWE-502")
            self.findings.append(Finding(
                cwe_id="CWE-502",
                title="Deserialization of Untrusted Data",
                description=f"Insecure deserialization using '{func_name}' allows arbitrary code execution via crafted payloads.",
                file_path=self.file_path,
                line_number=node.lineno,
                severity=cvss["severity"],
                cvss_score=cvss["base_score"],
                cvss_vector=cvss["vector_string"],
                code_snippet=self._get_code_snippet(node.lineno),
                remediation="Use safe serialization formats like JSON, Protocol Buffers, or HMAC signing.",
            ))
        elif func_name == "yaml.load":
            has_safe_loader = any(
                kw.arg == "Loader" and "Safe" in ast.unparse(kw.value)
                for kw in node.keywords
            )
            if not has_safe_loader:
                cvss = cvss_for_cwe("CWE-502")
                self.findings.append(Finding(
                    cwe_id="CWE-502",
                    title="Insecure YAML Deserialization",
                    description="yaml.load() without SafeLoader allows arbitrary code execution.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    severity=cvss["severity"],
                    cvss_score=cvss["base_score"],
                    cvss_vector=cvss["vector_string"],
                    code_snippet=self._get_code_snippet(node.lineno),
                    remediation="Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
                ))

        # 5. CWE-295: Disabled SSL Verification
        if func_name in ("requests.get", "requests.post", "requests.put", "requests.delete", "requests.request",
                         "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request",
                         "urllib3.PoolManager"):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    cvss = cvss_for_cwe("CWE-295")
                    self.findings.append(Finding(
                        cwe_id="CWE-295",
                        title="Disabled TLS/SSL Certificate Verification",
                        description=f"Call to '{func_name}' with 'verify=False' disables TLS verification, vulnerable to Man-in-the-Middle attacks.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        code_snippet=self._get_code_snippet(node.lineno),
                        remediation="Enable certificate verification or configure custom trusted CA certificates.",
                    ))
        elif func_name == "ssl._create_unverified_context":
            cvss = cvss_for_cwe("CWE-295")
            self.findings.append(Finding(
                cwe_id="CWE-295",
                title="Creation of Unverified SSL Context",
                description="Use of 'ssl._create_unverified_context()' disables certificate validation globally.",
                file_path=self.file_path,
                line_number=node.lineno,
                severity=cvss["severity"],
                cvss_score=cvss["base_score"],
                cvss_vector=cvss["vector_string"],
                code_snippet=self._get_code_snippet(node.lineno),
                remediation="Use ssl.create_default_context() with verified certificates.",
            ))

        self.generic_visit(node)


class ASTScanner:
    """Orchestrates AST parsing, security rule checks, and Delta diff scanning."""

    def scan_code(
        self,
        code_content: str,
        file_path: str = "<in-memory>",
        modified_lines: Optional[Set[int]] = None,
    ) -> List[Finding]:
        """
        Scan Python source code string.
        If modified_lines is provided (Delta scanning), only findings on those lines are returned.
        """
        try:
            tree = ast.parse(code_content, filename=file_path)
        except SyntaxError as exc:
            # Return syntax error as finding or raise
            return [Finding(
                cwe_id="CWE-SyntaxError",
                title="Python Syntax Error",
                description=str(exc),
                file_path=file_path,
                line_number=exc.lineno or 1,
                severity="High",
                cvss_score=7.0,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
                code_snippet=exc.text or "",
                remediation="Fix syntax error before SAST analysis.",
            )]

        source_lines = code_content.splitlines()
        visitor = ASTScannerVisitor(source_lines=source_lines, file_path=file_path)
        visitor.visit(tree)

        findings = visitor.findings
        if modified_lines is not None:
            # True Git Delta Scan: filter out any finding not in modified lines
            findings = [f for f in findings if f.line_number in modified_lines]

        return findings

    def scan_file(
        self,
        file_path: str | Path,
        modified_lines: Optional[Set[int]] = None,
    ) -> List[Finding]:
        """Scan a Python file from disk."""
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        code_content = path.read_text(encoding="utf-8", errors="replace")
        return self.scan_code(code_content, file_path=str(path), modified_lines=modified_lines)

    def scan_git_diff(
        self,
        file_path_or_repo: str | Path,
        file_path: Optional[str | Path] = None,
        base_commit: str = "HEAD",
    ) -> List[Finding]:
        """
        Run true Delta Scanning on modified lines extracted from git diff.
        Supports both scan_git_diff(file_path) and scan_git_diff(repo_path, file_path).
        """
        if file_path is None:
            target = Path(file_path_or_repo).resolve()
            repo = target.parent
            for parent in [target.parent, *target.parents]:
                if (parent / ".git").exists():
                    repo = parent
                    break
        else:
            repo = Path(file_path_or_repo).resolve()
            target = Path(file_path).resolve()
        rel_path = target.relative_to(repo) if target.is_relative_to(repo) else target
        rel_posix = rel_path.as_posix() if hasattr(rel_path, "as_posix") else str(rel_path).replace("\\", "/")

        # Check if file is tracked by git
        ls_argv = ["git", "ls-files", "--error-unmatch", "--", rel_posix]
        try:
            ls_res = subprocess.run(ls_argv, cwd=str(repo), capture_output=True, text=True, shell=False)
            if ls_res.returncode != 0:
                # Untracked / newly created file: scan 100% of lines
                return self.scan_file(target, modified_lines=None)
        except Exception:
            return self.scan_file(target, modified_lines=None)

        # Extract modified line numbers using git diff
        argv = ["git", "diff", "-U0", base_commit, "--", rel_posix]
        try:
            res = subprocess.run(argv, cwd=str(repo), capture_output=True, text=True, shell=False)
            if res.returncode != 0:
                modified_lines = None
            else:
                modified_lines = self._parse_diff_added_lines(res.stdout)
        except Exception:
            modified_lines = None

        return self.scan_file(target, modified_lines=modified_lines)

    @staticmethod
    def _parse_diff_added_lines(diff_text: str) -> Set[int]:
        """Parse unified diff hunk headers @@ -l,s +l,s @@ to get added/modified line numbers."""
        lines: Set[int] = set()
        # Example hunk header: @@ -10,3 +12,5 @@
        pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
        for line in diff_text.splitlines():
            m = pattern.match(line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1
                for i in range(start, start + count):
                    lines.add(i)
        return lines
