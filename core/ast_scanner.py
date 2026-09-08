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

from core.config import (
    CookieCyberConfig,
    DEFAULT_EXCLUDE_DIRS,
    DEFAULT_SHANNON_ENTROPY_THRESHOLD,
    DEFAULT_CVSS_VERSION,
)
from core.cvss_calculator import cvss_for_cwe as _calc_cvss_for_cwe

_CURRENT_CVSS_VERSION = DEFAULT_CVSS_VERSION


def cvss_for_cwe(
    cwe_id: str,
    version: Optional[str] = None,
    custom_overrides: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Calculate CVSS dictionary, adhering to currently active or specified CVSS version."""
    v = version or _CURRENT_CVSS_VERSION
    return _calc_cvss_for_cwe(cwe_id, version=v, custom_overrides=custom_overrides)


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


class CallGraphVisitor(ast.NodeVisitor):
    """Pass 1: Pre-computes call graph and typed function taint contracts across the module."""

    KNOWN_SINKS: Dict[str, Tuple[str, str]] = {
        # SQL Sinks
        "execute": ("sql", "CWE-89"),
        "executemany": ("sql", "CWE-89"),
        "executescript": ("sql", "CWE-89"),
        # Command Sinks
        "system": ("command", "CWE-78"),
        "popen": ("command", "CWE-78"),
        "run": ("command", "CWE-78"),
        "check_output": ("command", "CWE-78"),
        "check_call": ("command", "CWE-78"),
        "getoutput": ("command", "CWE-78"),
        # Code Eval Sinks
        "eval": ("eval", "CWE-95"),
        "exec": ("eval", "CWE-95"),
        # Path Sinks
        "open": ("path", "CWE-22"),
        "read_text": ("path", "CWE-22"),
        "read_bytes": ("path", "CWE-22"),
        "unlink": ("path", "CWE-22"),
        "rmdir": ("path", "CWE-22"),
        "remove": ("path", "CWE-22"),
        # SSRF Sinks
        "urlopen": ("ssrf", "CWE-918"),
        "urlretrieve": ("ssrf", "CWE-918"),
        # Deserialization Sinks
        "loads": ("deserialization", "CWE-502"),
        "load": ("deserialization", "CWE-502"),
        "unsafe_load": ("deserialization", "CWE-502"),
    }

    def __init__(self):
        self.contracts: Dict[str, Dict[str, Any]] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._analyze_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._analyze_function(node)
        self.generic_visit(node)

    def _analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        params = [arg.arg for arg in getattr(node.args, "posonlyargs", []) + node.args.args]
        returns_args: Set[int] = set()
        sink_contracts: Dict[int, Tuple[str, str]] = {}
        sink_args: Set[int] = set()

        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and sub.value:
                for idx, p in enumerate(params):
                    for r_node in ast.walk(sub.value):
                        if isinstance(r_node, ast.Name) and r_node.id == p:
                            returns_args.add(idx)

            if isinstance(sub, ast.Call):
                callee = ""
                if isinstance(sub.func, ast.Name):
                    callee = sub.func.id
                elif isinstance(sub.func, ast.Attribute):
                    callee = sub.func.attr

                if callee in self.KNOWN_SINKS:
                    sink_type, cwe_id = self.KNOWN_SINKS[callee]
                    for idx, p in enumerate(params):
                        for a in sub.args:
                            for a_node in ast.walk(a):
                                if isinstance(a_node, ast.Name) and a_node.id == p:
                                    sink_contracts[idx] = (sink_type, cwe_id)
                                    sink_args.add(idx)

        self.contracts[node.name] = {
            "params": params,
            "returns_args": returns_args,
            "sink_contracts": sink_contracts,
            "sink_args": sink_args,
        }


class ASTScannerVisitor(ast.NodeVisitor):
    """
    AST Visitor implementing deep security checks with alias resolution
    and local taint tracking.
    """

    SQL_KEYWORDS = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "WHERE", "UNION", "FROM", "TABLE"}
    SECRET_VAR_KEYWORDS = {"secret", "key", "token", "password", "passwd", "api_key", "apikey", "auth", "cred", "private"}
    SECRET_PREFIXES = ("ghp_", "glpat-", "sk-", "AKIA", "ASIA", "eyJh", "bearer ")

    def __init__(
        self,
        source_lines: List[str],
        file_path: str = "<unknown>",
        cvss_version: str = DEFAULT_CVSS_VERSION,
        shannon_entropy_threshold: float = DEFAULT_SHANNON_ENTROPY_THRESHOLD,
    ):
        self.source_lines = source_lines
        self.file_path = file_path
        self.cvss_version = cvss_version
        self.shannon_entropy_threshold = shannon_entropy_threshold
        self.findings: List[Finding] = []

        # Alias table: map local name -> fully-qualified canonical target
        # e.g. "my_os" -> "os", "sys_exec" -> "os.system"
        self.aliases: Dict[str, str] = {}

        # Lexical scope stack: each scope maps variable_name -> taint_type ("sql", "path", etc.) or None (cleared)
        # Innermost scope is scope_stack[-1], module level is scope_stack[0]
        self.scope_stack: List[Dict[str, Optional[str]]] = [{}]
        self.global_vars_stack: List[Set[str]] = [set()]
        self.nonlocal_vars_stack: List[Set[str]] = [set()]

        # Instance field taint: e.g. self.query -> "sql"
        self.instance_field_taint: Dict[str, Optional[str]] = {}

        # Function taint contracts from Pass 1: func_name -> contract
        self.function_contracts: Dict[str, Dict[str, Any]] = {}

    @property
    def tainted_vars(self) -> Dict[str, str]:
        """Flattened active taint mapping for backward compatibility."""
        merged: Dict[str, str] = {}
        for scope in self.scope_stack:
            for k, v in scope.items():
                if v:
                    merged[k] = v
                else:
                    merged.pop(k, None)
        return merged

    @tainted_vars.setter
    def tainted_vars(self, values: Dict[str, str]) -> None:
        self.scope_stack[-1] = dict(values)

    def _get_var_taint_type(self, var_name: str) -> Optional[str]:
        """Resolve identifier taint from innermost scope to outermost (module scope)."""
        for scope in reversed(self.scope_stack):
            if var_name in scope:
                return scope[var_name]
        return None

    def _is_var_tainted(self, var_name: str, taint_type: Optional[str] = None) -> bool:
        """Check whether a variable is tainted, optionally filtering by taint type."""
        tt = self._get_var_taint_type(var_name)
        if not tt:
            return False
        return taint_type is None or tt == taint_type

    def _set_var_taint(self, var_name: str, taint_type: Optional[str]) -> None:
        """Assign taint state taking global and nonlocal scope bindings into account."""
        if var_name in self.global_vars_stack[-1]:
            self.scope_stack[0][var_name] = taint_type
            return

        if var_name in self.nonlocal_vars_stack[-1]:
            for scope in reversed(self.scope_stack[1:-1]):
                if var_name in scope:
                    scope[var_name] = taint_type
                    return
            if len(self.scope_stack) > 1:
                self.scope_stack[-2][var_name] = taint_type
                return

        self.scope_stack[-1][var_name] = taint_type

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

    def visit_Global(self, node: ast.Global) -> None:
        self.global_vars_stack[-1].update(node.names)
        self.generic_visit(node)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocal_vars_stack[-1].update(node.names)
        self.generic_visit(node)

    def _collect_scope_declarations(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Tuple[Set[str], Set[str]]:
        globals_found: Set[str] = set()
        nonlocals_found: Set[str] = set()
        stack: List[ast.AST] = list(node.body)
        while stack:
            stmt = stack.pop()
            if isinstance(stmt, ast.Global):
                globals_found.update(stmt.names)
            elif isinstance(stmt, ast.Nonlocal):
                nonlocals_found.update(stmt.names)
            elif isinstance(stmt, (ast.If, ast.While, ast.For, ast.With, ast.Try)):
                for field_name in ("body", "orelse", "finalbody"):
                    stack.extend(getattr(stmt, field_name, []))
                if isinstance(stmt, ast.Try):
                    for h in stmt.handlers:
                        stack.extend(h.body)
            elif hasattr(ast, "Match") and isinstance(stmt, ast.Match):
                for case in stmt.cases:
                    stack.extend(case.body)
        return globals_found, nonlocals_found

    def _push_function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._check_csrf_exempt(node)
        globals_in_body, nonlocals_in_body = self._collect_scope_declarations(node)
        fn_scope: Dict[str, Optional[str]] = {}
        # Register parameters in lexical scope to allow clean nonlocal resolution
        for arg in getattr(node.args, "posonlyargs", []) + node.args.args + getattr(node.args, "kwonlyargs", []):
            fn_scope[arg.arg] = None
        if node.args.vararg:
            fn_scope[node.args.vararg.arg] = None
        if node.args.kwarg:
            fn_scope[node.args.kwarg.arg] = None

        self.scope_stack.append(fn_scope)
        self.global_vars_stack.append(globals_in_body)
        self.nonlocal_vars_stack.append(nonlocals_in_body)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._push_function_scope(node)
        try:
            self.generic_visit(node)
        finally:
            self.scope_stack.pop()
            self.global_vars_stack.pop()
            self.nonlocal_vars_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._push_function_scope(node)
        try:
            self.generic_visit(node)
        finally:
            self.scope_stack.pop()
            self.global_vars_stack.pop()
            self.nonlocal_vars_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope_stack.append({})
        self.global_vars_stack.append(set())
        self.nonlocal_vars_stack.append(set())
        try:
            self.generic_visit(node)
        finally:
            self.scope_stack.pop()
            self.global_vars_stack.pop()
            self.nonlocal_vars_stack.pop()

    def _check_csrf_exempt(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Detect route handlers using @csrf_exempt or @csrf.exempt (CWE-352)."""
        for dec in node.decorator_list:
            is_exempt = False
            dec_unparsed = ""
            try:
                dec_unparsed = ast.unparse(dec).lower()
            except Exception:
                pass

            if "csrf_exempt" in dec_unparsed or "csrf.exempt" in dec_unparsed or "csrf_protect.exempt" in dec_unparsed:
                is_exempt = True
            elif isinstance(dec, ast.Name) and dec.id == "csrf_exempt":
                is_exempt = True
            elif isinstance(dec, ast.Attribute) and (
                dec.attr == "csrf_exempt" or (dec.attr == "exempt" and "csrf" in dec_unparsed)
            ):
                is_exempt = True
            elif isinstance(dec, ast.Call):
                func = dec.func
                if isinstance(func, ast.Name) and func.id == "csrf_exempt":
                    is_exempt = True
                elif isinstance(func, ast.Attribute) and (
                    func.attr == "csrf_exempt" or (func.attr == "exempt" and "csrf" in dec_unparsed)
                ):
                    is_exempt = True

            if is_exempt:
                cvss = cvss_for_cwe("CWE-352")
                self.findings.append(Finding(
                    cwe_id="CWE-352",
                    title="Cross-Site Request Forgery (CSRF) Protection Disabled",
                    description=f"Route handler function '{node.name}' uses anti-CSRF exempt decorator ('{dec_unparsed or 'csrf_exempt'}'), disabling anti-CSRF token enforcement.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    severity=cvss["severity"],
                    cvss_score=cvss["base_score"],
                    cvss_vector=cvss["vector_string"],
                    code_snippet=self._get_code_snippet(node.lineno),
                    remediation="Remove '@csrf_exempt' decorator and enforce CSRF tokens on state-changing POST/PUT/DELETE requests.",
                ))

    def _check_assign_target_and_value(self, target: ast.AST, value: Optional[ast.AST], lineno: int) -> None:
        if isinstance(target, ast.Starred):
            self._check_assign_target_and_value(target.value, value, lineno)
            return

        if isinstance(target, (ast.Tuple, ast.List)):
            if value and isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                for t, v in zip(target.elts, value.elts):
                    self._check_assign_target_and_value(t, v, lineno)
            else:
                for t in target.elts:
                    self._check_assign_target_and_value(t, value, lineno)
            return

        if isinstance(target, (ast.Name, ast.Attribute)):
            sym_name = target.id if isinstance(target, ast.Name) else target.attr
            var_name = sym_name.lower()
            if value and isinstance(value, ast.Constant) and isinstance(value.value, str):
                val_str = value.value
                is_suspicious_var = any(kw in var_name for kw in self.SECRET_VAR_KEYWORDS)
                has_secret_prefix = any(val_str.lower().startswith(p.lower()) for p in self.SECRET_PREFIXES)
                entropy = calculate_shannon_entropy(val_str)

                high_entropy_secret = len(val_str) >= 20 and entropy >= getattr(self, "shannon_entropy_threshold", DEFAULT_SHANNON_ENTROPY_THRESHOLD)

                if (is_suspicious_var and len(val_str) >= 8 and not val_str.startswith("http")) or \
                   (has_secret_prefix and len(val_str) >= 16) or \
                   (is_suspicious_var and len(val_str) >= 16 and entropy >= 3.0) or \
                   high_entropy_secret:
                    cvss = cvss_for_cwe("CWE-798")
                    self.findings.append(Finding(
                        cwe_id="CWE-798",
                        title="Use of Hard-coded Credentials",
                        description=f"Variable '{sym_name}' is assigned a high-entropy or sensitive secret literal.",
                        file_path=self.file_path,
                        line_number=lineno,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        code_snippet=self._get_code_snippet(lineno),
                        remediation="Store secrets in environment variables or a secure key management vault.",
                    ))

            # Track local taint for SQL queries and path manipulations
            if isinstance(target, ast.Name):
                if value and self._is_potential_sql_expr(value):
                    self._set_var_taint(target.id, "sql")
                elif value and self._references_tainted_var(value, taint_type="sql"):
                    self._set_var_taint(target.id, "sql")
                elif value and self._is_potential_path_expr(value):
                    self._set_var_taint(target.id, "path")
                elif value and self._is_path_like_node(value):
                    self._set_var_taint(target.id, "path")
                elif value and self._references_tainted_var(value, taint_type="path"):
                    self._set_var_taint(target.id, "path")
                elif value and self._references_tainted_var(value):
                    self._set_var_taint(target.id, "generic")
                else:
                    self._set_var_taint(target.id, None)
            elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                attr_name = target.attr
                if value and (self._is_potential_sql_expr(value) or self._references_tainted_var(value, taint_type="sql")):
                    self.instance_field_taint[attr_name] = "sql"
                elif value and (self._is_potential_path_expr(value) or self._references_tainted_var(value, taint_type="path") or self._is_path_like_node(value)):
                    self.instance_field_taint[attr_name] = "path"
                elif value and self._references_tainted_var(value):
                    self.instance_field_taint[attr_name] = "generic"
                else:
                    self.instance_field_taint.pop(attr_name, None)

    def _references_tainted_var(self, node: ast.AST, taint_type: Optional[str] = None) -> bool:
        """Check if an AST expression references any currently tainted variable, self.attr, or return of tainted call."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and self._is_var_tainted(sub.id, taint_type=taint_type):
                return True
            if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == "self":
                tt = self.instance_field_taint.get(sub.attr)
                if tt and (taint_type is None or tt == taint_type or tt == "generic"):
                    return True
            if isinstance(sub, ast.Call):
                fname = self._resolve_call_name(sub.func)
                base_name = fname.split(".")[-1]
                contract = self.function_contracts.get(fname) or self.function_contracts.get(base_name)
                if contract:
                    returns_args = contract.get("returns_args", set())
                    for idx, arg_node in enumerate(sub.args):
                        if idx in returns_args and self._references_tainted_var(arg_node, taint_type=taint_type):
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
        # Track augmented assignments (e.g. sql += user_input, path += user_input)
        if isinstance(node.target, ast.Name):
            if (
                self._is_potential_sql_expr(node.value)
                or self._is_var_tainted(node.target.id, taint_type="sql")
                or self._references_tainted_var(node.value, taint_type="sql")
            ):
                self._set_var_taint(node.target.id, "sql")
            elif (
                self._is_potential_path_expr(node.value)
                or self._is_var_tainted(node.target.id, taint_type="path")
                or self._references_tainted_var(node.value, taint_type="path")
            ):
                self._set_var_taint(node.target.id, "path")
        self.generic_visit(node)

    def _is_path_like_node(self, node: ast.AST) -> bool:
        """Check if an AST node represents a pathlib.Path object or path-tainted variable."""
        if isinstance(node, ast.Call):
            func_name = self._resolve_call_name(node.func)
            if func_name in ("pathlib.Path", "Path") or func_name.endswith(".Path"):
                return True
        elif isinstance(node, ast.Name):
            if self._is_var_tainted(node.id, taint_type="path"):
                return True
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._is_path_like_node(node.left) or self._is_path_like_node(node.right)
        elif self._references_tainted_var(node, taint_type="path"):
            return True
        return False

    def _is_potential_path_expr(self, node: ast.AST) -> bool:
        """Check if an expression constructs a dynamic file path."""
        if isinstance(node, ast.NamedExpr):
            return self._is_potential_path_expr(node.value)

        if isinstance(node, ast.Call):
            func_name = self._resolve_call_name(node.func)
            if func_name in ("os.path.join", "posixpath.join", "ntpath.join"):
                return any(not isinstance(a, ast.Constant) for a in node.args[1:])
            if func_name in ("pathlib.Path", "Path") or func_name.endswith(".Path"):
                return any(not isinstance(a, ast.Constant) for a in node.args)

        if isinstance(node, ast.JoinedStr):
            raw_text = "".join(
                part.value for part in node.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            if ("/" in raw_text or "\\" in raw_text) and any(isinstance(p, ast.FormattedValue) for p in node.values):
                return True

        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                if not self._is_pure_static_constant_binop(node):
                    raw_text = self._extract_string_literals(node)
                    if "/" in raw_text or "\\" in raw_text:
                        return True
            elif isinstance(node.op, ast.Div):
                # Pathlib '/' operator: only true if at least one operand is a Path object or path-tainted
                if self._is_path_like_node(node.left) or self._is_path_like_node(node.right):
                    return True

        return False

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
                elif isinstance(unwrapped_arg, ast.Name) and self._is_var_tainted(unwrapped_arg.id, taint_type="sql"):
                    is_sqli = True
                elif self._references_tainted_var(unwrapped_arg, taint_type="sql"):
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

        # 4. CWE-502: Insecure Deserialization (Pickle, YAML, AI/ML models)
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
            if not has_safe_loader and len(node.args) >= 2:
                try:
                    if "Safe" in ast.unparse(node.args[1]):
                        has_safe_loader = True
                except Exception:
                    pass
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
        elif func_name in ("torch.load",):
            has_weights_only = False
            weights_only_false = False
            for kw in node.keywords:
                if kw.arg == "weights_only":
                    has_weights_only = True
                    if isinstance(kw.value, ast.Constant) and bool(kw.value.value) is False:
                        weights_only_false = True
                    break
            if not has_weights_only or weights_only_false:
                cvss = cvss_for_cwe("CWE-502")
                reason = "explicitly sets weights_only=False" if weights_only_false else "omits weights_only=True"
                self.findings.append(Finding(
                    cwe_id="CWE-502",
                    title="Insecure AI/ML Model Deserialization via torch.load",
                    description=f"Call to '{func_name}' {reason}, allowing arbitrary Python code execution via pickled weights.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    severity=cvss["severity"],
                    cvss_score=cvss["base_score"],
                    cvss_vector=cvss["vector_string"],
                    code_snippet=self._get_code_snippet(node.lineno),
                    remediation="Always specify 'weights_only=True' in torch.load() or use Safetensors format.",
                ))
        elif func_name in ("joblib.load",):
            cvss = cvss_for_cwe("CWE-502")
            self.findings.append(Finding(
                cwe_id="CWE-502",
                title="Insecure AI/ML Model Deserialization via joblib.load",
                description=f"Call to '{func_name}' deserializes untrusted pickle artifacts, allowing arbitrary code execution.",
                file_path=self.file_path,
                line_number=node.lineno,
                severity=cvss["severity"],
                cvss_score=cvss["base_score"],
                cvss_vector=cvss["vector_string"],
                code_snippet=self._get_code_snippet(node.lineno),
                remediation="Use secure model representations such as ONNX, Safetensors, or PMML.",
            ))
        elif func_name in ("numpy.load", "np.load"):
            allow_pickle = False
            for kw in node.keywords:
                if kw.arg == "allow_pickle" and isinstance(kw.value, ast.Constant) and bool(kw.value.value) is True:
                    allow_pickle = True
                    break
            if not allow_pickle and len(node.args) >= 3:
                if isinstance(node.args[2], ast.Constant) and bool(node.args[2].value) is True:
                    allow_pickle = True
            if allow_pickle:
                cvss = cvss_for_cwe("CWE-502")
                self.findings.append(Finding(
                    cwe_id="CWE-502",
                    title="Insecure Array Deserialization via numpy.load(allow_pickle=True)",
                    description=f"Call to '{func_name}' explicitly enables 'allow_pickle=True', allowing arbitrary code execution.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    severity=cvss["severity"],
                    cvss_score=cvss["base_score"],
                    cvss_vector=cvss["vector_string"],
                    code_snippet=self._get_code_snippet(node.lineno),
                    remediation="Avoid 'allow_pickle=True'. Save numeric arrays as pure binary .npy files without object arrays.",
                ))
        elif func_name in ("dill.loads", "dill.load", "cloudpickle.loads", "cloudpickle.load"):
            cvss = cvss_for_cwe("CWE-502")
            self.findings.append(Finding(
                cwe_id="CWE-502",
                title=f"Insecure Deserialization via {func_name}",
                description=f"Call to '{func_name}' deserializes arbitrary Python bytecode, allowing remote code execution.",
                file_path=self.file_path,
                line_number=node.lineno,
                severity=cvss["severity"],
                cvss_score=cvss["base_score"],
                cvss_vector=cvss["vector_string"],
                code_snippet=self._get_code_snippet(node.lineno),
                remediation="Never deserialize untrusted payloads with dill or cloudpickle. Use JSON or HMAC-authenticated payloads.",
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

        # 6. CWE-22: Path Traversal / Zip Slip
        if func_name.endswith(".extractall") or func_name == "extractall":
            has_safe_filter = False
            for kw in node.keywords:
                if kw.arg in ("members", "filter"):
                    if not (isinstance(kw.value, ast.Constant) and kw.value.value is None):
                        has_safe_filter = True
                        break
            if not has_safe_filter and len(node.args) >= 2:
                if not (isinstance(node.args[1], ast.Constant) and node.args[1].value is None):
                    has_safe_filter = True

            if not has_safe_filter:
                cvss = cvss_for_cwe("CWE-22")
                self.findings.append(Finding(
                    cwe_id="CWE-22",
                    title="Arbitrary File Overwrite via Archive Extraction (Zip Slip)",
                    description=f"Call to '{func_name}' without safe members filter allows path traversal / arbitrary file overwrite.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    severity=cvss["severity"],
                    cvss_score=cvss["base_score"],
                    cvss_vector=cvss["vector_string"],
                    code_snippet=self._get_code_snippet(node.lineno),
                    remediation="Validate archive member paths before extracting or pass safe member filter to extractall().",
                ))

        if func_name in ("open", "io.open", "os.open"):
            first_arg = node.args[0] if node.args else None
            if not first_arg and node.keywords:
                for kw in node.keywords:
                    if kw.arg in ("file", "path"):
                        first_arg = kw.value
                        break
            if first_arg is not None:
                is_path_traversal = False
                if self._is_potential_path_expr(first_arg):
                    is_path_traversal = True
                elif isinstance(first_arg, ast.JoinedStr) and any(isinstance(p, ast.FormattedValue) for p in first_arg.values):
                    is_path_traversal = True
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                    if not self._is_pure_static_constant_binop(first_arg):
                        is_path_traversal = True
                elif isinstance(first_arg, ast.Name) and self._is_var_tainted(first_arg.id, taint_type="path"):
                    is_path_traversal = True
                elif self._references_tainted_var(first_arg, taint_type="path"):
                    is_path_traversal = True

                if is_path_traversal:
                    cvss = cvss_for_cwe("CWE-22")
                    self.findings.append(Finding(
                        cwe_id="CWE-22",
                        title="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                        description=f"File open operation '{func_name}' called with dynamic or untrusted path expression.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        code_snippet=self._get_code_snippet(node.lineno),
                        remediation="Validate paths using os.path.realpath() and os.path.commonpath() against an allowed base directory.",
                    ))

        # Pathlib file operations: Path(...).read_text(), read_bytes(), write_text(), write_bytes(), Path.open()
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("read_text", "read_bytes", "write_text", "write_bytes", "open")
            and func_name not in ("open", "io.open", "os.open", "shelve.open", "tarfile.open")
        ):
            target_obj = node.func.value
            is_pathlib_traversal = False
            if self._is_potential_path_expr(target_obj):
                is_pathlib_traversal = True
            elif isinstance(target_obj, ast.Name) and self._is_var_tainted(target_obj.id, taint_type="path"):
                is_pathlib_traversal = True
            elif self._references_tainted_var(target_obj, taint_type="path"):
                is_pathlib_traversal = True

            if is_pathlib_traversal:
                cvss = cvss_for_cwe("CWE-22")
                op_type = "write" if "write" in node.func.attr else "read"
                self.findings.append(Finding(
                    cwe_id="CWE-22",
                    title="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                    description=f"Pathlib file {op_type} operation '{node.func.attr}' called on dynamic or untrusted path expression.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    severity=cvss["severity"],
                    cvss_score=cvss["base_score"],
                    cvss_vector=cvss["vector_string"],
                    code_snippet=self._get_code_snippet(node.lineno),
                    remediation="Validate paths using os.path.realpath() and os.path.commonpath() against an allowed base directory.",
                ))

        if func_name in ("os.path.join", "posixpath.join", "ntpath.join"):
            if len(node.args) >= 2 and any(not isinstance(a, ast.Constant) for a in node.args[1:]):
                cvss = cvss_for_cwe("CWE-22")
                self.findings.append(Finding(
                    cwe_id="CWE-22",
                    title="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                    description=f"Call to '{func_name}' with untrusted or dynamic subpath is vulnerable to path traversal.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    severity=cvss["severity"],
                    cvss_score=cvss["base_score"],
                    cvss_vector=cvss["vector_string"],
                    code_snippet=self._get_code_snippet(node.lineno),
                    remediation="Validate resolved path using os.path.commonpath([base_dir, resolved_path]) == base_dir.",
                ))

        # 7. CWE-327 & CWE-328: Broken Cryptography
        is_weak_hash = False
        if func_name in ("hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD5.new", "Crypto.Hash.SHA1.new"):
            is_weak_hash = True
        elif func_name == "hashlib.new":
            if node.args and isinstance(node.args[0], ast.Constant) and str(node.args[0].value).lower() in ("md5", "sha1"):
                is_weak_hash = True
            else:
                for kw in node.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant) and str(kw.value.value).lower() in ("md5", "sha1"):
                        is_weak_hash = True
                        break

        if is_weak_hash:
            for kw in node.keywords:
                if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    is_weak_hash = False
                    break

        if is_weak_hash:
            cvss = cvss_for_cwe("CWE-328")
            self.findings.append(Finding(
                cwe_id="CWE-328",
                title="Use of Weak Hash Algorithm",
                description=f"Cryptographically broken hash function '{func_name}' detected. Vulnerable to collision attacks.",
                file_path=self.file_path,
                line_number=node.lineno,
                severity=cvss["severity"],
                cvss_score=cvss["base_score"],
                cvss_vector=cvss["vector_string"],
                code_snippet=self._get_code_snippet(node.lineno),
                remediation="Use secure collision-resistant hash functions like SHA-256 (hashlib.sha256()) or SHA-3.",
            ))

        is_weak_cipher = False
        cipher_desc = ""
        if func_name.endswith(".DES.new") or func_name in ("DES.new", "DES", "Crypto.Cipher.DES.new"):
            is_weak_cipher = True
            cipher_desc = "Legacy DES encryption algorithm has insufficient 56-bit key length and is vulnerable to brute force."
        elif func_name.endswith(".AES.new") or func_name in ("AES.new", "Crypto.Cipher.AES.new"):
            for kw in node.keywords:
                if kw.arg == "mode" and "MODE_ECB" in ast.unparse(kw.value):
                    is_weak_cipher = True
                    cipher_desc = "AES with ECB (Electronic Codebook) mode leaks plaintext data patterns because identical blocks yield identical ciphertext."
                    break
            if not is_weak_cipher and len(node.args) >= 2:
                if "MODE_ECB" in ast.unparse(node.args[1]):
                    is_weak_cipher = True
                    cipher_desc = "AES with ECB (Electronic Codebook) mode leaks plaintext data patterns because identical blocks yield identical ciphertext."

        if is_weak_cipher:
            cvss = cvss_for_cwe("CWE-327")
            self.findings.append(Finding(
                cwe_id="CWE-327",
                title="Use of a Broken or Risky Cryptographic Algorithm",
                description=cipher_desc,
                file_path=self.file_path,
                line_number=node.lineno,
                severity=cvss["severity"],
                cvss_score=cvss["base_score"],
                cvss_vector=cvss["vector_string"],
                code_snippet=self._get_code_snippet(node.lineno),
                remediation="Use AES with authenticated encryption modes like GCM (AES.MODE_GCM) or ChaCha20-Poly1305.",
            ))

        # 8. CWE-377: Insecure Temporary File Creation
        if func_name in ("tempfile.mktemp", "mktemp"):
            cvss = cvss_for_cwe("CWE-377")
            self.findings.append(Finding(
                cwe_id="CWE-377",
                title="Insecure Temporary File Creation (mktemp)",
                description=f"Call to '{func_name}' is deprecated and insecure. Vulnerable to race conditions (TOCTOU) and symlink attacks.",
                file_path=self.file_path,
                line_number=node.lineno,
                severity=cvss["severity"],
                cvss_score=cvss["base_score"],
                cvss_vector=cvss["vector_string"],
                code_snippet=self._get_code_snippet(node.lineno),
                remediation="Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() which create files atomically.",
            ))

        # Inter-Procedural Call Graph Sink Propagation
        base_name = func_name.split(".")[-1]
        contract = self.function_contracts.get(func_name) or self.function_contracts.get(base_name)
        if contract:
            sink_contracts = contract.get("sink_contracts", {})
            legacy_sink_args = contract.get("sink_args", set())
            for idx in sorted(set(sink_contracts.keys()) | legacy_sink_args):
                if idx < len(node.args):
                    arg_node = node.args[idx]
                    sink_type, cwe_id = sink_contracts.get(idx, ("sql", "CWE-89"))
                    if self._references_tainted_var(arg_node, taint_type=sink_type if sink_type in ("sql", "path") else None):
                        cvss = cvss_for_cwe(cwe_id)
                        self.findings.append(Finding(
                            cwe_id=cwe_id,
                            title=f"Inter-Procedural Injection via Tainted Parameter Flow ({cwe_id})",
                            description=f"Function '{func_name}' passes tainted argument at position {idx} directly into internal {sink_type} sink.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            code_snippet=self._get_code_snippet(node.lineno),
                            remediation="Sanitize input or use parameterized queries before passing arguments to sink.",
                        ))

        # 9. CWE-611: XML External Entity (XXE)
        if (
            func_name in (
                "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
                "xml.etree.cElementTree.parse", "xml.etree.cElementTree.fromstring",
                "lxml.etree.parse", "lxml.etree.fromstring", "lxml.etree.fromstringlist",
                "xml.sax.parse", "xml.sax.parseString", "xml.dom.minidom.parse",
                "xml.dom.minidom.parseString", "xml.dom.pulldom.parse",
            )
            or (
                isinstance(node.func, ast.Attribute) and node.func.attr in ("parse", "fromstring")
                and any(pkg in func_name for pkg in ("etree", "ElementTree", "minidom", "sax"))
            )
        ):
            if not func_name.startswith("defusedxml"):
                is_xxe = True
                for kw in node.keywords:
                    if kw.arg == "parser":
                        # If parser resolves entities or default, flag
                        pass
                if is_xxe:
                    cvss = cvss_for_cwe("CWE-611")
                    self.findings.append(Finding(
                        cwe_id="CWE-611",
                        title="Improper Restriction of XML External Entity Reference (XXE)",
                        description=f"Standard XML parsing function '{func_name}' detected without secure entity resolution restrictions.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        code_snippet=self._get_code_snippet(node.lineno),
                        remediation="Use defusedxml package (e.g. defusedxml.ElementTree) or configure XMLParser(resolve_entities=False, no_network=True).",
                    ))

        # 10. CWE-918: Server-Side Request Forgery (SSRF)
        if func_name in (
            "requests.get", "requests.post", "requests.put", "requests.delete", "requests.head", "requests.request",
            "urllib.request.urlopen", "urllib.request.urlretrieve",
            "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request",
            "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
        ):
            url_arg = node.args[0] if node.args else None
            if not url_arg and node.keywords:
                for kw in node.keywords:
                    if kw.arg in ("url", "uri"):
                        url_arg = kw.value
                        break
            if url_arg:
                is_ssrf = False
                ssrf_desc = ""
                raw_url = self._extract_string_literals(url_arg)
                if "169.254.169.254" in raw_url or "metadata.google.internal" in raw_url:
                    is_ssrf = True
                    ssrf_desc = "Outbound HTTP request targets cloud metadata endpoint (169.254.169.254), exposing sensitive IAM credentials."
                elif self._references_tainted_var(url_arg) or (isinstance(url_arg, ast.Name) and self._is_var_tainted(url_arg.id)):
                    is_ssrf = True
                    ssrf_desc = f"Call to '{func_name}' fetches dynamic or untrusted URL from tainted variable, exposing internal services to SSRF."
                elif isinstance(url_arg, ast.JoinedStr) and any(isinstance(p, ast.FormattedValue) for p in url_arg.values):
                    is_ssrf = True
                    ssrf_desc = f"Call to '{func_name}' constructs destination URL via dynamic string interpolation without whitelist validation."

                if is_ssrf:
                    cvss = cvss_for_cwe("CWE-918")
                    self.findings.append(Finding(
                        cwe_id="CWE-918",
                        title="Server-Side Request Forgery (SSRF)",
                        description=ssrf_desc,
                        file_path=self.file_path,
                        line_number=node.lineno,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        code_snippet=self._get_code_snippet(node.lineno),
                        remediation="Validate destination URLs against an explicit domain whitelist and block private IP ranges (RFC 1918) and link-local metadata endpoints.",
                    ))

        # 11. CWE-1336 / CWE-79: Server-Side Template Injection & XSS
        if func_name in (
            "jinja2.Template", "Template", "jinja2.Environment.from_string",
            "flask.render_template_string", "render_template_string",
        ):
            tmpl_arg = node.args[0] if node.args else None
            if not tmpl_arg and node.keywords:
                for kw in node.keywords:
                    if kw.arg in ("source", "template_string", "template"):
                        tmpl_arg = kw.value
                        break
            if tmpl_arg and not (isinstance(tmpl_arg, ast.Constant) and isinstance(tmpl_arg.value, str)):
                cvss = cvss_for_cwe("CWE-1336")
                self.findings.append(Finding(
                    cwe_id="CWE-1336",
                    title="Improper Neutralization of Special Elements in Template Engine (SSTI)",
                    description=f"Call to '{func_name}' renders dynamic non-constant template string, allowing Remote Code Execution via SSTI.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    severity=cvss["severity"],
                    cvss_score=cvss["base_score"],
                    cvss_vector=cvss["vector_string"],
                    code_snippet=self._get_code_snippet(node.lineno),
                    remediation="Never concatenate user input into template strings. Use render_template() with static template files and pass variables via context dictionary.",
                ))

        # 12. CWE-943: NoSQL Injection
        if func_name.endswith((".find", ".find_one", ".update", ".update_one", ".update_many", ".delete_one", ".delete_many")):
            query_arg = node.args[0] if node.args else None
            if query_arg:
                is_nosql = False
                raw_text = self._extract_string_literals(query_arg)
                if "$where" in raw_text or "$expr" in raw_text:
                    if not self._is_pure_static_constant_binop(query_arg):
                        is_nosql = True
                elif self._references_tainted_var(query_arg):
                    is_nosql = True

                if is_nosql:
                    cvss = cvss_for_cwe("CWE-943")
                    self.findings.append(Finding(
                        cwe_id="CWE-943",
                        title="Improper Neutralization of Special Elements in Data Query Logic (NoSQL Injection)",
                        description=f"NoSQL database query operation '{func_name}' contains unsanitized dynamic logic or $where expression.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        code_snippet=self._get_code_snippet(node.lineno),
                        remediation="Avoid using $where or javascript evaluation in queries. Enforce strict JSON schema validation and parameterized query filters.",
                    ))

        # 13. CWE-400: Regular Expression Denial of Service (ReDoS)
        if func_name in ("re.compile", "re.search", "re.match", "re.findall", "re.finditer", "re.sub"):
            pattern_arg = node.args[0] if node.args else None
            if pattern_arg and isinstance(pattern_arg, ast.Constant) and isinstance(pattern_arg.value, str):
                pattern_str = pattern_arg.value
                if re.search(r"\([^\)]*[+*]\)\s*[+*]", pattern_str) or re.search(r"\(\?:\([^\)]*[+*]\)\)[+*]", pattern_str):
                    cvss = cvss_for_cwe("CWE-400")
                    self.findings.append(Finding(
                        cwe_id="CWE-400",
                        title="Uncontrolled Resource Consumption via Catastrophic Regex Backtracking (ReDoS)",
                        description=f"Regular expression pattern '{pattern_str}' contains nested quantifiers susceptible to polynomial or exponential backtracking.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        code_snippet=self._get_code_snippet(node.lineno),
                        remediation="Rewrite regular expression to remove nested quantifiers, or use atomic grouping / re2 with linear time guarantees.",
                    ))

        self.generic_visit(node)


class ASTScanner:
    """Orchestrates AST parsing, security rule checks, and Delta diff scanning."""

    def __init__(
        self,
        config: Optional[CookieCyberConfig] = None,
        cvss_version: Optional[str] = None,
        shannon_entropy_threshold: Optional[float] = None,
        exclude_dirs: Optional[Set[str]] = None,
    ):
        self.config = config or CookieCyberConfig()
        self.cvss_version = cvss_version or self.config.cvss_version
        self.shannon_entropy_threshold = (
            shannon_entropy_threshold if shannon_entropy_threshold is not None
            else self.config.shannon_entropy_threshold
        )
        self.exclude_dirs = (
            {d.strip() for d in exclude_dirs} if exclude_dirs is not None
            else set(self.config.exclude_dirs)
        )

    def is_path_excluded(self, path: Union[str, Path]) -> bool:
        """Check if any directory component of path matches exclude_dirs."""
        p = Path(path)
        parts = {part.lower() for part in p.parts}
        return any(ex.lower() in parts for ex in self.exclude_dirs)

    def scan_directory(
        self,
        dir_path: Union[str, Path],
        recursive: bool = True,
    ) -> List[Finding]:
        """Scan all Python files in directory, skipping paths matching exclude_dirs."""
        p = Path(dir_path).resolve()
        if not p.is_dir():
            if p.is_file():
                return self.scan_file(p)
            return []

        all_findings: List[Finding] = []
        pattern = "**/*.py" if recursive else "*.py"
        for py_file in sorted(p.glob(pattern)):
            if self.is_path_excluded(py_file):
                continue
            try:
                findings = self.scan_file(py_file)
                all_findings.extend(findings)
            except Exception:
                continue
        return all_findings

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

        global _CURRENT_CVSS_VERSION
        prev_cvss_version = _CURRENT_CVSS_VERSION
        _CURRENT_CVSS_VERSION = self.cvss_version
        try:
            source_lines = code_content.splitlines()
            cg_visitor = CallGraphVisitor()
            cg_visitor.visit(tree)

            visitor = ASTScannerVisitor(
                source_lines=source_lines,
                file_path=file_path,
                cvss_version=self.cvss_version,
                shannon_entropy_threshold=self.shannon_entropy_threshold,
            )
            visitor.function_contracts = cg_visitor.contracts
            visitor.visit(tree)

            findings = visitor.findings
            if modified_lines is not None:
                # True Git Delta Scan: filter out any finding not in modified lines
                findings = [f for f in findings if f.line_number in modified_lines]

            return findings
        finally:
            _CURRENT_CVSS_VERSION = prev_cvss_version

    def scan_file(
        self,
        file_path: str | Path,
        modified_lines: Optional[Set[int]] = None,
    ) -> List[Finding]:
        """Scan a Python file from disk."""
        path = Path(file_path).resolve()
        if self.is_path_excluded(path):
            return []
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        try:
            import tokenize
            with tokenize.open(path) as f:
                code_content = f.read()
        except Exception:
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
        if self.is_path_excluded(target):
            return []

        rel_path = target.relative_to(repo) if target.is_relative_to(repo) else target
        rel_posix = rel_path.as_posix() if hasattr(rel_path, "as_posix") else str(rel_path).replace("\\", "/")

        # Check if file is tracked by git
        ls_argv = ["git", "ls-files", "--error-unmatch", "--", rel_posix]
        try:
            ls_res = subprocess.run(ls_argv, cwd=str(repo), capture_output=True, text=True, shell=False, timeout=10)
            if ls_res.returncode != 0:
                # Untracked / newly created file: scan 100% of lines
                return self.scan_file(target, modified_lines=None)
        except Exception:
            return self.scan_file(target, modified_lines=None)

        # Extract modified line numbers using git diff
        argv = ["git", "diff", "-U0", base_commit, "--", rel_posix]
        try:
            res = subprocess.run(argv, cwd=str(repo), capture_output=True, text=True, shell=False, timeout=10)
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

    def to_sarif(
        self,
        findings: List[Finding | Dict[str, Any]],
        tool_version: str = "1.3.0",
    ) -> Dict[str, Any]:
        """Convert findings into OASIS SARIF v2.1.0 JSON representation."""
        return findings_to_sarif(findings, tool_version=tool_version)


def findings_to_sarif(
    findings: List[Finding | Dict[str, Any]],
    tool_version: str = "1.3.0",
) -> Dict[str, Any]:
    """
    Export list of SAST findings into standard OASIS SARIF v2.1.0 schema format.
    Compatible with GitHub Code Scanning, DefectDojo, and modern CI/CD dashboards.
    """
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    sev_level_map = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "None": "note",
    }

    for f in findings:
        f_dict = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        cwe_id = f_dict.get("cwe_id", "UNKNOWN")
        title = f_dict.get("title", cwe_id)
        description = f_dict.get("description", "")
        file_path = f_dict.get("file_path") or "<unknown>"
        line_no_raw = f_dict.get("line_number")
        line_no = int(line_no_raw) if line_no_raw is not None else 1
        severity = f_dict.get("severity", "Low")
        level = sev_level_map.get(severity, "warning")
        snippet = f_dict.get("code_snippet", "")
        remediation = f_dict.get("remediation", "")

        rule_name = re.sub(r"[^A-Za-z0-9_]", "", title.title()) or cwe_id
        if cwe_id not in rules_map:
            rules_map[cwe_id] = {
                "id": cwe_id,
                "name": rule_name,
                "shortDescription": {"text": title},
                "fullDescription": {"text": description or title},
                "defaultConfiguration": {"level": level},
                "help": {"text": remediation or description},
                "properties": {
                    "tags": ["security", cwe_id],
                    "precision": "high",
                },
            }

        rule_index = list(rules_map.keys()).index(cwe_id)

        # Normalize file path URI to posix format
        posix_path = Path(file_path).as_posix() if hasattr(Path(file_path), "as_posix") else str(file_path).replace("\\", "/")

        result_item: Dict[str, Any] = {
            "ruleId": cwe_id,
            "ruleIndex": rule_index,
            "level": level,
            "message": {
                "text": f"{title}: {description}" if description else title,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": posix_path,
                        },
                        "region": {
                            "startLine": max(1, line_no),
                            "snippet": {
                                "text": snippet,
                            },
                        },
                    }
                }
            ],
            "properties": {
                "cvss_score": f_dict.get("cvss_score", 0.0),
                "cvss_vector": f_dict.get("cvss_vector", ""),
                "remediation": remediation,
            },
        }
        results.append(result_item)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CookieCyberTeam-AST-Scanner",
                        "semanticVersion": tool_version,
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
