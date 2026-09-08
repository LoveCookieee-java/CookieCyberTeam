"""
CookieCyberTeam Platform Native & AST YAGNI Engine.
Enforces DietrichGebert/ponytail "Lazy Senior Dev" mindset:
1. Prioritizes Python standard library and native Web/Node APIs over external dependencies.
2. Detects AST-level over-engineering (stateless utility classes, shallow wrapper functions).
3. Zero external dependencies (uses standard library `ast`, `re`, `json`, `pathlib`).
"""

from __future__ import annotations
import ast
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union


# Python 3rd-party packages mapped to standard library equivalents
PYTHON_STDLIB_EQUIVALENTS: Dict[str, str] = {
    "requests": "urllib.request",
    "httpx": "urllib.request",
    "pytz": "zoneinfo / datetime",
    "dateutil": "datetime / zoneinfo",
    "simplejson": "json",
    "attrs": "dataclasses",
    "tomli": "tomllib",
    "mock": "unittest.mock",
    "six": "builtins (Python 3 native)",
    "enum34": "enum",
    "pathlib2": "pathlib",
    "typing-extensions": "typing",
    "future": "builtins",
    "funcsigs": "inspect",
}

# JavaScript / TypeScript npm packages mapped to native Web & ECMAScript APIs
JAVASCRIPT_NATIVE_EQUIVALENTS: Dict[str, str] = {
    "qs": "URLSearchParams",
    "querystring": "URLSearchParams",
    "lodash.clonedeep": "structuredClone",
    "clone-deep": "structuredClone",
    "lodash.groupby": "Object.groupBy",
    "uuid": "crypto.randomUUID()",
    "node-fetch": "fetch",
    "axios": "fetch",
    "is-odd": "num % 2 !== 0",
    "is-even": "num % 2 === 0",
    "left-pad": "String.prototype.padStart",
    "moment": "Intl.DateTimeFormat / Date",
    "date-fns": "Intl.DateTimeFormat / Date",
    "lodash": "Array.prototype / Object.assign / native ES6+",
    "underscore": "Array.prototype / Object.assign / native ES6+",
    "chalk": "node:util.styleText()",
    "rimraf": "fs.rm(path, { recursive: true, force: true })",
    "mkdirp": "fs.mkdir(path, { recursive: true })",
}


def get_stdlib_equivalent(package_name: str) -> Optional[str]:
    """Retrieve Python standard library alternative for given package name."""
    clean = package_name.lower().replace("_", "-").strip()
    return PYTHON_STDLIB_EQUIVALENTS.get(clean) or PYTHON_STDLIB_EQUIVALENTS.get(package_name.lower().strip())


def get_js_native_equivalent(package_name: str) -> Optional[str]:
    """Retrieve JavaScript/TypeScript native platform alternative for given npm package."""
    clean = package_name.lower().strip()
    return JAVASCRIPT_NATIVE_EQUIVALENTS.get(clean)


def is_stateless_utility_class(node: ast.ClassDef) -> bool:
    """
    Detect if a ClassDef is a stateless utility class (over-engineering / AI code slop).
    Flags classes that:
    - Have no instance state or attributes initialized (`self.x = ...`).
    - Either have no `__init__` or an empty/trivial `__init__` (`pass`, docstring).
    - Contain only static methods (@staticmethod), class methods (@classmethod),
      or methods that never access `self`.
    - Do not inherit from framework classes (TestCase, Model, Enum, Exception, ABC).
    """
    # Exclude classes inheriting from common domain bases
    exempt_bases = {
        "exception", "error", "testcase", "model", "basemodel", "schema",
        "enum", "intenum", "strenum", "abc", "protocol", "generic", "dict", "list",
    }
    for base in node.bases:
        base_name = ""
        if isinstance(base, ast.Name):
            base_name = base.id.lower()
        elif isinstance(base, ast.Attribute):
            base_name = base.attr.lower()
        if any(base_name.endswith(ex) for ex in exempt_bases) or base_name in exempt_bases:
            return False

    methods: List[Union[ast.FunctionDef, ast.AsyncFunctionDef]] = []
    has_custom_init = False

    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if item.name == "__init__":
                # Inspect __init__ body
                meaningful_stmts = [
                    stmt for stmt in item.body
                    if not (
                        isinstance(stmt, ast.Pass)
                        or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
                    )
                ]
                if meaningful_stmts:
                    has_custom_init = True
                    return False
            else:
                methods.append(item)

    if has_custom_init or not methods:
        return False

    # Check if all non-init methods are static, classmethod, or lack `self` state mutations
    for method in methods:
        # Check decorators
        is_static = any(
            (isinstance(d, ast.Name) and d.id == "staticmethod")
            or (isinstance(d, ast.Attribute) and d.attr == "staticmethod")
            for d in method.decorator_list
        )
        is_classmethod = any(
            (isinstance(d, ast.Name) and d.id == "classmethod")
            or (isinstance(d, ast.Attribute) and d.attr == "classmethod")
            for d in method.decorator_list
        )
        if is_static or is_classmethod:
            continue

        # Check if method references self or mutates attributes
        first_arg = method.args.args[0].arg if method.args.args else None
        if not first_arg or first_arg not in ("self", "cls"):
            continue

        uses_self_state = False
        for n in ast.walk(method):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == first_arg:
                # If reading or writing instance attributes on self
                uses_self_state = True
                break
        if uses_self_state:
            return False

    return True


def _format_ast_callable(node: ast.AST) -> str:
    """Format AST call target expression into string representation (e.g. 'foo' or 'json.dumps')."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        parent = _format_ast_callable(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def is_shallow_wrapper_function(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> Optional[str]:
    """
    Detect if a function is a shallow wrapper that merely calls another function
    with the exact same arguments and returns or evaluates the result directly.
    Returns the name of the wrapped target function, or None.
    Supports attribute chains (e.g. json.dumps), *args/**kwargs forwarding, and kwargs.
    """
    # Filter out docstrings and empty statements
    stmts = [
        s for s in node.body
        if not (isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)))
    ]

    if len(stmts) != 1:
        return None

    stmt = stmts[0]
    call_node: Optional[ast.Call] = None

    if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
        call_node = stmt.value
    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        call_node = stmt.value
    elif isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Await) and isinstance(stmt.value.value, ast.Call):
        call_node = stmt.value.value

    if not call_node:
        return None

    # Resolve target function name
    target_name = _format_ast_callable(call_node.func)
    if not target_name:
        return None

    # Reject direct self-recursion (e.g. def foo(): return foo())
    if isinstance(call_node.func, ast.Name) and target_name == node.name:
        return None

    # Compare arguments:
    # 1. Positional arguments
    wrapper_positional = [a.arg for a in node.args.args]
    call_positional: List[str] = []
    starred_arg: Optional[str] = None

    for arg in call_node.args:
        if isinstance(arg, ast.Name):
            call_positional.append(arg.id)
        elif isinstance(arg, ast.Starred) and isinstance(arg.value, ast.Name):
            starred_arg = arg.value.id
        else:
            return None

    if wrapper_positional != call_positional:
        return None

    # Verify *args forwarding
    wrapper_vararg = node.args.vararg.arg if node.args.vararg else None
    if wrapper_vararg != starred_arg:
        return None

    # 2. Keyword-only arguments & **kwargs
    wrapper_kwonly = {a.arg for a in node.args.kwonlyargs}
    wrapper_kwarg = node.args.kwarg.arg if node.args.kwarg else None

    call_kwonly = set()
    double_starred_kwarg: Optional[str] = None

    for kw in call_node.keywords:
        if kw.arg is None:
            if isinstance(kw.value, ast.Name):
                double_starred_kwarg = kw.value.id
            else:
                return None
        else:
            if isinstance(kw.value, ast.Name) and kw.value.id == kw.arg:
                call_kwonly.add(kw.arg)
            else:
                return None

    if wrapper_kwonly != call_kwonly:
        return None

    if wrapper_kwarg != double_starred_kwarg:
        return None

    return target_name



def audit_ast_yagni(tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Audit Python AST for YAGNI / Ponytail anti-patterns:
    - Stateless utility classes
    - Shallow wrapper functions
    """
    findings: List[Dict[str, Any]] = []

    for node in tree.body if hasattr(tree, "body") else []:
        if isinstance(node, ast.ClassDef):
            if is_stateless_utility_class(node):
                findings.append({
                    "type": "stateless_utility_class",
                    "tag": "yagni:",
                    "name": node.name,
                    "line_number": getattr(node, "lineno", 1),
                    "message": (
                        f"Stateless utility class '{node.name}' detected. "
                        "Ponytail Rung 6: Replace with module-level functions or inline expressions."
                    ),
                    "remediation": f"Unwrap methods of '{node.name}' into standalone functions.",
                })
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            wrapped = is_shallow_wrapper_function(node)
            if wrapped:
                findings.append({
                    "type": "shallow_wrapper_function",
                    "tag": "shrink:",
                    "name": node.name,
                    "wrapped_target": wrapped,
                    "line_number": getattr(node, "lineno", 1),
                    "message": (
                        f"Shallow wrapper function '{node.name}' merely delegates to '{wrapped}'. "
                        "Ponytail Rung 6: Call '{wrapped}' directly without intermediate wrapping."
                    ),
                    "remediation": f"Remove '{node.name}' and invoke '{wrapped}' directly.",
                })

    return findings


def audit_npm_dependencies(package_json_content: Union[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Audit package.json dependencies for libraries replaceable by modern native Web/Node APIs."""
    findings: List[Dict[str, Any]] = []
    data: Dict[str, Any] = {}

    if isinstance(package_json_content, str):
        try:
            data = json.loads(package_json_content)
        except Exception:
            return []
    elif isinstance(package_json_content, dict):
        data = package_json_content

    all_deps: Dict[str, str] = {}
    for sec in ("dependencies", "devDependencies", "peerDependencies"):
        if sec in data and isinstance(data[sec], dict):
            all_deps.update(data[sec])

    for pkg, ver in all_deps.items():
        equiv = get_js_native_equivalent(pkg)
        if equiv:
            findings.append({
                "package": pkg,
                "version": ver,
                "tag": "native:",
                "native_alternative": equiv,
                "message": (
                    f"Dependency '{pkg}' can be replaced with native platform API: {equiv} "
                    "(Ponytail Rung 4: Native Platform Features)."
                ),
                "remediation": f"npm uninstall {pkg} and adopt native '{equiv}'.",
            })

    return findings
