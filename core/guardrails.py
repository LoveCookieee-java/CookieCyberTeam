"""
Safe Patching Guardrails Engine.
Enforces the 3 mandatory safety gates:
1. Diff Cap Gate (<= 50 lines changed, Ponytail Principle)
2. AST Syntax & Zero-Regression SAST Gate (no new vulnerabilities introduced)
3. Git Branch Isolation Gate (block direct commits/patches to main/master)
"""

from __future__ import annotations
import ast
import difflib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.ast_scanner import ASTScanner, Finding
from core.config import (
    CookieCyberConfig,
    DEFAULT_DIFF_CAP_LIMIT,
    DEFAULT_NEW_FILE_CAP_LIMIT,
    DEFAULT_RESTRICTED_BRANCHES,
)
from core.semgrep_adapter import SemgrepAdapter


DIFF_CAP_LIMIT = DEFAULT_DIFF_CAP_LIMIT
NEW_FILE_CAP_LIMIT = DEFAULT_NEW_FILE_CAP_LIMIT
RESTRICTED_BRANCHES = DEFAULT_RESTRICTED_BRANCHES


class GuardrailViolation(Exception):
    """Exception raised when a patch violates safety guardrails."""
    def __init__(self, gate_name: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"[{gate_name} Violation]: {message}")
        self.gate_name = gate_name
        self.message = message
        self.details = details or {}


def calculate_diff_stats(original_text: str, modified_text: str, filename: str = "target") -> Dict[str, Any]:
    """Calculate unified diff and line change count (added + deleted)."""
    orig_lines = original_text.splitlines(keepends=True)
    mod_lines = modified_text.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        orig_lines,
        mod_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
    ))

    added = 0
    deleted = 0
    for line in diff:
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            deleted += 1

    total_changed = added + deleted
    unified_diff_text = "".join(diff)

    return {
        "added": added,
        "deleted": deleted,
        "total_changed": total_changed,
        "diff_text": unified_diff_text,
    }


def find_git_root(path: str | Path) -> Optional[Path]:
    """Find the root of the git repository by traversing upwards from path."""
    curr = Path(path).resolve()
    if not curr.is_dir():
        curr = curr.parent
    for p in [curr, *curr.parents]:
        if (p / ".git").exists():
            return p
    return None


def get_current_git_branch(repo_path: str | Path) -> Optional[str]:
    """Retrieve current Git branch name safely."""
    git_bin = shutil.which("git")
    if not git_bin:
        return None
    r_dir = Path(repo_path).resolve()
    if r_dir.is_file():
        r_dir = r_dir.parent
    try:
        res = subprocess.run(
            [git_bin, "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(r_dir),
            capture_output=True,
            text=True,
            shell=False,
            timeout=5,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return None


def validate_code_delimiters(code: str, file_path: str = "") -> None:
    """
    Validate balanced delimiters (curly braces {}, brackets [], parentheses ())
    and string quotes for C-family, JavaScript, TypeScript, Go, Java, shell, YAML, etc.
    Skips line comments (//, # for configs/shell/yaml) and block comments (/* ... */).
    Properly handles JS/TS template literals (`... ${...} ...`), Go raw strings,
    escaped quotes, and regex literals.
    """
    stack: List[Tuple[str, int, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}

    ext = Path(file_path).suffix.lower()
    file_name = Path(file_path).name.lower()
    is_hash_comment_lang = ext in (".yaml", ".yml", ".sh", ".bash", ".zsh", ".env", ".conf", ".rb", ".pl") or file_name in ("dockerfile", "makefile", "containerfile")
    is_js_ts = ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
    is_go = ext in (".go",)

    i = 0
    n = len(code)
    line = 1
    col = 1
    last_non_ws = ""

    while i < n:
        char = code[i]

        # Line tracking
        if char == "\n":
            line += 1
            col = 1
            i += 1
            continue

        if char in (" ", "\t", "\r"):
            i += 1
            col += 1
            continue

        # Check for line comment //
        if char == "/" and i + 1 < n and code[i + 1] == "/":
            i += 2
            col += 2
            while i < n and code[i] != "\n":
                i += 1
                col += 1
            continue

        # Check for block comment /* ... */
        if char == "/" and i + 1 < n and code[i + 1] == "*":
            start_line = line
            i += 2
            col += 2
            closed = False
            while i + 1 < n:
                if code[i] == "\n":
                    line += 1
                    col = 1
                    i += 1
                elif code[i] == "*" and code[i + 1] == "/":
                    i += 2
                    col += 2
                    closed = True
                    break
                else:
                    i += 1
                    col += 1
            if not closed:
                raise GuardrailViolation(
                    gate_name="Syntax Pre-Flight Gate",
                    message=f"Unclosed block comment (/*) starting at line {start_line}.",
                    details={"lineno": start_line, "file": file_path},
                )
            continue

        # Check for hash comments (#) for YAML, shell, and Dockerfiles
        if is_hash_comment_lang and char == "#":
            while i < n and code[i] != "\n":
                i += 1
                col += 1
            continue

        # Check for regular expression literals in JS/TS: e.g. /pattern/ or /\{/
        if is_js_ts and char == "/" and i + 1 < n and code[i + 1] not in ("/", "*"):
            regex_starters = {"", "=", "(", "[", "{", ":", ",", ";", "!", "&", "|", "?", "~", "^", "+", "-", "*", "%"}
            if last_non_ws in regex_starters:
                start_line = line
                i += 1
                col += 1
                closed = False
                while i < n:
                    c = code[i]
                    if c == "\n":
                        break
                    elif c == "\\":
                        i += 1
                        col += 1
                        if i < n:
                            i += 1
                            col += 1
                        continue
                    elif c == "/":
                        closed = True
                        i += 1
                        col += 1
                        break
                    else:
                        i += 1
                        col += 1
                if closed:
                    last_non_ws = "/"
                    continue

        # Check for normal strings: '...' or "..."
        if char in ("'", '"'):
            # In YAML/shell, an apostrophe inside a word (e.g. don't, it's) is not a string delimiter
            if is_hash_comment_lang and char == "'" and i > 0 and code[i - 1].isalnum():
                last_non_ws = char
                i += 1
                col += 1
                continue

            quote = char
            start_line = line
            i += 1
            col += 1
            closed = False
            while i < n:
                c = code[i]
                if c == "\\":
                    # Escape sequence
                    i += 1
                    col += 1
                    if i < n and code[i] == "\n":
                        line += 1
                        col = 1
                    i += 1
                    col += 1
                    continue
                elif c == "\n":
                    raise GuardrailViolation(
                        gate_name="Syntax Pre-Flight Gate",
                        message=f"Unclosed string literal ({quote}) starting at line {start_line}.",
                        details={"lineno": start_line, "file": file_path},
                    )
                elif c == quote:
                    closed = True
                    i += 1
                    col += 1
                    break
                else:
                    i += 1
                    col += 1
            if not closed:
                raise GuardrailViolation(
                    gate_name="Syntax Pre-Flight Gate",
                    message=f"Unclosed string literal ({quote}) starting at line {start_line}.",
                    details={"lineno": start_line, "file": file_path},
                )
            last_non_ws = quote
            continue

        # Check for backtick strings (Go raw strings or JS/TS template literals)
        if char == "`":
            if is_go:
                # Go raw string: backslash is literal, multiline allowed, terminates at backtick
                start_line = line
                i += 1
                col += 1
                closed = False
                while i < n:
                    c = code[i]
                    if c == "\n":
                        line += 1
                        col = 1
                        i += 1
                        continue
                    elif c == "`":
                        closed = True
                        i += 1
                        col += 1
                        break
                    else:
                        i += 1
                        col += 1
                if not closed:
                    raise GuardrailViolation(
                        gate_name="Syntax Pre-Flight Gate",
                        message=f"Unclosed Go raw string literal (`) starting at line {start_line}.",
                        details={"lineno": start_line, "file": file_path},
                    )
                last_non_ws = "`"
                continue
            else:
                # JS/TS Template Literal: supports embedded expressions ${...}
                start_line = line
                i += 1
                col += 1
                closed = False
                while i < n:
                    c = code[i]
                    if c == "\n":
                        line += 1
                        col = 1
                        i += 1
                        continue
                    elif c == "\\":
                        i += 1
                        col += 1
                        if i < n and code[i] == "\n":
                            line += 1
                            col = 1
                        i += 1
                        col += 1
                        continue
                    elif c == "$" and i + 1 < n and code[i + 1] == "{":
                        # Embedded expression begins: push marker onto stack and switch to code mode
                        stack.append(("${", line, col))
                        i += 2
                        col += 2
                        closed = True
                        break
                    elif c == "`":
                        closed = True
                        i += 1
                        col += 1
                        break
                    else:
                        i += 1
                        col += 1
                if not closed:
                    raise GuardrailViolation(
                        gate_name="Syntax Pre-Flight Gate",
                        message=f"Unclosed template literal (`) starting at line {start_line}.",
                        details={"lineno": start_line, "file": file_path},
                    )
                last_non_ws = "`"
                continue

        # Check opening delimiters
        if char in ("(", "[", "{"):
            stack.append((char, line, col))
            last_non_ws = char
            i += 1
            col += 1
            continue

        # Check closing delimiters
        if char in (")", "]", "}"):
            if not stack:
                raise GuardrailViolation(
                    gate_name="Syntax Pre-Flight Gate",
                    message=f"Unmatched closing delimiter '{char}' at line {line}:{col}.",
                    details={"lineno": line, "col": col, "delimiter": char, "file": file_path},
                )
            top_char, top_line, top_col = stack.pop()
            if char == "}" and top_char == "${":
                # Closing of embedded template expression ${...} in JS/TS:
                # Re-enter template string mode until closing ` or next ${
                start_line = top_line
                i += 1
                col += 1
                closed = False
                while i < n:
                    c = code[i]
                    if c == "\n":
                        line += 1
                        col = 1
                        i += 1
                        continue
                    elif c == "\\":
                        i += 1
                        col += 1
                        if i < n and code[i] == "\n":
                            line += 1
                            col = 1
                        i += 1
                        col += 1
                        continue
                    elif c == "$" and i + 1 < n and code[i + 1] == "{":
                        stack.append(("${", line, col))
                        i += 2
                        col += 2
                        closed = True
                        break
                    elif c == "`":
                        closed = True
                        i += 1
                        col += 1
                        break
                    else:
                        i += 1
                        col += 1
                if not closed:
                    raise GuardrailViolation(
                        gate_name="Syntax Pre-Flight Gate",
                        message=f"Unclosed template literal (`) starting at line {start_line}.",
                        details={"lineno": start_line, "file": file_path},
                    )
                last_non_ws = "`"
                continue
            else:
                expected_open = pairs[char]
                if top_char != expected_open:
                    raise GuardrailViolation(
                        gate_name="Syntax Pre-Flight Gate",
                        message=(
                            f"Mismatched delimiter '{char}' at line {line}:{col}. "
                            f"Expected closing for '{top_char}' from line {top_line}:{top_col}."
                        ),
                        details={
                            "lineno": line,
                            "col": col,
                            "found": char,
                            "expected_matching": top_char,
                            "opened_at_line": top_line,
                            "file": file_path,
                        },
                    )
                last_non_ws = char
                i += 1
                col += 1
                continue

        last_non_ws = char
        i += 1
        col += 1

    if stack:
        last_char, last_line, last_col = stack[-1]
        desc = "template expression '${'" if last_char == "${" else f"delimiter '{last_char}'"
        raise GuardrailViolation(
            gate_name="Syntax Pre-Flight Gate",
            message=f"Unclosed {desc} opened at line {last_line}:{last_col}.",
            details={"lineno": last_line, "col": last_col, "delimiter": last_char, "file": file_path},
        )


def validate_yaml_syntax(code: str, file_path: str = "") -> None:
    """
    Lightweight stdlib validation for YAML when PyYAML is not installed:
    1. Forbids tab indentation.
    2. Enforces balanced brackets [] and braces {} outside comments and strings.
    3. Detects unclosed quotes while permitting natural apostrophes in unquoted words.
    """
    lines = code.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.lstrip(" ")
        if stripped.startswith("\t"):
            raise GuardrailViolation(
                gate_name="Syntax Pre-Flight Gate",
                message=f"YAML syntax error: Tabs are strictly forbidden for indentation at line {lineno}.",
                details={"lineno": lineno, "file": file_path},
            )

    validate_code_delimiters(code, file_path=file_path)


def check_polyglot_syntax(code: str, file_path: str = "") -> None:
    """
    Validate code syntax polyglot based on file extension:
    - Python (.py, .pyw): strict ast.parse()
    - JSON (.json): stdlib json.loads()
    - YAML (.yaml, .yml): yaml.safe_load() if available, else validate_yaml_syntax()
    - Markdown (.md, .markdown, .mdown, .txt): balanced code fences (```)
    - Non-Python files without extension (Dockerfile, Makefile, etc.): delimiter/text check
    - Other languages (.js, .ts, .go, .java, .c, .cpp, etc.): balanced delimiters & quotes
    """
    ext = Path(file_path).suffix.lower()
    file_name = Path(file_path).name.lower()

    if ext in (".py", ".pyw"):
        try:
            ast.parse(code, filename=file_path)
        except SyntaxError as exc:
            raise GuardrailViolation(
                gate_name="Syntax Pre-Flight Gate",
                message=f"Patched Python code has syntax error at line {exc.lineno}: {exc.msg}",
                details={"lineno": exc.lineno, "offset": exc.offset, "text": exc.text, "file": file_path},
            )
        return

    if ext == ".json":
        try:
            json.loads(code)
        except Exception as exc:
            raise GuardrailViolation(
                gate_name="Syntax Pre-Flight Gate",
                message=f"Patched JSON has syntax error: {exc}",
                details={"error": str(exc), "file": file_path},
            )
        return

    if ext in (".yaml", ".yml"):
        try:
            import yaml
            yaml.safe_load(code)
            return
        except ImportError:
            validate_yaml_syntax(code, file_path=file_path)
            return
        except Exception as exc:
            raise GuardrailViolation(
                gate_name="Syntax Pre-Flight Gate",
                message=f"Patched YAML has syntax error: {exc}",
                details={"error": str(exc), "file": file_path},
            )

    if ext in (".md", ".markdown", ".mdown", ".txt"):
        fence_count = code.count("```")
        if fence_count % 2 != 0:
            raise GuardrailViolation(
                gate_name="Syntax Pre-Flight Gate",
                message="Patched Markdown has unclosed code fence (```).",
                details={"file": file_path},
            )
        return

    if not ext:
        if file_path in ("", "patched_file.py") or file_name in ("", "patched_file.py"):
            try:
                ast.parse(code, filename=file_path or "patched_file.py")
            except SyntaxError as exc:
                raise GuardrailViolation(
                    gate_name="Syntax Pre-Flight Gate",
                    message=f"Patched Python code has syntax error at line {exc.lineno}: {exc.msg}",
                    details={"lineno": exc.lineno, "offset": exc.offset, "text": exc.text, "file": file_path},
                )
            return

        known_non_python = {
            "dockerfile", "makefile", "containerfile", "jenkinsfile",
            "procfile", "gemfile", "vagrantfile", ".gitattributes", ".gitignore",
        }
        if file_name in known_non_python or file_name.startswith("dockerfile"):
            validate_code_delimiters(code, file_path=file_path)
            return

        first_line = code.split("\n", 1)[0] if code else ""
        if first_line.startswith("#!"):
            if "python" in first_line.lower():
                try:
                    ast.parse(code, filename=file_path)
                except SyntaxError as exc:
                    raise GuardrailViolation(
                        gate_name="Syntax Pre-Flight Gate",
                        message=f"Patched Python code has syntax error at line {exc.lineno}: {exc.msg}",
                        details={"lineno": exc.lineno, "offset": exc.offset, "text": exc.text, "file": file_path},
                    )
                return
            else:
                validate_code_delimiters(code, file_path=file_path)
                return

        try:
            ast.parse(code, filename=file_path)
            return
        except SyntaxError:
            validate_code_delimiters(code, file_path=file_path)
            return

    validate_code_delimiters(code, file_path=file_path)


def apply_patch_hunks(original_text: str, hunks: List[Dict[str, Any]]) -> str:
    """
    Apply a list of hunks with sliding window matching (+/- 10 lines) and global fallback.
    Hunk format: {"start_line": int, "end_line": int, "target_content": str, "replacement_chunk": str}
    """
    lines = original_text.splitlines(keepends=True)
    sorted_hunks = sorted(hunks, key=lambda h: int(h.get("start_line", 1)), reverse=True)

    for hunk in sorted_hunks:
        start_line = int(hunk.get("start_line", 1))
        end_line = int(hunk.get("end_line", start_line))
        target_content = hunk.get("target_content", "")
        replacement = hunk.get("replacement_chunk")
        if replacement is None:
            replacement = hunk.get("replacement_content", "")

        idx_start = max(0, start_line - 1)
        idx_end = min(len(lines), end_line)
        slice_content = "".join(lines[idx_start:idx_end])

        match_idx = None
        match_len = None

        if slice_content == target_content or slice_content.rstrip("\r\n") == target_content.rstrip("\r\n"):
            match_idx = idx_start
            match_len = idx_end - idx_start
        else:
            # Sliding window matching (+/- 10 lines)
            target_norm = target_content.rstrip("\r\n")
            target_line_count = len(target_content.splitlines()) or 1
            window_min = max(0, idx_start - 10)
            window_max = min(len(lines), idx_end + 10)

            for offset in range(window_min, max(window_min + 1, window_max)):
                candidate = "".join(lines[offset:offset + target_line_count]).rstrip("\r\n")
                if candidate == target_norm:
                    match_idx = offset
                    match_len = target_line_count
                    break

        # Whole-file unique fallback
        if match_idx is None:
            target_norm = target_content.rstrip("\r\n")
            target_line_count = len(target_content.splitlines()) or 1
            matches = []
            for offset in range(len(lines) - target_line_count + 1):
                candidate = "".join(lines[offset:offset + target_line_count]).rstrip("\r\n")
                if candidate == target_norm:
                    matches.append(offset)
            if len(matches) == 1:
                match_idx = matches[0]
                match_len = target_line_count

        if match_idx is None:
            raise GuardrailViolation(
                gate_name="Dual-Format Patch Engine",
                message=f"Hunk matching failed: target_content at lines {start_line}-{end_line} could not be matched even with +/-10 sliding window.",
                details={"hunk": hunk},
            )

        repl_lines = replacement.splitlines(keepends=True)
        if replacement and not replacement.endswith("\n") and lines and match_idx < len(lines) and lines[match_idx].endswith("\n"):
            if repl_lines:
                repl_lines[-1] = repl_lines[-1] + "\n"

        lines[match_idx:match_idx + match_len] = repl_lines

    return "".join(lines)


def apply_unified_diff(original_text: str, diff_text: str) -> str:
    """
    Apply a unified diff string (--- a/..., +++ b/..., @@ -l,s +l,s @@) to original_text.
    """
    orig_lines = original_text.splitlines(keepends=True)
    diff_lines = diff_text.splitlines(keepends=True)

    hunk_header_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    hunks = []
    current_hunk = None

    for line in diff_lines:
        m = hunk_header_re.match(line)
        if m:
            if current_hunk:
                hunks.append(current_hunk)
            orig_start = int(m.group(1))
            orig_len = int(m.group(2)) if m.group(2) is not None else 1
            new_start = int(m.group(3))
            new_len = int(m.group(4)) if m.group(4) is not None else 1
            current_hunk = {
                "orig_start": orig_start,
                "orig_len": orig_len,
                "new_start": new_start,
                "new_len": new_len,
                "lines": [],
            }
        elif current_hunk is not None:
            if line.startswith(("+", "-", " ")):
                current_hunk["lines"].append(line)

    if current_hunk:
        hunks.append(current_hunk)

    if not hunks:
        raise GuardrailViolation(
            gate_name="Dual-Format Patch Engine",
            message="No valid unified diff hunks (@@ ... @@) found in diff_text.",
        )

    res_lines = list(orig_lines)
    for h in sorted(hunks, key=lambda x: x["orig_start"], reverse=True):
        idx = max(0, h["orig_start"] - 1)
        del_count = 0
        new_chunk = []
        for l in h["lines"]:
            if l.startswith("-"):
                del_count += 1
            elif l.startswith("+"):
                new_chunk.append(l[1:])
            elif l.startswith(" "):
                del_count += 1
                new_chunk.append(l[1:])
        res_lines[idx:idx + del_count] = new_chunk

    return "".join(res_lines)


def resolve_patched_content(
    original_code: str,
    patched_content: Optional[str] = None,
    hunks: Optional[List[Dict[str, Any]]] = None,
    unified_diff: Optional[str] = None,
) -> str:
    """Resolve final patched content across Hunk JSON, Unified Diff, or whole file."""
    if hunks is not None:
        return apply_patch_hunks(original_code, hunks)
    if unified_diff is not None:
        return apply_unified_diff(original_code, unified_diff)
    if patched_content is not None:
        stripped = patched_content.strip()
        if (stripped.startswith("--- ") or stripped.startswith("@@ ")) and "@@ " in stripped:
            return apply_unified_diff(original_code, patched_content)
        return patched_content
    raise GuardrailViolation(
        gate_name="Dual-Format Patch Engine",
        message="No patch payload provided. Must supply patched_content, hunks, or unified_diff.",
    )


DESTRUCTIVE_PRIMITIVES = [
    (r"\bos\.remove\s*\(", "os.remove()"),
    (r"\bos\.unlink\s*\(", "os.unlink()"),
    (r"\bshutil\.rmtree\s*\(", "shutil.rmtree()"),
    (r"\bos\.rmdir\s*\(", "os.rmdir()"),
    (r"\.unlink\s*\(", "Path.unlink()"),
    (r"\.rmdir\s*\(", "Path.rmdir()"),
    (r"\b(?:rm|del|Remove-Item)\s+-[rf]+", "shell deletion (rm/del/Remove-Item)"),
]


def check_zero_deletion(patched_code: str, file_path: str = "") -> None:
    """Gate 4: Absolute Prohibition of Unauthorized File Deletion Primitives."""
    for pattern, name in DESTRUCTIVE_PRIMITIVES:
        if re.search(pattern, patched_code):
            raise GuardrailViolation(
                gate_name="Gate 4 Zero-Deletion Invariant",
                message=(
                    f"Forbidden file deletion primitive detected: '{name}'. "
                    "Zero-Deletion Invariant strictly prohibits deleting workspace files or data. "
                    "Use Safe Containment (.quarantine/ vault) or inert relocation instead."
                ),
                details={"matched_primitive": name, "file": file_path},
            )


STDLIB_EQUIVALENTS = {
    "requests": "urllib.request",
    "pytz": "zoneinfo",
    "simplejson": "json",
    "mock": "unittest.mock",
}


def check_ponytail_linter(
    original_code: str,
    patched_code: str,
    file_path: str = "",
    repo_path: Optional[Union[str, Path]] = None,
) -> None:
    """
    Gate 1.5: Ponytail Linter (Zero-Bloat Gate).
    Enforces the Ponytail Principle:
    1. Rejects dead code (functions/classes added without callers or __all__ export).
    2. Prioritizes Python standard library over unlisted 3rd-party dependencies.
    """
    p = Path(file_path)
    # Skip dead code checks on test files or fixtures
    is_test_file = "test" in p.name.lower() or "tests" in [part.lower() for part in p.parts]

    ext = p.suffix.lower()
    is_python = ext in (".py", ".pyw") or file_path in ("", "patched_file.py")

    if not is_python:
        return

    try:
        patched_ast = ast.parse(patched_code, filename=file_path)
    except SyntaxError:
        return

    orig_ast = None
    if original_code.strip():
        try:
            orig_ast = ast.parse(original_code, filename=file_path)
        except SyntaxError:
            pass

    orig_defs: Set[str] = set()
    if orig_ast:
        for n in ast.walk(orig_ast):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                orig_defs.add(n.name)

    patched_defs: Set[str] = set()
    for n in ast.walk(patched_ast):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            patched_defs.add(n.name)

    new_defs = patched_defs - orig_defs

    # Check __all__
    all_exports: Set[str] = set()
    for stmt in patched_ast.body:
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name) and t.id == "__all__":
                    if isinstance(stmt.value, (ast.List, ast.Tuple, ast.Set)):
                        for elt in stmt.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                all_exports.add(elt.value)

    # 1. Dead Code Check (YAGNI)
    if not is_test_file:
        for sym in new_defs:
            if sym in all_exports:
                continue
            refs = 0
            for n in ast.walk(patched_ast):
                if isinstance(n, ast.Name) and n.id == sym:
                    refs += 1
                elif isinstance(n, ast.Attribute) and n.attr == sym:
                    refs += 1
            if refs == 0:
                raise GuardrailViolation(
                    gate_name="Gate 1.5 Ponytail Linter",
                    message=(
                        f"Dead code detected: New function or class '{sym}' defined without any "
                        "caller, reference, or export in __all__ (Ponytail Principle / YAGNI)."
                    ),
                    details={"dead_symbol": sym, "file": file_path},
                )

    # 2. Stdlib Prioritization
    orig_imports: Set[str] = set()
    if orig_ast:
        for n in ast.walk(orig_ast):
            if isinstance(n, ast.Import):
                for alias in n.names:
                    orig_imports.add(alias.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom) and n.module:
                orig_imports.add(n.module.split(".")[0])

    patched_imports: Set[str] = set()
    for n in ast.walk(patched_ast):
        if isinstance(n, ast.Import):
            for alias in n.names:
                patched_imports.add(alias.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom) and n.module:
            patched_imports.add(n.module.split(".")[0])

    new_imports = patched_imports - orig_imports
    for imp in new_imports:
        if imp in STDLIB_EQUIVALENTS:
            equiv = STDLIB_EQUIVALENTS[imp]
            # Check if declared in project dependencies
            is_listed = False
            search_dirs = [p.parent, *p.parents] if file_path else []
            if repo_path:
                search_dirs.insert(0, Path(repo_path))
            for d in search_dirs:
                req_f = d / "requirements.txt"
                if req_f.is_file():
                    if imp.lower() in req_f.read_text(encoding="utf-8", errors="ignore").lower():
                        is_listed = True
                        break
                pyp_f = d / "pyproject.toml"
                if pyp_f.is_file():
                    if imp.lower() in pyp_f.read_text(encoding="utf-8", errors="ignore").lower():
                        is_listed = True
                        break
            if not is_listed:
                raise GuardrailViolation(
                    gate_name="Gate 1.5 Ponytail Linter",
                    message=(
                        f"Unlisted 3rd-party dependency '{imp}' imported when standard library '{equiv}' "
                        "is available. Prioritize stdlib (Ponytail Principle)."
                    ),
                    details={"imported_package": imp, "stdlib_alternative": equiv, "file": file_path},
                )


class TransactionalPatchSession:
    """
    Transactional Patch Session with automated snapshot backup and rollback.
    If sandbox tests or validations fail, automatically rolls back target file.
    """
    def __init__(self, target_file_path: Union[str, Path]):
        self.target_file = Path(target_file_path).resolve()
        self.original_exists = self.target_file.exists()
        self.original_content = (
            self.target_file.read_text(encoding="utf-8", errors="replace")
            if self.original_exists else None
        )
        self.committed = False

    def __enter__(self) -> TransactionalPatchSession:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is not None and not self.committed:
            self.rollback()
        return False

    def rollback(self) -> None:
        """Rollback target file to original snapshot."""
        if not self.original_exists:
            if self.target_file.exists():
                try:
                    os.unlink(str(self.target_file))
                except Exception:
                    pass
        else:
            if self.original_content is not None:
                self.target_file.write_text(self.original_content, encoding="utf-8")

    def commit(self) -> None:
        """Commit patch permanently."""
        self.committed = True

    def verify_and_commit(self, verification_callable: Any) -> bool:
        """
        Execute verification test callable.
        If it returns False or raises an exception, automatically roll back.
        """
        try:
            passed = bool(verification_callable())
            if passed:
                self.commit()
                return True
            else:
                self.rollback()
                return False
        except Exception:
            self.rollback()
            raise


class SafePatchManager:
    """Orchestrates patch validation across mandatory safety gates."""

    def __init__(
        self,
        diff_cap: Optional[int] = None,
        new_file_cap: Optional[int] = None,
        semgrep: Optional[SemgrepAdapter] = None,
        enforce_token: bool = False,
        config: Optional[CookieCyberConfig] = None,
        restricted_branches: Optional[Set[str]] = None,
        workspace_root: Optional[Union[str, Path]] = None,
        allowed_roots: Optional[List[Union[str, Path]]] = None,
    ):
        self.config = config or CookieCyberConfig()
        self.diff_cap = diff_cap if diff_cap is not None else self.config.diff_cap_limit
        self.new_file_cap = new_file_cap if new_file_cap is not None else self.config.new_file_cap_limit
        self.restricted_branches = (
            {b.lower() for b in restricted_branches} if restricted_branches is not None
            else set(self.config.restricted_branches)
        )
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else None
        self.allowed_roots = (
            [Path(r).resolve() for r in allowed_roots] if allowed_roots is not None
            else ([self.workspace_root] if self.workspace_root else None)
        )
        self.scanner = ASTScanner(config=self.config)
        self.semgrep = semgrep or SemgrepAdapter()
        self.enforce_token = enforce_token
        self._committer_tokens: Set[str] = set()
        self._tokens_issued: int = 0

    def generate_committer_token(self, role: str = "Lead Orchestrator") -> str:
        """Issue an ephemeral capability session token for authorized Lead Orchestrator."""
        if role != "Lead Orchestrator":
            raise GuardrailViolation(
                gate_name="Single-Committer Gate",
                message=(
                    f"Cannot issue committer token to unauthorized role '{role}'. "
                    "Only 'Lead Orchestrator' holds single-committer authority."
                ),
                details={"role": role, "required_role": "Lead Orchestrator"},
            )
        token = f"lead-token-{secrets.token_hex(16)}"
        self._committer_tokens.add(token)
        self._tokens_issued += 1
        return token

    def validate_committer_token(self, token: Optional[str]) -> bool:
        """Validate whether a token is active and authorized."""
        return bool(token and token in self._committer_tokens)

    def revoke_committer_token(self, token: str) -> None:
        """Revoke an active committer session token."""
        self._committer_tokens.discard(token)

    def check_diff_cap(
        self,
        original_code: str,
        patched_code: str,
        file_name: str = "file.py",
        is_new_file: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Gate 1: Ensure total changed lines <= diff_cap (or new_file_cap for new files)."""
        if is_new_file is None:
            is_new_file = not bool(original_code.strip())

        limit = self.new_file_cap if is_new_file else self.diff_cap
        stats = calculate_diff_stats(original_code, patched_code, file_name)
        stats["is_new_file"] = is_new_file
        stats["effective_limit"] = limit

        if stats["total_changed"] > limit:
            file_type_desc = "New file scaffolding cap exceeded" if is_new_file else "Diff cap exceeded"
            raise GuardrailViolation(
                gate_name="Diff Cap Gate",
                message=(
                    f"{file_type_desc}: {stats['total_changed']} lines changed "
                    f"(limit: {limit}). Shortest working diff wins (Ponytail Principle). "
                    "Decompose this task into smaller atomic patches."
                ),
                details=stats,
            )
        return stats

    def check_syntax_and_zero_regression(
        self,
        original_code: str,
        patched_code: str,
        file_path: str = "patched_file.py",
    ) -> Dict[str, Any]:
        """Gate 2: AST/Polyglot syntax check & Zero-Regression SAST validation."""
        # 1. Polyglot syntax check
        check_polyglot_syntax(patched_code, file_path=file_path)

        ext = Path(file_path).suffix.lower()
        file_name = Path(file_path).name.lower()
        first_line = patched_code.split("\n", 1)[0] if patched_code else ""
        is_python = (ext in (".py", ".pyw")) or (
            not ext and (
                file_path in ("", "patched_file.py")
                or file_name in ("", "patched_file.py")
                or (first_line.startswith("#!") and "python" in first_line.lower())
            )
        )

        # 2. SAST comparison
        if is_python:
            orig_findings = self.scanner.scan_code(original_code, file_path=file_path)
            patched_findings = self.scanner.scan_code(patched_code, file_path=file_path)

            orig_snippets = {(f.cwe_id, f.code_snippet.strip()) for f in orig_findings}
            orig_cwe_counts: Dict[str, int] = {}
            for f in orig_findings:
                orig_cwe_counts[f.cwe_id] = orig_cwe_counts.get(f.cwe_id, 0) + 1

            patched_cwe_counts: Dict[str, int] = {}
            for f in patched_findings:
                patched_cwe_counts[f.cwe_id] = patched_cwe_counts.get(f.cwe_id, 0) + 1

            # Check for newly introduced vulnerabilities or count regressions
            new_vulnerabilities = [
                f for f in patched_findings
                if (f.cwe_id, f.code_snippet.strip()) not in orig_snippets
                or patched_cwe_counts.get(f.cwe_id, 0) > orig_cwe_counts.get(f.cwe_id, 0)
            ]

            if new_vulnerabilities:
                culprit = new_vulnerabilities[0]
                raise GuardrailViolation(
                    gate_name="Zero-Regression SAST Gate",
                    message=(
                        f"Patch introduced new security vulnerability: {culprit.cwe_id} "
                        f"({culprit.title}) at line {culprit.line_number}."
                    ),
                    details={"new_vulnerabilities": [f.to_dict() for f in new_vulnerabilities]},
                )

            return {
                "passed": True,
                "original_findings_count": len(orig_findings),
                "patched_findings_count": len(patched_findings),
                "resolved_findings_count": max(0, len(orig_findings) - len(patched_findings)),
                "residual_findings": [f.to_dict() for f in patched_findings],
                "sast_engine": "ast_scanner",
            }
        else:
            # Polyglot non-Python file: dispatch to Semgrep if available
            if self.semgrep and self.semgrep.is_available():
                import tempfile
                with tempfile.TemporaryDirectory() as tmp_dir:
                    orig_file = Path(tmp_dir) / f"orig{ext}"
                    patch_file = Path(tmp_dir) / f"patch{ext}"
                    orig_file.write_text(original_code, encoding="utf-8")
                    patch_file.write_text(patched_code, encoding="utf-8")

                    orig_res = self.semgrep.scan(orig_file)
                    patch_res = self.semgrep.scan(patch_file)

                    orig_findings_list = orig_res.get("findings", [])
                    patch_findings_list = patch_res.get("findings", [])

                    if len(patch_findings_list) > len(orig_findings_list):
                        new_findings = [f for f in patch_findings_list if f not in orig_findings_list]
                        culprit = new_findings[0] if new_findings else patch_findings_list[0]
                        raise GuardrailViolation(
                            gate_name="Zero-Regression SAST Gate",
                            message=f"Patch introduced new security vulnerability: {culprit.get('cwe_id', 'Vulnerability')} ({culprit.get('title', 'Semgrep finding')}).",
                            details={"new_vulnerabilities": patch_findings_list},
                        )

                    return {
                        "passed": True,
                        "original_findings_count": len(orig_findings_list),
                        "patched_findings_count": len(patch_findings_list),
                        "resolved_findings_count": max(0, len(orig_findings_list) - len(patch_findings_list)),
                        "residual_findings": patch_findings_list,
                        "sast_engine": "semgrep",
                    }

            return {
                "passed": True,
                "original_findings_count": 0,
                "patched_findings_count": 0,
                "resolved_findings_count": 0,
                "residual_findings": [],
                "sast_engine": "polyglot_syntax_only",
            }

    def check_branch_isolation(self, repo_path: Optional[str | Path], task_id: str) -> Dict[str, Any]:
        """Gate 3: Ensure current branch is not main/master."""
        if not repo_path:
            return {"passed": True, "branch": "non-git"}

        current_branch = get_current_git_branch(repo_path)
        if not current_branch:
            return {"passed": True, "branch": "unknown"}

        allowed_restricted = getattr(self, "restricted_branches", RESTRICTED_BRANCHES)
        if current_branch.lower() in allowed_restricted:
            raise GuardrailViolation(
                gate_name="Git Branch Isolation Gate",
                message=(
                    f"Cannot apply patch directly on protected branch '{current_branch}'. "
                    f"Create and switch to an isolated branch (e.g. 'fix/{task_id}') first."
                ),
                details={"current_branch": current_branch, "recommended_branch": f"fix/{task_id}"},
            )

        return {"passed": True, "branch": current_branch}

    def check_single_committer(
        self,
        committer: str = "Lead Orchestrator",
        committer_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Gate: Enforce Single-Committer Isolation. Only Lead Orchestrator can commit code directly."""
        if committer != "Lead Orchestrator":
            raise GuardrailViolation(
                gate_name="Single-Committer Gate",
                message=(
                    f"Agent '{committer}' is not authorized to apply patches directly. "
                    f"Only 'Lead Orchestrator' holds single-committer authority. "
                    f"Worker agents must send proposals via Point-to-Point Mailbox."
                ),
                details={"committer": committer, "required_role": "Lead Orchestrator"},
            )

        # If token was provided, or if tokens have been issued, or enforce_token is enabled:
        token_required = (self._tokens_issued > 0) or bool(self._committer_tokens) or self.enforce_token
        if token_required or committer_token is not None:
            if not committer_token or committer_token not in self._committer_tokens:
                raise GuardrailViolation(
                    gate_name="Single-Committer Gate",
                    message=(
                        f"Single-committer verification failed: Missing or invalid session token for '{committer}'. "
                        "A valid committer_token issued by Lead Orchestrator is required."
                    ),
                    details={"committer": committer, "token_provided": bool(committer_token)},
                )

        return {"passed": True, "committer": committer, "token_verified": bool(committer_token)}

    def preview_surgical_patch(
        self,
        target_file_path: Union[str, Path],
        patched_content: Optional[str] = None,
        hunks: Optional[List[Dict[str, Any]]] = None,
        unified_diff: Optional[str] = None,
        task_id: str = "preview",
        repo_path: Optional[Union[str, Path]] = None,
        committer: str = "Lead Orchestrator",
        committer_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Dry-run evaluation of all gates without modifying the target file on disk.
        Returns diff preview, stats, and gate statuses.
        """
        committer_stats = self.check_single_committer(committer, committer_token=committer_token)

        raw_target = Path(target_file_path)
        if not raw_target.is_absolute() and self.workspace_root:
            target = (self.workspace_root / raw_target).resolve()
        else:
            target = raw_target.resolve()

        # Security: Prevent writing inside .git directory or sensitive files
        lower_parts = [p.lower() for p in target.parts]
        if ".git" in lower_parts:
            raise GuardrailViolation(
                gate_name="Git Branch Isolation Gate",
                message="Cannot target .git internal repository files.",
                details={"target_file": str(target)},
            )
        sensitive_parts = {".ssh", ".aws", ".config"}
        if any(p in sensitive_parts or p.startswith(".env") for p in lower_parts):
            raise GuardrailViolation(
                gate_name="Diff Cap Gate",
                message=f"Cannot apply patch to sensitive configuration file '{target.name}'.",
                details={"target_file": str(target)},
            )

        is_new_file = not target.exists()
        original_code = ""
        if not is_new_file:
            original_code = target.read_text(encoding="utf-8", errors="replace")
            if not original_code.strip():
                is_new_file = True

        final_patched = resolve_patched_content(
            original_code,
            patched_content=patched_content,
            hunks=hunks,
            unified_diff=unified_diff,
        )

        repo = repo_path or find_git_root(target)

        # Gate 4: Zero-Deletion Invariant
        check_zero_deletion(final_patched, file_path=str(target))

        # Gate 1.5: Ponytail Linter
        check_ponytail_linter(original_code, final_patched, file_path=str(target), repo_path=repo)

        # Gate 1: Diff Cap
        diff_stats = self.check_diff_cap(
            original_code,
            final_patched,
            file_name=target.name,
            is_new_file=is_new_file,
        )

        # Gate 2: AST & SAST Zero Regression
        regression_stats = self.check_syntax_and_zero_regression(
            original_code,
            final_patched,
            file_path=str(target),
        )

        # Gate 3: Git Branch Isolation
        branch_stats = self.check_branch_isolation(repo, task_id)

        return {
            "success": True,
            "preview_mode": True,
            "target_file": str(target),
            "committer": committer_stats.get("committer"),
            "token_verified": committer_stats.get("token_verified", False),
            "diff_stats": diff_stats,
            "regression_stats": regression_stats,
            "branch": branch_stats.get("branch"),
            "gates_passed": [
                "Single-Committer Gate",
                "Gate 1 Diff Cap",
                "Gate 1.5 Ponytail Linter",
                "Gate 2 Zero-Regression SAST",
                "Gate 3 Git Branch Isolation",
                "Gate 4 Zero-Deletion Invariant",
            ],
        }

    def apply_safe_patch(
        self,
        target_file_path: Union[str, Path],
        patched_content: Optional[str] = None,
        hunks: Optional[List[Dict[str, Any]]] = None,
        unified_diff: Optional[str] = None,
        task_id: str = "bugfix",
        repo_path: Optional[Union[str, Path]] = None,
        committer: str = "Lead Orchestrator",
        committer_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate all mandatory gates (Single-Committer, Zero-Deletion, Ponytail Linter,
        Diff Cap, Zero-Regression SAST, Branch Isolation) and atomically apply patch if successful.
        """
        # 0. Gate 0: Single-Committer Gate
        committer_stats = self.check_single_committer(committer, committer_token=committer_token)

        raw_target = Path(target_file_path)
        if not raw_target.is_absolute() and self.workspace_root:
            target = (self.workspace_root / raw_target).resolve()
        else:
            target = raw_target.resolve()

        # Security: Prevent writing inside .git directory or sensitive files
        lower_parts = [p.lower() for p in target.parts]
        if ".git" in lower_parts:
            raise GuardrailViolation(
                gate_name="Git Branch Isolation Gate",
                message="Cannot apply patch directly to .git internal repository files.",
                details={"target_file": str(target)},
            )
        sensitive_parts = {".ssh", ".aws", ".config"}
        if any(p in sensitive_parts or p.startswith(".env") for p in lower_parts):
            raise GuardrailViolation(
                gate_name="Diff Cap Gate",
                message=f"Cannot apply patch to sensitive configuration file '{target.name}'.",
                details={"target_file": str(target)},
            )

        # Boundary check: Ensure target does not escape specified repo_path or workspace_root
        if repo_path:
            repo_resolved = Path(repo_path).resolve()
            if not (target == repo_resolved or repo_resolved in target.parents):
                raise GuardrailViolation(
                    gate_name="Git Branch Isolation Gate",
                    message=f"Path traversal violation: Target file '{target}' is outside repository root '{repo_resolved}'.",
                    details={"target_file": str(target), "repo_path": str(repo_resolved)},
                )
        elif self.allowed_roots:
            if not any(target == r or r in target.parents for r in self.allowed_roots):
                raise GuardrailViolation(
                    gate_name="Git Branch Isolation Gate",
                    message=f"Path traversal violation: Target file '{target}' is outside allowed workspace root: {self.workspace_root}",
                    details={"target_file": str(target)},
                )

        is_new_file = not target.exists()
        original_code = ""
        if not is_new_file:
            original_code = target.read_text(encoding="utf-8", errors="replace")
            if not original_code.strip():
                is_new_file = True

        final_patched = resolve_patched_content(
            original_code,
            patched_content=patched_content,
            hunks=hunks,
            unified_diff=unified_diff,
        )

        repo = repo_path or find_git_root(target)

        # Gate 4: Zero-Deletion Invariant
        check_zero_deletion(final_patched, file_path=str(target))

        # Gate 1.5: Ponytail Linter
        check_ponytail_linter(original_code, final_patched, file_path=str(target), repo_path=repo)

        # 1. Gate 1: Diff Cap
        diff_stats = self.check_diff_cap(
            original_code,
            final_patched,
            file_name=target.name,
            is_new_file=is_new_file,
        )

        # 2. Gate 2: AST & SAST Zero Regression
        regression_stats = self.check_syntax_and_zero_regression(
            original_code,
            final_patched,
            file_path=str(target),
        )

        # 3. Gate 3: Git Branch Isolation
        branch_stats = self.check_branch_isolation(repo, task_id)

        # Atomic Write
        target.parent.mkdir(parents=True, exist_ok=True)
        temp_file = target.with_suffix(f"{target.suffix}.tmp")
        try:
            temp_file.write_text(final_patched, encoding="utf-8")
            # os.replace is atomic
            os.replace(temp_file, target)
        finally:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass

        return {
            "success": True,
            "target_file": str(target),
            "committer": committer_stats.get("committer"),
            "token_verified": committer_stats.get("token_verified", False),
            "diff_stats": diff_stats,
            "regression_stats": regression_stats,
            "branch": branch_stats.get("branch"),
        }
