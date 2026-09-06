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
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.ast_scanner import ASTScanner, Finding


DIFF_CAP_LIMIT = 50
RESTRICTED_BRANCHES = {"main", "master", "prod", "production", "release"}


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
    if curr.is_file():
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


class SafePatchManager:
    """Orchestrates patch validation across the 3 mandatory gates."""

    def __init__(self, diff_cap: int = DIFF_CAP_LIMIT):
        self.diff_cap = diff_cap
        self.scanner = ASTScanner()

    def check_diff_cap(self, original_code: str, patched_code: str, file_name: str = "file.py") -> Dict[str, Any]:
        """Gate 1: Ensure total changed lines <= diff_cap."""
        stats = calculate_diff_stats(original_code, patched_code, file_name)
        if stats["total_changed"] > self.diff_cap:
            raise GuardrailViolation(
                gate_name="Diff Cap Gate",
                message=(
                    f"Diff cap exceeded: {stats['total_changed']} lines changed "
                    f"(limit: {self.diff_cap}). Shortest working diff wins (Ponytail Principle). "
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
        """Gate 2: AST syntax check & Zero-Regression SAST validation."""
        # 1. Syntax check
        try:
            ast.parse(patched_code, filename=file_path)
        except SyntaxError as exc:
            raise GuardrailViolation(
                gate_name="Syntax Pre-Flight Gate",
                message=f"Patched code has syntax error at line {exc.lineno}: {exc.msg}",
                details={"lineno": exc.lineno, "offset": exc.offset, "text": exc.text},
            )

        # 2. SAST comparison
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
        }

    def check_branch_isolation(self, repo_path: Optional[str | Path], task_id: str) -> Dict[str, Any]:
        """Gate 3: Ensure current branch is not main/master."""
        if not repo_path:
            return {"passed": True, "branch": "non-git"}

        current_branch = get_current_git_branch(repo_path)
        if not current_branch:
            return {"passed": True, "branch": "unknown"}

        if current_branch.lower() in RESTRICTED_BRANCHES:
            raise GuardrailViolation(
                gate_name="Git Branch Isolation Gate",
                message=(
                    f"Cannot apply patch directly on protected branch '{current_branch}'. "
                    f"Create and switch to an isolated branch (e.g. 'fix/{task_id}') first."
                ),
                details={"current_branch": current_branch, "recommended_branch": f"fix/{task_id}"},
            )

        return {"passed": True, "branch": current_branch}

    def apply_safe_patch(
        self,
        target_file_path: str | Path,
        patched_content: str,
        task_id: str = "bugfix",
        repo_path: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        """
        Validate all 3 gates and atomically apply patch if successful.
        """
        target = Path(target_file_path).resolve()
        original_code = ""
        if target.exists():
            original_code = target.read_text(encoding="utf-8", errors="replace")

        # 1. Gate 1: Diff Cap
        diff_stats = self.check_diff_cap(original_code, patched_content, file_name=target.name)

        # 2. Gate 2: AST & SAST Zero Regression
        regression_stats = self.check_syntax_and_zero_regression(
            original_code,
            patched_content,
            file_path=str(target),
        )

        # 3. Gate 3: Git Branch Isolation
        repo = repo_path or find_git_root(target)
        branch_stats = self.check_branch_isolation(repo, task_id)

        # Atomic Write
        target.parent.mkdir(parents=True, exist_ok=True)
        temp_file = target.with_suffix(f"{target.suffix}.tmp")
        try:
            temp_file.write_text(patched_content, encoding="utf-8")
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
            "diff_stats": diff_stats,
            "regression_stats": regression_stats,
            "branch": branch_stats.get("branch"),
        }
