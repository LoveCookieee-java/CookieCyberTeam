"""
CookieCyberTeam Project Genome Profiler & Adaptive Meta-Guide Engine.
Performs sub-5ms repository stack discovery, toolchain discovery, security posture,
and generates targeted adaptive execution playbooks for MCP agents.
"""

from __future__ import annotations
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from core.config import CookieCyberConfig, DEFAULT_RESTRICTED_BRANCHES


class ProjectGenomeProfiler:
    """Discovers project architecture, test runners, git status, and risk profile in <5ms."""

    def __init__(self, workspace_root: Optional[Union[str, Path]] = None):
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
        if self.workspace_root.is_file():
            self.workspace_root = self.workspace_root.parent
        self.config = CookieCyberConfig.load_from_repo(self.workspace_root)

    def _detect_languages(self, root: Path) -> List[str]:
        langs = []
        if (root / "pyproject.toml").exists() or (root / "setup.py").exists() or (root / "requirements.txt").exists() or list(root.glob("*.py")):
            langs.append("python")
        if (root / "package.json").exists() or (root / "tsconfig.json").exists():
            langs.append("typescript/javascript")
        if (root / "go.mod").exists():
            langs.append("go")
        if (root / "Cargo.toml").exists():
            langs.append("rust")
        if (root / "pom.xml").exists() or (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
            langs.append("java")
        if (root / "CMakeLists.txt").exists() or (root / "Makefile").exists():
            langs.append("c/c++")
        return langs or ["unknown"]

    def _detect_frameworks(self, root: Path) -> List[str]:
        frameworks = []
        # Python frameworks
        req_files = [root / "requirements.txt", root / "pyproject.toml", root / "Pipfile"]
        req_content = ""
        for rf in req_files:
            if rf.is_file():
                try:
                    req_content += rf.read_text(encoding="utf-8", errors="ignore").lower()
                except Exception:
                    pass
        if "fastapi" in req_content:
            frameworks.append("fastapi")
        if "django" in req_content or (root / "manage.py").exists():
            frameworks.append("django")
        if "flask" in req_content:
            frameworks.append("flask")
        if "torch" in req_content or "tensorflow" in req_content:
            frameworks.append("ai/ml")

        # JS frameworks
        pkg_json = root / "package.json"
        if pkg_json.is_file():
            try:
                pkg_text = pkg_json.read_text(encoding="utf-8", errors="ignore").lower()
                if "react" in pkg_text:
                    frameworks.append("react")
                if "next" in pkg_text:
                    frameworks.append("next.js")
                if "express" in pkg_text:
                    frameworks.append("express")
            except Exception:
                pass

        # Java frameworks
        pom_xml = root / "pom.xml"
        if pom_xml.is_file():
            try:
                pom_text = pom_xml.read_text(encoding="utf-8", errors="ignore").lower()
                if "spring-boot" in pom_text:
                    frameworks.append("spring-boot")
            except Exception:
                pass

        return frameworks

    def _detect_test_runner(self, root: Path) -> Dict[str, str]:
        req_files = [root / "requirements.txt", root / "pyproject.toml", root / "Pipfile"]
        has_pytest = False
        for rf in req_files:
            if rf.is_file():
                try:
                    if "pytest" in rf.read_text(encoding="utf-8", errors="ignore").lower():
                        has_pytest = True
                        break
                except Exception:
                    pass
        if (root / "pytest.ini").exists() or has_pytest:
            return {"name": "pytest", "type": "pytest", "command": "pytest -v"}
        if (root / "tests").is_dir():
            test_files = list((root / "tests").glob("test_*.py"))
            if test_files:
                return {"name": "unittest", "type": "unittest", "command": "python -m unittest discover -s tests -v"}
        if (root / "Cargo.toml").exists():
            return {"name": "cargo", "type": "cargo", "command": "cargo test"}
        if (root / "go.mod").exists():
            return {"name": "go test", "type": "go", "command": "go test ./..."}
        if (root / "package.json").exists():
            return {"name": "npm test", "type": "npm_test", "command": "npm test"}
        return {"name": "generic", "type": "generic", "command": "python -m unittest discover -s tests -v"}

    def _get_git_info(self, root: Path) -> Dict[str, Any]:
        git_dir = root / ".git"
        if not git_dir.exists():
            return {"is_git": False, "branch": "non-git", "is_restricted": False, "is_clean": True}

        branch = "unknown"
        head_file = git_dir / "HEAD"
        if head_file.is_file():
            try:
                content = head_file.read_text(encoding="utf-8", errors="ignore").strip()
                if content.startswith("ref: refs/heads/"):
                    branch = content.replace("ref: refs/heads/", "")
            except Exception:
                pass

        if branch == "unknown":
            try:
                res = subprocess.run(
                    ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                    cwd=str(root),
                    capture_output=True,
                    text=True,
                    timeout=2,
                    shell=False,
                )
                if res.returncode == 0:
                    branch = res.stdout.strip()
            except Exception:
                pass

        is_restricted = branch.lower() in self.config.restricted_branches

        is_clean = True
        try:
            res_status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=2,
                shell=False,
            )
            if res_status.returncode == 0:
                is_clean = not bool(res_status.stdout.strip())
        except Exception:
            pass

        return {
            "is_git": True,
            "branch": branch,
            "is_restricted": is_restricted,
            "is_clean": is_clean,
        }

    def _detect_toolchains(self) -> Dict[str, bool]:
        tools = [
            "docker", "semgrep", "r2", "radare2", "ghidra",
            "pytest", "bandit", "strings", "readelf", "objdump",
            "cfr", "jadx", "git",
        ]
        return {t: bool(shutil.which(t)) for t in tools}

    def _determine_risk_profile(self, root: Path, frameworks: List[str]) -> str:
        # Check if contains malware sample hints or binary formats
        for ext in (".bin", ".exe", ".elf", ".apk", ".dex"):
            if list(root.glob(f"*{ext}")):
                return "binary_analysis_and_triage"
        if any(fw in frameworks for fw in ("fastapi", "django", "flask", "express", "next.js")):
            return "web_application_high_surface"
        if (root / "server.py").exists() or (root / "mcp").is_dir():
            return "mcp_server_agentic_system"
        return "software_library_standard"

    def profile(self, workspace_root: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
        """Profile project and return comprehensive genome in <5ms."""
        start_t = time.perf_counter()
        ws = Path(workspace_root).resolve() if workspace_root else self.workspace_root
        if ws.is_file():
            ws = ws.parent

        languages = self._detect_languages(ws)
        frameworks = self._detect_frameworks(ws)
        test_runner = self._detect_test_runner(ws)
        git_info = self._get_git_info(ws)
        toolchains = self._detect_toolchains()
        risk_profile = self._determine_risk_profile(ws, frameworks)

        elapsed_ms = (time.perf_counter() - start_t) * 1000.0

        return {
            "workspace_root": str(ws),
            "primary_language": languages[0] if languages else "unknown",
            "languages": languages,
            "frameworks": frameworks,
            "tech_stack": languages + frameworks,
            "test_runner": test_runner,
            "git": git_info,
            "toolchains": toolchains,
            "risk_profile": risk_profile,
            "diff_cap_limit": self.config.diff_cap_limit,
            "new_file_cap_limit": self.config.new_file_cap_limit,
            "ponytail_mode": getattr(self.config, "ponytail_mode", "full"),
            "enable_ponytail_linter": getattr(self.config, "enable_ponytail_linter", True),
            "discovery_time_ms": round(elapsed_ms, 2),
        }

    discover = profile

    def generate_targeted_test_command(
        self,
        active_file: Optional[str] = None,
        workspace_root: Optional[Union[str, Path]] = None,
    ) -> str:
        """Generate the exact test command for the specified active file or full test suite."""
        profile = self.profile(workspace_root)
        runner_info = profile["test_runner"]
        full_command = runner_info["command"]

        if not active_file:
            return full_command

        p = Path(active_file)
        file_name = p.stem  # e.g. "test_ast_scanner" or "ast_scanner"

        if profile["primary_language"] == "python":
            if file_name.startswith("test_"):
                test_target = f"tests/{p.name}" if not str(p).startswith("tests") else str(p).replace("\\", "/")
            else:
                test_target = f"tests/test_{file_name}.py"

            # Check if this test file exists
            ws = Path(profile["workspace_root"])
            if (ws / test_target).is_file() or not (ws / "tests").exists():
                if runner_info.get("type") == "pytest" or runner_info.get("name") == "pytest":
                    return f"pytest {test_target} -v"
                return f"python -m unittest {test_target} -v"
            elif runner_info.get("type") == "pytest" or runner_info.get("name") == "pytest":
                return f"pytest {active_file} -v"

        return full_command

    def get_adaptive_guide(
        self,
        task_intent: str,
        active_file: Optional[str] = None,
        workspace_root: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Generate cognitive anchor guide: Playbook (2-4 tools in order), active guardrails,
        exact commands, and prohibited actions.
        """
        prof = self.profile(workspace_root)
        targeted_cmd = self.generate_targeted_test_command(active_file, workspace_root)
        regression_cmd = prof["test_runner"]["command"]

        playbooks = {
            "security_audit": [
                "mcp_search_code",
                "mcp_scan_vulnerabilities",
                "mcp_audit_dependencies",
            ],
            "bugfix_patch": [
                "mcp_create_reproduction_test",
                "mcp_preview_surgical_patch",
                "mcp_apply_safe_patch",
                "mcp_execute_sandbox_test",
            ],
            "test_verification": [
                "mcp_execute_sandbox_test",
                "mcp_scan_vulnerabilities",
            ],
            "binary_triage": [
                "mcp_triage_binary",
                "mcp_run_diagnostic_tool",
                "mcp_quarantine_artifact",
            ],
            "containment_incident": [
                "mcp_generate_containment_rule",
                "mcp_terminate_process",
                "mcp_quarantine_artifact",
            ],
            "dependency_audit": [
                "mcp_audit_dependencies",
                "mcp_scan_vulnerabilities",
            ],
            "code_exploration": [
                "mcp_search_code",
                "mcp_adaptive_guide",
            ],
            "code_simplification": [
                "mcp_search_code",
                "mcp_ponytail_review",
                "mcp_preview_surgical_patch",
                "mcp_apply_safe_patch",
            ],
            "architecture_audit": [
                "mcp_ponytail_audit",
                "mcp_ponytail_debt",
                "mcp_audit_dependencies",
                "mcp_scan_vulnerabilities",
            ],
        }

        chosen_playbook = playbooks.get(
            task_intent,
            ["mcp_adaptive_guide", "mcp_search_code", "mcp_scan_vulnerabilities"],
        )

        diff_cap_display = "unlimited ('free')" if prof.get("diff_cap_limit") == "free" else f"maximum {prof.get('diff_cap_limit')} lines"
        new_file_display = "unlimited ('free')" if prof.get("new_file_cap_limit") == "free" else f"maximum {prof.get('new_file_cap_limit')} lines"

        p_mode = prof.get("ponytail_mode", "full")
        p_enabled = prof.get("enable_ponytail_linter", True)
        if p_enabled and p_mode != "off":
            gate_1_5_msg = f"Gate 1.5 (Ponytail Linter): Active in '{p_mode}' mode. Dead code, unlisted dependencies, and AST YAGNI pruning enforced."
        else:
            gate_1_5_msg = "Gate 1.5 (Ponytail Linter): Deactivated ('off' mode)."

        active_guardrails = [
            f"Gate 0 (Single-Committer): Only Lead Orchestrator can apply patches directly.",
            f"Gate 1 (Diff Cap): {diff_cap_display} for modified files, {new_file_display} for new files (Ponytail Principle).",
            gate_1_5_msg,
            f"Gate 2 (Zero-Regression SAST): No new CWE vulnerabilities may be introduced.",
            f"Gate 3 (Git Branch Isolation): Direct commits/patches to '{prof['git']['branch']}' {'are BLOCKED' if prof['git']['is_restricted'] else 'permitted'}.",
            f"Gate 4 (Zero-Deletion Invariant): Absolute prohibition of file deletion primitives (os.remove, unlink, rmdir, del, rm).",
        ]

        prohibited_actions = [
            "Gate 4 (Zero-Deletion Invariant): Do NOT execute file deletion commands (rm, del, Remove-Item, os.remove, unlink, rmdir).",
            "Do NOT use shell=True or unvalidated raw command strings.",
            "Do NOT add new 3rd-party dependencies when Python stdlib suffices.",
        ]
        if prof.get("diff_cap_limit") != "free":
            prohibited_actions.append(f"Do NOT exceed the {prof.get('diff_cap_limit')}-line diff cap on existing files.")
        else:
            prohibited_actions.append("Diff cap is set to 'free' (unlimited line diffs allowed on existing files).")
        prohibited_actions.append("Do NOT push directly to protected branches (main, master, prod).")
        if task_intent == "binary_triage":
            prohibited_actions.append("Zero-Execution Policy: Do NOT execute live untrusted binaries on host.")

        return {
            "success": True,
            "task_intent": task_intent,
            "active_file": active_file,
            "playbook": chosen_playbook,
            "recommended_tool_sequence": chosen_playbook,
            "rules": {"mandatory_gates": active_guardrails},
            "active_guardrails": active_guardrails,
            "exact_command_lines": {
                "targeted_test": targeted_cmd,
                "full_regression_test": regression_cmd,
            },
            "prohibited_actions": prohibited_actions,
            "project_genome": prof,
        }
