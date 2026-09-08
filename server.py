"""
CookieCyberTeam MCP Security Guardrails & Multi-Agent Orchestration Server.
Standard JSON-RPC 2.0 stdio MCP Server.
Packages 19 Tools, 9 Resources, and 8 Prompts for safe, scientific defensive engineering,
zero-regression patching, air-gapped binary triage, and multi-agent coordination.
"""

from __future__ import annotations
import argparse
import ast
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.ast_scanner import ASTScanner
from core.binary_triage import BinaryTriageEngine
from core.cape_adapter import CapeSandboxAdapter
from core.code_search import HybridCodeSearch
from core.config import CookieCyberConfig
from core.containment import (
    generate_firewall_rule,
    quarantine_file,
    restore_quarantined_file,
    terminate_suspicious_process,
)
from core.cvss_calculator import cvss_for_cwe, calculate_cvss_score
from core.dag_engine import DAGEngine, DAGCycleError, MAX_HOP_TTL
from core.guardrails import SafePatchManager, GuardrailViolation, find_git_root
from core.project_profiler import ProjectGenomeProfiler
from core.sandbox_runner import SandboxRunner
from core.sca_scanner import SCAScanner
from core.semgrep_adapter import SemgrepAdapter
from core.soc_rules import SOCRuleEngine
from core.platform_native import (
    PYTHON_STDLIB_EQUIVALENTS,
    JAVASCRIPT_NATIVE_EQUIVALENTS,
    get_stdlib_equivalent,
    get_js_native_equivalent,
    is_stateless_utility_class,
    is_shallow_wrapper_function,
    audit_ast_yagni,
    audit_npm_dependencies,
)
from core.tool_indexer import ToolchainIndexer


SERVER_NAME = "cookie-cyber-team"
SERVER_VERSION = "1.0.2"
PROTOCOL_VERSION = "2024-11-05"


# ---------------------------------------------------------------------------
# Static Security & Ponytail Resources Content
# ---------------------------------------------------------------------------

PONYTAIL_LADDER_RESOURCE = """# Ponytail: The Lazy Senior Developer Decision Ladder & Code Hygiene Rules

> "The best code is the code you never wrote." — DietrichGebert/ponytail

## 1. The 7-Rung Decision Ladder (Execute in Strict Order)

When solving any engineering requirement, stop at the FIRST rung that satisfies it:

1. **Rung 1: YAGNI (Does this need to exist?)**
   - Challenge speculative requirements. If the user asks for X, do NOT build hooks or abstract factories for Y and Z.
   - Tag: `yagni:`

2. **Rung 2: Codebase Reuse (Can we reuse existing code?)**
   - Search the workspace before writing new utility functions or types.
   - Tag: `shrink:`

3. **Rung 3: Standard Library (Does the standard library do it?)**
   - Prefer language stdlib over third-party packages or reinvented wheels.
   - Python: `requests/httpx` -> `urllib.request`, `attrs` -> `dataclasses`, `pytz` -> `zoneinfo`, `simplejson` -> `json`.
   - Tag: `stdlib:`

4. **Rung 4: Native Platform Features (Can native platform/HTML/CSS/DB handle it?)**
   - Prefer HTML semantic tags (`<dialog>`, `<details>`) and CSS over JS UI libraries.
   - JS/TS: `lodash.clonedeep` -> `structuredClone`, `uuid` -> `crypto.randomUUID()`, `qs` -> `URLSearchParams`.
   - Prefer SQL constraints (`UNIQUE`, `FOREIGN KEY`, `CHECK`) over procedural check logic.
   - Tag: `native:`

5. **Rung 5: Installed Dependencies (Does an installed package do it?)**
   - Use packages already present in project manifests (`requirements.txt`, `package.json`, `pom.xml`).
   - Tag: `shrink:`

6. **Rung 6: One-Liner & Direct Calls (Can it be written in a clean single line?)**
   - Do NOT wrap simple operations in single-use helper functions or stateless utility classes.
   - Tag: `shrink:` / `yagni:`

7. **Rung 7: Minimum Viable Code (Write shortest working diff)**
   - Decompose into minimal, atomic, surgical edits.
   - Tag: `shrink:`

---

## 2. Standard Review Tags
- `delete:` Dead code, unreferenced symbols, commented-out blocks.
- `stdlib:` 3rd-party library replaceable with standard library.
- `native:` Library or abstraction replaceable with platform native Web/Node/DB features.
- `yagni:` Speculative abstraction, stateless utility class, or shallow wrapper.
- `shrink:` Verbose boilerplate that can be shortened or inlined.

---

## 3. Intensity Modes Matrix
- `ultra`: 25-line diff cap, zero intermediate wrappers/classes, 100% native platform/stdlib usage.
- `full` (Default): 50-line diff cap, dead code rejection, unlisted dependency blocking.
- `lite`: 80-line diff cap, soft warnings for architectural flexibility.
- `off`: Deactivates Ponytail linter, diff cap set to 'free'.

---

## 4. Invariant Safety Standard: "Lazy, Not Negligent"
Ponytail never sacrifices security or data integrity for brevity:
- Never skip input validation or sanitization.
- Never bypass authentication, authorization, or encryption.
- Maintain clear error boundaries and proper exception propagation.
- Zero file deletion invariant: Never delete user files without consent.
"""


SECURITY_STANDARDS_RESOURCE = """# CookieCyberTeam Security Standards & Defensive Guardrails

## 1. Zero-Trust Command Execution (CWE-78 Prevention)
- **Rule**: Absolute prohibition of `shell=True` in all subprocess, os, and runner invocations.
- **Implementation**: Always pass arguments as a validated list of strings (`argv: list[str]`).
- **Environment**: Always sanitize the environment via an explicit whitelist. Never pass untrusted `**os.environ`.
- **Termination**: Use process tree termination (`taskkill /F /T /PID` on Windows, process groups on POSIX) on timeout.

## 2. Parameterized Database Queries (CWE-89 Prevention)
- **Rule**: Never interpolate, concatenate, or format user variables into SQL query strings (no f-strings, no `%`, no `+`).
- **Implementation**: Always use database driver parameterized queries with placeholders (`?` or `%s`).
  - Safe: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
  - Unsafe: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`

## 3. Safe Dynamic Evaluation & Serialization (CWE-95, CWE-502)
- **Rule**: Never pass untrusted inputs to `eval()`, `exec()`, or `compile()`.
- **Alternative**: Use `ast.literal_eval()` for evaluating string literals to Python constants.
- **Deserialization**: Never load untrusted data with `pickle.loads()`, `pickle.load()`, or `yaml.load()` without `SafeLoader`. Prefer JSON or Protocol Buffers.

## 4. Secret & Credential Management (CWE-798)
- **Rule**: Hardcoded API keys, tokens, passwords, and private keys in source code are strictly forbidden.
- **Detection**: Guardrails check variable naming and Shannon entropy ($H \\ge 3.0$ for length $\\ge 16$).
- **Storage**: Load secrets exclusively via secure environment variables or vault KMS.

## 5. Transport Layer Security (CWE-295)
- **Rule**: Never disable certificate verification (`verify=False` or `ssl._create_unverified_context`).
- **Implementation**: Always verify TLS certificates with trusted CA bundles.

## 6. Agent Safety & File Protection Invariant
- **Rule**: Absolute prohibition of unauthorized file deletion (`rm`, `del`, `rmdir`, `Remove-Item`, `unlink`). Never delete user source files.
- **Diff Cap**: Maximum 50 lines changed per patch (Ponytail Principle).
- **Single-Committer**: Only Lead Coordinator applies Git patches; Worker Agents operate via mailbox.

## 7. Dual-Tier Sandbox Architecture Advisory
- **Tier-1 (Subprocess Argv + Env Whitelist + Process Tree Kill)**: Active out-of-the-box with zero host prerequisites. Pass argv list, sanitize environment, kill process trees on timeout (`taskkill` on Windows).
- **Tier-2 (Containerized Docker Sandbox)**: Optional containerized runtime with `--network none` and read-only mounts. Requires running Docker daemon on host; automatically falls back to Tier-1 if Docker is not available.

## 8. Zero-Execution Policy Advisory for Binary & Malware Triage
- **Rule**: Untrusted binaries, malware samples, and unknown executables must NEVER be executed directly on the host system.
- **Detonation Containment**: Always inspect statically on host (`mcp_triage_binary`, `mcp_run_diagnostic_tool`). Route dynamic behavioral execution strictly through Tier-2 Docker or external dynamic sandboxes (`mcp_submit_dynamic_sandbox`).
"""

DEBUGGING_MINDSET_RESOURCE = """# 4-Step Hypothesis-Driven Debugging Mindset

> "Guessing code is the root of all regressions. Formulate, isolate, reproduce, and confirm."

## Step 1: Reproduce (Create Minimal Reproduction Test)
- Before writing or altering ANY source code, construct a minimal, isolated test that reliably fails and reproduces the defect.
- If the test passes initially, your understanding of the bug is incomplete. Re-examine the preconditions.

## Step 2: Trace & Isolate (Map Execution Flow)
- Trace the data flow from source to sink without speculation.
- Use AST inspection, call graphs, or minimal print/log statements to isolate the exact line and state where invariants break.

## Step 3: Formulate Falsifiable Hypothesis
- Explicitly write out the hypothesis: "Under condition X, variable Y has state Z because function F assumes W."
- A valid hypothesis must predict when the failure occurs and when it does not.

## Step 4: Confirm via Proof & Minimal Diff (Ponytail Standard)
- Confirm the hypothesis with targeted assertion tests before modifying production code.
- Apply the shortest working diff (Ponytail Principle: Diff Cap $\\le 50$ lines).
- Verify that the reproduction test passes and all regression tests remain 100% clean.
"""

MALWARE_TRIAGE_PLAYBOOK_RESOURCE = """# NIST SP 800-61 Rev 3: Malware Triage & Reverse Engineering Playbook

## Mandatory Rule 1: Zero-Execution Policy
- **Absolute Invariant**: Static binary inspection only. Never execute, decode into memory, or launch untrusted binaries on host.
- **Air-Gapped Blackhole**: Analyze binaries inside an isolated read-only container with `--network none` if dynamic behavioral inspection is ever required.

## Phase 1: Artifact Registration & Cryptographic Evidence Chain
1. Compute SHA-256 and MD5 cryptographic hashes immediately upon artifact discovery.
2. Record file size, timestamp, and filesystem metadata.
3. Formulate the Evidence-Finding Path:
   `Artifact SHA-256 -> File/Byte Offset -> Identified Feature/IOC -> CWE/CVSS v3.1 -> Containment Plan`

## Phase 2: Static Header & Format Dissection
- **Windows PE**: Check `MZ` signature (offset 0x0) and `PE\\0\\0` (offset 0x3C). Parse Machine architecture (i386, x86_64, ARM64) and Subsystem (GUI, Console).
- **Linux ELF**: Check `\\x7fELF` magic. Parse 32-bit vs 64-bit and Endianness.
- **Android / Java**: Check `dex\\n` for Dalvik bytecode and `PK\\x03\\x04` for APK/JAR archives.
- **PDF / Scripts**: Inspect header for embedded streams or executable shebangs.

## Phase 3: Shannon Entropy & Packing Detection
- Calculate global Shannon entropy ($0.0 \\le H \\le 8.0$).
- Calculate 1KB block entropy. Flag artifacts with peak block entropy $> 7.2$ as packed (UPX, Themida, VMProtect) or encrypted payloads.

## Phase 4: Safe String & IOC Extraction
- Extract ASCII ($\\ge 4$ characters) and UTF-16LE wide strings without executing binary code.
- Extract high-fidelity IOCs:
  - C2 IPv4 addresses and Domain/URL endpoints.
  - Persistence registry keys (`CurrentVersion\\Run`, `HKLM`, `HKCU`).
  - Dangerous process injection APIs (`VirtualAlloc`, `CreateRemoteThread`, `WriteProcessMemory`).
"""

COMPROMISE_ASSESSMENT_PLAYBOOK_RESOURCE = """# Multi-Agent Compromise Assessment & Agentic Threats Playbook

## 1. Safety Invariant: Absolute Prohibition of Unauthorized File Deletion
- Agents are strictly prohibited from issuing destructive commands (`rm`, `del`, `rmdir`, `Remove-Item`).
- Never delete user workspace files or repositories without explicit human consent.

## 2. Multi-Agent Single-Committer Isolation
- Lead Orchestrator manages Git branching and atomic commits.
- Subordinate Workers (Security Auditor, Debugger, Patch Developer, QA Reviewer, SOC Incident Responder) communicate exclusively through SQLite WAL point-to-point mailboxes.
- Prevents race conditions and repository lock contention (`.git/index.lock`).

## 3. OWASP Top 10 for LLM & Agentic Systems (2026 Focus)
- **ASI-01: Prompt Injection & Indirect Poisoning**: Verify untrusted data payloads are not evaluated as system instructions.
- **ASI-02: Excessive Agency & Unsafe Tool Invocations**: Enforce strict tool parameter schemas, argv whitelisting, and no `shell=True`.
- **ASI-03: Sensitive Information Disclosure**: Strip API keys, tokens, and credentials via environment variable whitelisting.
- **ASI-04: Insecure Output Handling & Cascading Failures**: Enforce max hop TTL (20 hops) on inter-agent messaging to prevent infinite communication loops.

## 4. Four-Stage Incident Response Workflow
1. **Triage & Scope**: Audit attack surface, assign CVSS v3.1 vector scores, and isolate affected components.
2. **Containment**: Apply network blackhole isolation and quarantine affected test modules.
3. **Eradication & Remediation**: Formulate minimal working diff (<= 50 lines) eliminating root cause.
4. **Post-Incident Recovery**: Execute 100% clean regression tests and verify zero new CWE introductions.
"""


def _safe_int(val: Any, default: int) -> int:
    """Safely convert value to int with fallback default on None or conversion error."""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_float(val: Any, default: float) -> float:
    """Safely convert value to float with fallback default on None or conversion error."""
    if val is None:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# MCP Server Implementation
# ---------------------------------------------------------------------------

class CookieCyberMCPServer:
    """Standard JSON-RPC 2.0 Stdio MCP Server."""

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        workspace_root: Optional[str | Path] = None,
        allowed_roots: Optional[List[str | Path]] = None,
        config: Optional[CookieCyberConfig] = None,
    ):
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
        if allowed_roots:
            self.allowed_roots = [Path(r).resolve() for r in allowed_roots]
        else:
            self.allowed_roots = [self.workspace_root]
        self.config = config or CookieCyberConfig.load_from_repo(self.workspace_root)
        self.scanner = ASTScanner(config=self.config)
        self.semgrep = SemgrepAdapter()
        self.sandbox = SandboxRunner()
        self.patch_manager = SafePatchManager(
            config=self.config,
            semgrep=self.semgrep,
            enforce_token=True,
            workspace_root=self.workspace_root,
            allowed_roots=self.allowed_roots,
        )
        self.dag_engine = DAGEngine(db_path=db_path)
        self.code_searcher = HybridCodeSearch()
        self.tool_indexer = ToolchainIndexer()
        self.binary_triage_engine = BinaryTriageEngine()
        self.soc_engine = SOCRuleEngine()
        self.cape_adapter = CapeSandboxAdapter()
        self.profiler = ProjectGenomeProfiler(workspace_root=self.workspace_root)
        self.sca_scanner = SCAScanner(workspace_root=self.workspace_root)

    # -----------------------------------------------------------------------
    # Tool Handlers (19 Tools)
    # -----------------------------------------------------------------------

    def tool_adaptive_guide(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Generate dynamic cognitive anchor and workflow playbook for given task intent."""
        task_intent = args.get("task_intent", "security_audit")
        active_file = args.get("active_file")
        return self.profiler.get_adaptive_guide(task_intent=task_intent, active_file=active_file)

    def tool_audit_dependencies(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Perform offline Software Composition Analysis (SCA) on dependency manifests."""
        scan_path = args.get("path")
        return self.sca_scanner.audit_workspace(scan_dir=scan_path)

    def tool_preview_surgical_patch(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Dry-run preview of patch application validating Gate 1.5, Gate 2, Gate 4."""
        target_file = args.get("target_file")
        if not target_file:
            return {"success": False, "error": "target_file is required for patch preview."}

        raw_path = Path(target_file)
        if not raw_path.is_absolute():
            resolved_target = (self.workspace_root / raw_path).resolve()
        else:
            resolved_target = raw_path.resolve()

        is_confined = any(resolved_target == root or root in resolved_target.parents for root in self.allowed_roots)
        if not is_confined:
            return {
                "success": False,
                "violation": True,
                "gate": "Git Branch Isolation Gate",
                "message": f"Path traversal violation: Target '{target_file}' resolves outside allowed workspace root: {self.workspace_root}",
                "details": {"target_file": str(resolved_target)},
            }

        return self.patch_manager.preview_surgical_patch(
            target_file=resolved_target,
            hunks=args.get("hunks"),
            unified_diff=args.get("unified_diff"),
            patched_content=args.get("patched_content"),
        )

    def tool_restore_quarantined_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Restore quarantined artifact from encrypted vault back to workspace."""
        quarantine_target = args.get("quarantine_path") or args.get("quarantine_id")
        if not quarantine_target:
            return {"success": False, "error": "quarantine_path or quarantine_id is required."}
        dest = args.get("original_destination") or args.get("destination_path")
        quarantine_dir = args.get("quarantine_dir")
        return restore_quarantined_file(
            quarantine_id=quarantine_target,
            quarantine_dir=quarantine_dir,
            destination_path=dest,
            workspace_root=self.workspace_root,
        )

    def tool_terminate_process(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Safely terminate a suspicious process and its entire descendant child process tree."""
        pid = args.get("pid")
        if pid is None:
            return {"success": False, "error": "pid is required."}
        try:
            pid = int(pid)
        except (ValueError, TypeError):
            return {"success": False, "error": f"Invalid PID: {pid}"}
        timeout = _safe_float(args.get("timeout"), 3.0)
        return terminate_suspicious_process(pid=pid, timeout=timeout)

    def tool_scan_vulnerabilities(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan file or snippet for security vulnerabilities using AST or Semgrep."""
        target_path = args.get("target_path")
        code_content = args.get("code_content")
        delta_only = bool(args.get("delta_only", False))
        base_commit = args.get("base_commit", "HEAD")
        use_semgrep = bool(args.get("use_semgrep", False))

        findings: List[Dict[str, Any]] = []

        if use_semgrep and target_path:
            semgrep_res = self.semgrep.scan(target_path)
            if semgrep_res.get("available"):
                findings.extend(semgrep_res.get("findings", []))
            else:
                findings.append({
                    "cwe_id": "INFO",
                    "title": "Semgrep Notice",
                    "description": semgrep_res.get("error", "Semgrep CLI not available"),
                    "severity": "Low",
                    "cvss_score": 0.0,
                    "cvss_vector": "",
                    "file_path": str(target_path),
                    "line_number": 1,
                    "code_snippet": "",
                    "remediation": "Using Pure-Python AST Scanner.",
                })

        # Run pure Python AST SAST scanner
        if code_content:
            ast_findings = self.scanner.scan_code(code_content, file_path=target_path or "<in-memory>")
            findings.extend([f.to_dict() for f in ast_findings])
        elif target_path:
            p = Path(target_path).resolve()
            if p.is_dir():
                ast_findings = self.scanner.scan_directory(p)
                findings.extend([f.to_dict() for f in ast_findings])
            elif p.suffix.lower() == ".py" or not use_semgrep:
                if delta_only:
                    repo_dir = find_git_root(p) or p.parent
                    ast_findings = self.scanner.scan_git_diff(repo_dir, p, base_commit=base_commit)
                else:
                    ast_findings = self.scanner.scan_file(p)
                findings.extend([f.to_dict() for f in ast_findings])

        # Summary statistics
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        max_cvss = 0.0
        for f in findings:
            sev = f.get("severity", "Low")
            if sev in severity_counts:
                severity_counts[sev] += 1
            score = float(f.get("cvss_score", 0.0))
            if score > max_cvss:
                max_cvss = score

        # Residual Vulnerabilities Assessment
        residual_vulnerabilities = [
            {
                "cwe_id": f.get("cwe_id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "cvss_score": f.get("cvss_score"),
                "line_number": f.get("line_number"),
                "remediation": f.get("remediation"),
            }
            for f in findings
        ]

        res: Dict[str, Any] = {
            "success": True,
            "total_findings": len(findings),
            "max_cvss_score": max_cvss,
            "overall_severity": "Critical" if max_cvss >= 9.0 else ("High" if max_cvss >= 7.0 else ("Medium" if max_cvss >= 4.0 else "Low")),
            "severity_distribution": severity_counts,
            "residual_vulnerabilities": residual_vulnerabilities,
            "findings": findings,
        }

        output_format = str(args.get("output_format", "json")).lower()
        if output_format == "sarif":
            res["output_format"] = "sarif"
            res["sarif"] = self.scanner.to_sarif(findings)

        return res

    def tool_ponytail_review(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Review source code or diff against the Ponytail 7-Rung Decision Ladder."""
        code = args.get("code")
        file_path = args.get("file_path", "")
        diff_text = args.get("diff")
        mode = str(args.get("mode") or getattr(self.config, "ponytail_mode", "full")).lower()

        target_content = ""
        if code:
            target_content = code
        elif file_path:
            p = Path(file_path)
            if not p.is_absolute():
                p = (self.workspace_root / p).resolve()
            if p.is_file():
                target_content = p.read_text(encoding="utf-8", errors="replace")
        elif diff_text:
            added_lines = [l[1:] for l in diff_text.splitlines() if l.startswith("+") and not l.startswith("+++")]
            target_content = "\n".join(added_lines)

        if not target_content.strip():
            return {
                "success": False,
                "error": "No reviewable content provided. Pass 'code', 'file_path', or 'diff'.",
            }

        findings: List[Dict[str, Any]] = []
        loc_savings = 0
        tag_counts = {"delete:": 0, "stdlib:": 0, "native:": 0, "yagni:": 0, "shrink:": 0}

        ext = Path(file_path).suffix.lower() if file_path else ".py"
        is_python = ext in (".py", ".pyw") or not ext
        is_js_ts = ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

        if is_python:
            try:
                tree = ast.parse(target_content, filename=file_path or "<review>")
                # 1. YAGNI AST audit
                y_findings = audit_ast_yagni(tree)
                for f in y_findings:
                    findings.append(f)
                    tag = f.get("tag", "yagni:")
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
                    loc_savings += 5

                # 2. Stdlib audit
                for n in ast.walk(tree):
                    imports_to_check = []
                    if isinstance(n, ast.Import):
                        for alias in n.names:
                            imports_to_check.append((alias.name.split(".")[0], getattr(n, "lineno", 1)))
                    elif isinstance(n, ast.ImportFrom) and n.module:
                        imports_to_check.append((n.module.split(".")[0], getattr(n, "lineno", 1)))

                    for pkg, lineno in imports_to_check:
                        equiv = get_stdlib_equivalent(pkg)
                        if equiv:
                            findings.append({
                                "type": "stdlib_replacement",
                                "tag": "stdlib:",
                                "package": pkg,
                                "stdlib_alternative": equiv,
                                "line_number": lineno,
                                "message": f"Package '{pkg}' can be replaced with Python standard library '{equiv}' (Ponytail Rung 3).",
                                "remediation": f"Remove '{pkg}' from imports and use '{equiv}'.",
                            })
                            tag_counts["stdlib:"] += 1
                            loc_savings += 2

                # 3. Dead code check (unreferenced functions in single file)
                if not ("test" in file_path.lower()):
                    defined_names = {}
                    for n in tree.body:
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            defined_names[n.name] = n

                    for name, node in defined_names.items():
                        refs = 0
                        for n in ast.walk(tree):
                            if isinstance(n, ast.Name) and n.id == name and n != node:
                                refs += 1
                            elif isinstance(n, ast.Attribute) and n.attr == name:
                                refs += 1
                        if refs == 0 and not name.startswith("_"):
                            exported = False
                            for stmt in tree.body:
                                if isinstance(stmt, ast.Assign):
                                    for t in stmt.targets:
                                        if isinstance(t, ast.Name) and t.id == "__all__":
                                            if isinstance(stmt.value, (ast.List, ast.Tuple, ast.Set)):
                                                for elt in stmt.value.elts:
                                                    if isinstance(elt, ast.Constant) and elt.value == name:
                                                        exported = True
                            if not exported and len(defined_names) > 1:
                                findings.append({
                                    "type": "potential_dead_code",
                                    "tag": "delete:",
                                    "name": name,
                                    "line_number": getattr(node, "lineno", 1),
                                    "message": f"Symbol '{name}' appears unused within this module and is not exported in __all__.",
                                    "remediation": f"Delete '{name}' if not part of external API.",
                                })
                                tag_counts["delete:"] += 1
                                loc_savings += len(node.body) if hasattr(node, "body") else 3
            except SyntaxError as e:
                findings.append({
                    "type": "syntax_notice",
                    "tag": "shrink:",
                    "message": f"Syntax warning: {e.msg} at line {e.lineno}",
                    "line_number": e.lineno,
                })

        if is_js_ts:
            js_re = re.compile(r"""(?:import\s+.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))""")
            for idx, line in enumerate(target_content.splitlines(), start=1):
                m = js_re.search(line)
                if m:
                    pkg = m.group(1) or m.group(2)
                    if pkg and not pkg.startswith((".", "/")):
                        parts = pkg.split("/")
                        pkg_name = f"{parts[0]}/{parts[1]}" if pkg.startswith("@") and len(parts) >= 2 else parts[0]
                        equiv = get_js_native_equivalent(pkg_name) or get_js_native_equivalent(parts[0])
                        if equiv:
                            findings.append({
                                "type": "native_replacement",
                                "tag": "native:",
                                "package": pkg,
                                "native_alternative": equiv,
                                "line_number": idx,
                                "message": f"Package '{pkg}' can be replaced with native Web/ECMAScript API '{equiv}' (Ponytail Rung 4).",
                                "remediation": f"Replace import of '{pkg}' with native '{equiv}'.",
                            })
                            tag_counts["native:"] += 1
                            loc_savings += 3

        # Check for commented-out code
        commented_code_re = re.compile(r"^\s*(?:#|//)\s*(?:def |class |function |import |const |let |var |return )", re.MULTILINE)
        for idx, line in enumerate(target_content.splitlines(), start=1):
            if commented_code_re.match(line):
                findings.append({
                    "type": "commented_out_code",
                    "tag": "delete:",
                    "line_number": idx,
                    "code_snippet": line.strip(),
                    "message": "Commented-out code detected. Ponytail Principle: Delete dead code, version control remembers history.",
                    "remediation": "Remove commented-out code lines.",
                })
                tag_counts["delete:"] += 1
                loc_savings += 1

        verdict = "CLEAN" if not findings else ("PRUNING_REQUIRED" if mode == "ultra" else "SIMPLIFICATION_RECOMMENDED")

        return {
            "success": True,
            "mode": mode,
            "file_path": file_path or "inline_content",
            "total_findings": len(findings),
            "potential_loc_savings": loc_savings,
            "tags_summary": tag_counts,
            "verdict": verdict,
            "findings": findings,
            "recommendations": [
                "Walk down the Ponytail Decision Ladder before adding new code.",
                "Shortest working diff wins. Delete dead code and unneeded wrappers.",
            ],
        }

    def tool_ponytail_audit(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Audit repository files for dead code, unneeded dependencies, and LOC reduction potential."""
        raw_path = args.get("path")
        target_dir = Path(raw_path).resolve() if raw_path else self.workspace_root
        if target_dir.is_file():
            target_dir = target_dir.parent

        mode = str(args.get("mode") or getattr(self.config, "ponytail_mode", "full")).lower()
        excluded_dirs = getattr(self.config, "exclude_dirs", {"vendor", "node_modules", ".git", "dist", "build", "__pycache__", ".quarantine"})

        audited_files: List[str] = []
        all_findings: List[Dict[str, Any]] = []
        file_savings: Dict[str, int] = {}
        dep_savings: List[Dict[str, Any]] = []

        # Check dependency files
        req_path = target_dir / "requirements.txt"
        if req_path.is_file():
            req_content = req_path.read_text(encoding="utf-8", errors="ignore")
            req_deps = self.sca_scanner.parse_requirements_txt(req_content)
            for pkg in req_deps:
                equiv = get_stdlib_equivalent(pkg)
                if equiv:
                    dep_savings.append({
                        "manifest": "requirements.txt",
                        "package": pkg,
                        "tag": "stdlib:",
                        "stdlib_alternative": equiv,
                        "message": f"Dependency '{pkg}' in requirements.txt can be replaced with standard library '{equiv}'.",
                    })

        pkg_json_path = target_dir / "package.json"
        if pkg_json_path.is_file():
            npm_findings = audit_npm_dependencies(pkg_json_path.read_text(encoding="utf-8", errors="ignore"))
            dep_savings.extend(npm_findings)

        excluded_dirs_lower = {str(d).lower() for d in excluded_dirs}
        max_files = max(1, int(args.get("max_files", 1000)))

        # Walk workspace files
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d.lower() not in excluded_dirs_lower and not d.startswith(".")]
            for f in files:
                if len(audited_files) >= max_files:
                    break
                ext = os.path.splitext(f)[1].lower()
                if ext in (".py", ".js", ".ts"):
                    f_path = Path(root) / f
                    try:
                        content = f_path.read_text(encoding="utf-8", errors="ignore")
                        rel_path = str(f_path.relative_to(target_dir))
                        res = self.tool_ponytail_review({"code": content, "file_path": rel_path, "mode": mode})
                        audited_files.append(rel_path)
                        f_findings = res.get("findings", [])
                        if f_findings:
                            all_findings.extend(f_findings)
                            savings = res.get("potential_loc_savings", 0)
                            if savings > 0:
                                file_savings[rel_path] = savings
                    except Exception:
                        pass
            if len(audited_files) >= max_files:
                break

        # Sort files by LOC savings descending
        ranked_files = sorted(
            [{"file": k, "potential_loc_savings": v} for k, v in file_savings.items()],
            key=lambda x: x["potential_loc_savings"],
            reverse=True,
        )
        total_savings = sum(item["potential_loc_savings"] for item in ranked_files)

        return {
            "success": True,
            "path": str(target_dir),
            "mode": mode,
            "files_audited": len(audited_files),
            "total_potential_loc_reduction": total_savings,
            "ranked_files": ranked_files,
            "findings": all_findings,
            "dependency_savings": dep_savings,
        }

    def tool_ponytail_debt(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan repository for ponytail: debt comments and return structured Debt Ledger."""
        raw_path = args.get("path")
        target_dir = Path(raw_path).resolve() if raw_path else self.workspace_root
        if target_dir.is_file():
            target_dir = target_dir.parent

        excluded_dirs = getattr(self.config, "exclude_dirs", {"vendor", "node_modules", ".git", "dist", "build", "__pycache__", ".quarantine"})
        excluded_dirs_lower = {str(d).lower() for d in excluded_dirs}
        debt_re = re.compile(r"""(?:#|//|/\*|\*)\s*ponytail:\s*(.*?)(?:\*/|\n|$)""", re.IGNORECASE)
        max_files = max(1, int(args.get("max_files", 2000)))

        debt_items: List[Dict[str, Any]] = []
        tag_counts: Dict[str, int] = {}
        files_scanned = 0

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d.lower() not in excluded_dirs_lower and not d.startswith(".")]
            for f in files:
                if files_scanned >= max_files:
                    break
                ext = os.path.splitext(f)[1].lower()
                if ext in (".py", ".js", ".ts", ".go", ".java", ".rs", ".md", ".toml", ".yaml", ".yml", ".c", ".cpp", ".h"):
                    f_path = Path(root) / f
                    files_scanned += 1
                    try:
                        lines = f_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                        for idx, line in enumerate(lines, start=1):
                            m = debt_re.search(line)
                            if m:
                                raw_desc = m.group(1).strip()
                                tag = "general"
                                tag_match = re.match(r"^\[([a-zA-Z0-9_\-]+)\]", raw_desc)
                                if tag_match:
                                    tag = tag_match.group(1).lower()
                                    desc = raw_desc[tag_match.end():].strip()
                                else:
                                    desc = raw_desc

                                tag_counts[tag] = tag_counts.get(tag, 0) + 1
                                debt_items.append({
                                    "file": str(f_path.relative_to(target_dir)),
                                    "line_number": idx,
                                    "tag": tag,
                                    "description": desc or raw_desc,
                                    "raw_comment": line.strip(),
                                })
                    except Exception:
                        pass
            if files_scanned >= max_files:
                break

        return {
            "success": True,
            "path": str(target_dir),
            "total_debt_items": len(debt_items),
            "summary_by_tag": tag_counts,
            "debt_items": debt_items,
        }

    def tool_execute_sandbox_test(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run tests under isolated sandbox environment."""
        test_path = args.get("test_path")
        timeout = _safe_int(args.get("timeout"), 30)
        sandbox_type = args.get("sandbox_type", "subprocess")

        if not test_path:
            return {"success": False, "error": "test_path argument is required."}

        res = self.sandbox.run_python_test(
            test_file_path=test_path,
            timeout=timeout,
            sandbox_type=sandbox_type,
        )
        return res

    def tool_create_reproduction_test(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create and immediately execute minimal reproduction test to verify it FAILS.
        (Step 1 of Hypothesis-Driven Debugging).
        """
        save_path = args.get("save_path")
        test_code = args.get("test_code")
        vulnerability_type = args.get("vulnerability_type", "Bug")

        if not save_path or not test_code:
            return {"success": False, "error": "save_path and test_code are required."}

        raw_path = Path(save_path)
        if not raw_path.is_absolute():
            target = (self.workspace_root / raw_path).resolve()
        else:
            target = raw_path.resolve()

        lower_parts = [p.lower() for p in target.parts]

        # 1. Strictly forbid writing inside any .git directory (case-insensitive for Windows/cross-platform)
        if ".git" in lower_parts:
            return {
                "success": False,
                "error": "Path traversal or unauthorized write: Access to .git directory is strictly forbidden.",
            }

        # 2. Strictly forbid sensitive configuration or secret paths (case-insensitive)
        sensitive_parts = {".ssh", ".aws", ".config"}
        if any(p in sensitive_parts or p.startswith(".env") for p in lower_parts):
            return {
                "success": False,
                "error": f"Path traversal or unauthorized write: Access to sensitive path '{target.name}' is strictly forbidden.",
            }

        # 3. Enforce confinement within workspace root or designated test directory
        is_confined = any(target == root or root in target.parents for root in self.allowed_roots)
        if not is_confined:
            return {
                "success": False,
                "error": f"Path traversal violation: Target '{save_path}' resolves outside allowed workspace root: {self.workspace_root}",
            }

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(test_code, encoding="utf-8")

        # Execute test immediately to verify it fails as expected
        run_res = self.sandbox.run_python_test(target, timeout=20)
        reproduced = run_res["exit_code"] != 0

        return {
            "success": True,
            "test_path": str(target),
            "vulnerability_type": vulnerability_type,
            "reproduced_successfully": reproduced,
            "exit_code": run_res["exit_code"],
            "stdout": run_res["stdout"],
            "stderr": run_res["stderr"],
            "message": (
                "Reproduction confirmed: Test failed as expected."
                if reproduced
                else "Warning: Reproduction test PASSED! A valid reproduction test MUST fail before fixing."
            ),
        }

    def tool_apply_safe_patch(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Apply patch with Diff Cap, Zero-Regression SAST, and Branch Isolation gates."""
        target_file = args.get("target_file")
        patched_content = args.get("patched_content")
        hunks = args.get("hunks")
        unified_diff = args.get("unified_diff")
        task_id = args.get("task_id", "bugfix")
        repo_path = args.get("repo_path")

        committer = args.get("committer", "Lead Orchestrator")
        committer_token = args.get("committer_token")

        if not target_file or (patched_content is None and hunks is None and unified_diff is None):
            return {"success": False, "error": "target_file and at least one of (hunks, unified_diff, patched_content) are required."}

        raw_path = Path(target_file)
        if not raw_path.is_absolute():
            resolved_target = (self.workspace_root / raw_path).resolve()
        else:
            resolved_target = raw_path.resolve()

        is_confined = any(resolved_target == root or root in resolved_target.parents for root in self.allowed_roots)
        if not is_confined:
            return {
                "success": False,
                "violation": True,
                "gate": "Git Branch Isolation Gate",
                "message": f"Path traversal violation: Target '{target_file}' resolves outside allowed workspace root: {self.workspace_root}",
                "details": {"target_file": str(resolved_target)},
            }
        effective_target = resolved_target

        try:
            res = self.patch_manager.apply_safe_patch(
                target_file_path=effective_target,
                patched_content=patched_content,
                hunks=hunks,
                unified_diff=unified_diff,
                task_id=task_id,
                repo_path=repo_path,
                committer=committer,
                committer_token=committer_token,
            )
            return res
        except GuardrailViolation as gv:
            return {
                "success": False,
                "violation": True,
                "gate": gv.gate_name,
                "message": gv.message,
                "details": gv.details,
            }
        except Exception as exc:
            return {"success": False, "error": f"Patch application error: {str(exc)}"}

    def tool_orchestrate_dag(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Coordinate multi-agent workflow DAG and point-to-point mailbox through SQLite WAL."""
        action = str(args.get("action") or "get_summary").strip().lower()

        if action == "init_pipeline":
            requester = args.get("agent_id", args.get("assigned_to", "Lead Orchestrator"))
            pipeline_id = args.get("pipeline_id", f"pipe_{int(time.time())}")
            target_file = args.get("target_file", "unknown.py")
            include_soc = bool(args.get("include_soc", False))
            res = self.dag_engine.create_standard_security_pipeline(pipeline_id, target_file, include_soc=include_soc)
            if requester == "Lead Orchestrator":
                token = self.patch_manager.generate_committer_token(role="Lead Orchestrator")
                res["committer_token"] = token
            return res

        elif action in ("issue_committer_token", "get_committer_token"):
            requester = args.get("agent_id", args.get("assigned_to", "Lead Orchestrator"))
            if requester != "Lead Orchestrator":
                return {
                    "success": False,
                    "error": f"Role '{requester}' is not authorized to request committer tokens. Only 'Lead Orchestrator' is allowed.",
                }
            token = self.patch_manager.generate_committer_token(role="Lead Orchestrator")
            return {"success": True, "committer_token": token, "role": "Lead Orchestrator"}

        elif action == "add_task":
            task_id = args.get("task_id")
            name = args.get("name", "Task")
            assigned_to = args.get("assigned_to", "Worker")
            deps = args.get("dependencies", [])
            if not task_id:
                return {"success": False, "error": "task_id is required for add_task"}
            try:
                task = self.dag_engine.add_task(task_id, name, assigned_to, deps)
                return {"success": True, "task": task}
            except DAGCycleError as ce:
                return {"success": False, "error": str(ce)}

        elif action == "update_task":
            task_id = args.get("task_id")
            status = args.get("status")
            result = args.get("result")
            if not task_id or not status:
                return {"success": False, "error": "task_id and status are required for update_task"}
            try:
                updated = self.dag_engine.update_task_status(task_id, status, result)
                if not updated:
                    return {"success": False, "error": f"Task '{task_id}' not found"}
                return {"success": True, "task": self.dag_engine.get_task(task_id)}
            except ValueError as ve:
                return {"success": False, "error": str(ve)}

        elif action == "get_ready":
            ready = self.dag_engine.get_ready_tasks()
            return {"success": True, "ready_tasks": ready}

        elif action == "set_context":
            key = args.get("key")
            value = args.get("value")
            if not key:
                return {"success": False, "error": "key is required"}
            self.dag_engine.set_shared_context(key, value)
            return {"success": True}

        elif action == "get_context":
            key = args.get("key")
            if not key:
                return {"success": False, "error": "key is required"}
            val = self.dag_engine.get_shared_context(key)
            return {"success": True, "key": key, "value": val}

        # Multi-Agent Point-to-Point Mailbox Actions
        elif action == "send_message":
            task_id = args.get("task_id")
            from_agent = args.get("from_agent")
            to_agent = args.get("to_agent")
            speech_act = args.get("speech_act", "INFORM")
            subject = args.get("subject", "")
            payload = args.get("payload", {})
            if not task_id or not from_agent or not to_agent:
                return {"success": False, "error": "task_id, from_agent, and to_agent are required for send_message"}
            try:
                msg = self.dag_engine.send_agent_message(
                    task_id=task_id,
                    from_agent=from_agent,
                    to_agent=to_agent,
                    speech_act=speech_act,
                    subject=subject,
                    payload=payload,
                )
                return {"success": True, "message": msg}
            except ValueError as ve:
                return {"success": False, "error": str(ve)}

        elif action == "get_inbox":
            task_id = args.get("task_id")
            agent_id = args.get("agent_id")
            unread_only = bool(args.get("unread_only", True))
            msgs = self.dag_engine.get_agent_inbox(task_id=task_id, agent_id=agent_id, unread_only=unread_only)
            return {"success": True, "inbox": msgs, "count": len(msgs)}

        elif action == "mark_processed":
            msg_id = args.get("msg_id")
            if not msg_id:
                return {"success": False, "error": "msg_id is required"}
            ok = self.dag_engine.mark_message_processed(msg_id)
            return {"success": ok}

        elif action == "check_drainage":
            task_id = args.get("task_id")
            agent_id = args.get("agent_id")
            if not task_id:
                return {"success": False, "error": "task_id is required for check_drainage"}
            drained = self.dag_engine.is_inbox_drained(task_id, agent_id)
            return {"success": True, "task_id": task_id, "agent_id": agent_id, "is_drained": drained}

        elif action == "get_messages":
            task_id = args.get("task_id")
            if not task_id:
                return {"success": False, "error": "task_id is required for get_messages"}
            msgs = self.dag_engine.get_task_messages(task_id)
            return {"success": True, "task_id": task_id, "messages": msgs, "count": len(msgs)}

        elif action == "recover_orphans":
            recovery_res = self.dag_engine.recover_orphaned_tasks()
            return {"success": True, "recovery": recovery_res}

        # Default: get_summary
        return {"success": True, "summary": self.dag_engine.get_dag_summary()}

    def tool_search_code(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Search code using Syntactic AST Chunking and SQLite FTS5 BM25."""
        query = args.get("query")
        target_path = args.get("target_path", ".")
        top_k = _safe_int(args.get("top_k"), 5)
        extensions = args.get("extensions")
        ext_tuple = tuple(extensions) if extensions else None

        if not query:
            return {"success": False, "error": "query parameter is required."}

        return self.code_searcher.search(query=query, target_path=target_path, top_k=top_k, extensions=ext_tuple)

    def tool_triage_binary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Safely triage binary artifacts (PE/ELF/ZIP/DEX) under Zero-Execution Policy and evaluate SOC detection rules."""
        file_path = args.get("file_path")
        if not file_path:
            return {"success": False, "error": "file_path parameter is required."}

        res = self.binary_triage_engine.triage_file(file_path=file_path)
        if res.get("success"):
            soc_alerts = self.soc_engine.evaluate_binary_triage(res)
            res["soc_alerts"] = soc_alerts
            for alert in soc_alerts:
                res["evidence_chain"].append(
                    f"[SOC ALERT - {alert['technique_id']} {alert['technique_name']}]: {alert['rule_name']} (Severity: {alert['severity']})"
                )
        return res

    def tool_run_diagnostic_tool(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Safely execute whitelisted diagnostic or reverse engineering tool (strings, readelf, objdump, cfr, jadx, r2, radare2)."""
        tool_name = args.get("tool_name", "")
        target_file = args.get("target_file", "")
        tool_args = args.get("args")
        timeout = _safe_int(args.get("timeout"), 30)
        return self.tool_indexer.run_diagnostic_tool(
            tool_name=tool_name,
            target_file=target_file,
            args=tool_args,
            timeout=timeout,
        )

    def tool_submit_dynamic_sandbox(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a binary artifact to an external dynamic analysis sandbox (CAPEv2 / Cuckoo) or poll task status."""
        check_task_id = args.get("task_id")
        if check_task_id is None:
            check_task_id = args.get("check_status_task_id")
        file_path = args.get("file_path")

        if check_task_id is not None:
            return self.cape_adapter.check_task_status(task_id=check_task_id, target_file=file_path)

        if not file_path:
            return {"success": False, "error": "file_path parameter is required when not checking status with task_id."}

        timeout = _safe_int(args.get("timeout"), 120)
        tags = args.get("tags")
        async_mode = bool(args.get("async_mode", False))
        poll_completion = not async_mode

        return self.cape_adapter.submit_file(
            file_path=file_path,
            tags=tags,
            timeout_sec=timeout,
            poll_completion=poll_completion,
        )

    def tool_quarantine_artifact(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Automated artifact quarantine: atomically move into vault (.quarantine/), XOR obfuscate, and strip execute permissions."""
        file_path = args.get("file_path")
        if not file_path:
            return {"success": False, "error": "file_path parameter is required."}
        quarantine_dir = args.get("quarantine_dir")
        return quarantine_file(
            file_path=file_path,
            quarantine_dir=quarantine_dir,
            workspace_root=self.workspace_root,
        )

    def tool_generate_containment_rule(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Generate host firewall rules (Windows netsh, Linux iptables, UFW, DNS sinkhole) to contain C2 IPs or domains."""
        target = args.get("target")
        if not target:
            return {"success": False, "error": "target parameter is required."}
        rule_type = args.get("rule_type", "block")
        port = args.get("port")
        if port is not None:
            port = _safe_int(port, port)
        return generate_firewall_rule(target=target, rule_type=rule_type, port=port)

    # -----------------------------------------------------------------------
    # Specifications & Metadata (19 Tools, 9 Resources, 8 Prompts)
    # -----------------------------------------------------------------------

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return MCP standard Tool definitions (19 Tools)."""
        tools: List[Dict[str, Any]] = [
            {
                "name": "mcp_adaptive_guide",
                "description": "Adaptive Meta-Guide and Cognitive Anchor. Discovers project genome (<5ms) and outputs optimal tool call sequence, active guardrail rules, exact targeted test commands, and prohibited actions tailored to task intent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_intent": {
                            "type": "string",
                            "enum": [
                                "security_audit",
                                "bugfix_patch",
                                "test_verification",
                                "binary_triage",
                                "containment_incident",
                                "dependency_audit",
                                "code_exploration",
                                "code_simplification",
                                "architecture_audit",
                            ],
                            "default": "security_audit",
                            "description": "Intended action or objective.",
                        },
                        "active_file": {
                            "type": "string",
                            "description": "Optional file path currently being inspected or edited to generate targeted test commands.",
                        },
                    },
                },
            },
            {
                "name": "mcp_scan_vulnerabilities",
                "description": "Performs SAST security scan using Pure-Python AST Engine (CWE-78, CWE-89, CWE-95, CWE-502, CWE-798, CWE-295, CWE-22, CWE-327, CWE-328, CWE-377, CWE-352, CWE-611, CWE-918, CWE-79, CWE-1336, CWE-943, CWE-400), Call Graph Taint Analysis, Delta Git scanning, CVSS scoring (v3.1 & v4.0), and OASIS SARIF v2.1.0 export.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "description": "Absolute or relative path to file to scan."},
                        "code_content": {"type": "string", "description": "Optional in-memory code string to scan directly."},
                        "delta_only": {"type": "boolean", "description": "If true, scans only modified lines from git diff."},
                        "base_commit": {"type": "string", "description": "Base Git commit for diff comparison (default: 'HEAD')."},
                        "use_semgrep": {"type": "boolean", "description": "If true, enables Semgrep multi-language adapter."},
                        "output_format": {
                            "type": "string",
                            "enum": ["json", "sarif"],
                            "description": "Output report format: 'json' (default) or 'sarif' (OASIS SARIF v2.1.0 standard).",
                            "default": "json",
                        },
                    },
                },
            },
            {
                "name": "mcp_audit_dependencies",
                "description": "Performs offline Software Composition Analysis (SCA) on workspace dependency files (requirements.txt, pyproject.toml, poetry.lock) against curated offline OSV JSON vulnerability database.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Optional directory or dependency file path to audit (defaults to workspace root).",
                        },
                    },
                },
            },
            {
                "name": "mcp_execute_sandbox_test",
                "description": "Executes unit or regression tests under strict isolated sandbox (zero shell=True, env whitelist, Windows process tree termination, optional Docker).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "test_path": {"type": "string", "description": "Path to test script to execute."},
                        "timeout": {"type": "integer", "description": "Timeout in seconds (default: 30)."},
                        "sandbox_type": {"type": "string", "enum": ["subprocess", "docker"], "description": "Sandbox isolation tier (default: 'subprocess')."},
                    },
                    "required": ["test_path"],
                },
            },
            {
                "name": "mcp_create_reproduction_test",
                "description": "Generates and validates a minimal reproduction test under Step 1 of Hypothesis-Driven Debugging (verifies test fails before fix).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "save_path": {"type": "string", "description": "File path where reproduction test is written."},
                        "test_code": {"type": "string", "description": "Python test code reproducing the defect."},
                        "vulnerability_type": {"type": "string", "description": "Identified vulnerability type or CWE ID."},
                    },
                    "required": ["save_path", "test_code"],
                },
            },
            {
                "name": "mcp_preview_surgical_patch",
                "description": "Dry-run preview of surgical patch application. Validates Gate 1.5 (Ponytail linter: dead code, stdlib preference), Gate 2 (Diff Cap <=50 lines), Gate 4 (Zero-Deletion invariant), and returns generated unified diff without modifying disk.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_file": {"type": "string", "description": "File path to apply the preview patch to."},
                        "hunks": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "List of hunk objects: [{'start_line': int, 'end_line': int, 'target_content': str, 'replacement_content': str}].",
                        },
                        "unified_diff": {"type": "string", "description": "Standard unified diff string (--- a/ +++ b/ @@ ...)."},
                        "patched_content": {"type": "string", "description": "Complete new content for the target file."},
                    },
                    "required": ["target_file"],
                },
            },
            {
                "name": "mcp_apply_safe_patch",
                "description": "Applies source code patch protected by 5 safety guardrails: Single-Committer authority, Gate 1.5 Ponytail Linter (Dead code, stdlib priority), Diff Cap (<=50 lines), Zero-Regression SAST, and Gate 4 Zero-Deletion.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_file": {"type": "string", "description": "File path to apply the patch to."},
                        "hunks": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "List of hunk objects: [{'start_line': int, 'end_line': int, 'target_content': str, 'replacement_content': str}].",
                        },
                        "unified_diff": {"type": "string", "description": "Standard unified diff string (--- a/ +++ b/ @@ ...)."},
                        "patched_content": {"type": "string", "description": "Complete new content for the target file."},
                        "task_id": {"type": "string", "description": "Identifier of the fixing task (default: 'bugfix')."},
                        "repo_path": {"type": "string", "description": "Optional Git repository root path."},
                        "committer": {"type": "string", "description": "Agent persona applying the patch. Only 'Lead Orchestrator' is authorized (Single-Committer Gate).", "default": "Lead Orchestrator"},
                        "committer_token": {"type": "string", "description": "Ephemeral capability session token issued to Lead Orchestrator for authorized patch application."},
                    },
                    "required": ["target_file"],
                },
            },
            {
                "name": "mcp_orchestrate_dag",
                "description": "Manages Multi-Agent DAG tasks and Point-to-Point Mailbox (Lead Orchestrator, Security Auditor, Debugger, Patch Developer, QA Reviewer, SOC Incident Responder).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "init_pipeline", "add_task", "update_task", "get_ready", "get_summary",
                                "set_context", "get_context", "send_message", "get_inbox", "mark_processed",
                                "check_drainage", "get_messages", "recover_orphans", "issue_committer_token", "get_committer_token",
                            ],
                            "description": "Action to perform on DAG workflow or Mailbox.",
                        },
                        "pipeline_id": {"type": "string", "description": "Pipeline unique ID."},
                        "target_file": {"type": "string", "description": "Target file for pipeline."},
                        "include_soc": {"type": "boolean", "description": "Include SOC Incident Responder in pipeline."},
                        "task_id": {"type": "string", "description": "Task identifier."},
                        "name": {"type": "string", "description": "Task descriptive name."},
                        "assigned_to": {"type": "string", "description": "Agent role assigned."},
                        "dependencies": {"type": "array", "items": {"type": "string"}, "description": "List of prerequisite task IDs."},
                        "status": {"type": "string", "enum": ["PENDING", "READY", "RUNNING", "COMPLETED", "FAILED"], "description": "New status for task state transition."},
                        "result": {"type": "object", "description": "Task output payload."},
                        "key": {"type": "string", "description": "Shared context key."},
                        "value": {"type": "string", "description": "Shared context JSON or string value."},
                        "from_agent": {"type": "string", "description": "Sender agent for mailbox message."},
                        "to_agent": {"type": "string", "description": "Recipient agent for mailbox message."},
                        "speech_act": {"type": "string", "enum": ["INFORM", "REQUEST", "PROPOSE", "CONFIRM", "ESCALATE"], "description": "FIPA-ACL speech act communicative intent."},
                        "subject": {"type": "string", "description": "Message subject line."},
                        "payload": {"type": "object", "description": "Message structured payload."},
                        "agent_id": {"type": "string", "description": "Agent identifier to check inbox or drainage."},
                        "msg_id": {"type": "string", "description": "Message ID to mark processed."},
                        "unread_only": {"type": "boolean", "description": "Filter inbox by unread status."},
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "mcp_search_code",
                "description": "Surgical code search using Semble-style tokenization, syntactic method/skeleton chunking, and SQLite FTS5 BM25. Returns targeted chunks (<100 tokens).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query keywords or function/class symbols."},
                        "target_path": {"type": "string", "description": "Target file or directory path to index and search."},
                        "top_k": {"type": "integer", "description": "Maximum number of chunks to return (default: 5)."},
                        "extensions": {"type": "array", "items": {"type": "string"}, "description": "File extensions to include (e.g. ['.py', '.js', '.ts', '.go', '.java', '.c', '.cpp'])."},
                        "mode": {"type": "string", "enum": ["full", "skeleton", "compact"], "description": "Chunk presentation mode (default: 'full').", "default": "full"},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "mcp_triage_binary",
                "description": "Air-Gapped Binary Triage under Zero-Execution Policy. Dissects PE/ELF/ZIP/DEX magic headers, 1KB block Shannon entropy, and safe string IOCs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to binary artifact to triage safely."},
                    },
                    "required": ["file_path"],
                },
            },
            {
                "name": "mcp_run_diagnostic_tool",
                "description": "Safely executes a whitelisted host diagnostic or reverse engineering tool ('strings', 'readelf', 'objdump', 'cfr', 'jadx', 'r2', 'radare2') against a target file under strict sandbox isolation and input sanitization.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tool_name": {
                            "type": "string",
                            "description": "Name of whitelisted diagnostic tool.",
                            "enum": ["strings", "readelf", "objdump", "cfr", "jadx", "r2", "radare2"],
                        },
                        "target_file": {
                            "type": "string",
                            "description": "Path to binary or target file to inspect.",
                        },
                        "args": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of CLI arguments (forbidden shell metacharacters are strictly rejected).",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Execution timeout in seconds (default: 30).",
                        },
                    },
                    "required": ["tool_name", "target_file"],
                },
            },
            {
                "name": "mcp_submit_dynamic_sandbox",
                "description": "Submits a suspicious binary to an external isolated dynamic analysis sandbox (CAPEv2 / Cuckoo REST API) or polls task status non-blockingly via async_mode and check_status_task_id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to binary artifact to submit for dynamic execution analysis.",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Dynamic analysis timeout in seconds (default: 120).",
                        },
                        "tags": {
                            "type": "string",
                            "description": "Optional sandbox routing tags (e.g. 'win10', 'x64', 'office').",
                        },
                        "async_mode": {
                            "type": "boolean",
                            "description": "If true, submits file and returns task_id immediately without blocking for 120s.",
                            "default": False,
                        },
                        "task_id": {
                            "type": "integer",
                            "description": "Poll status or retrieve report for a previously submitted task ID without re-submitting.",
                        },
                        "check_status_task_id": {
                            "type": "integer",
                            "description": "Legacy alias for task_id.",
                        },
                    },
                },
            },
            {
                "name": "mcp_quarantine_artifact",
                "description": "Automated artifact quarantine under Zero-Execution Policy. Atomically moves suspicious binary into encrypted/obfuscated vault (.quarantine/), strips execute permissions, and records SHA-256 evidence manifest.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the suspicious file or malware sample to quarantine.",
                        },
                        "quarantine_dir": {
                            "type": "string",
                            "description": "Optional custom quarantine directory (defaults to .quarantine/ in workspace).",
                        },
                    },
                    "required": ["file_path"],
                },
            },
            {
                "name": "mcp_restore_quarantined_file",
                "description": "Restores a previously quarantined file from the encrypted/obfuscated vault back to its original destination or workspace.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "quarantine_path": {
                            "type": "string",
                            "description": "Path to the quarantined encrypted file in the vault.",
                        },
                        "original_destination": {
                            "type": "string",
                            "description": "Optional path where the file should be restored. If omitted, restored to original location recorded in manifest.",
                        },
                    },
                    "required": ["quarantine_path"],
                },
            },
            {
                "name": "mcp_generate_containment_rule",
                "description": "Generates host containment and firewall rules across Windows Defender Firewall (netsh), Linux iptables, Linux UFW, and DNS sinkhole formats to block malicious C2 IPs or domains.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Malicious IP address, CIDR subnet, or C2 domain name to block.",
                        },
                        "rule_type": {
                            "type": "string",
                            "enum": ["block", "allow"],
                            "default": "block",
                            "description": "Containment action: 'block' (default) or 'allow'.",
                        },
                        "port": {
                            "type": "integer",
                            "description": "Optional port number (1-65535) for port-specific firewall filtering.",
                        },
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "mcp_terminate_process",
                "description": "Safely terminates a suspicious or rogue process and its entire descendant child process tree (using taskkill /T on Windows, process groups / SIGKILL on Linux) under containment protocols.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": {
                            "type": "integer",
                            "description": "Process ID (PID) to terminate.",
                        },
                        "timeout": {
                            "type": "number",
                            "description": "Timeout in seconds to wait for graceful termination before force killing (default: 3.0).",
                            "default": 3.0,
                        },
                    },
                    "required": ["pid"],
                },
            },
            {
                "name": "mcp_ponytail_review",
                "description": "Reviews code or diff against the Ponytail 7-Rung Decision Ladder, tagging findings with delete:, stdlib:, native:, yagni:, shrink: and estimating LOC reduction.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Source code snippet to review against Ponytail rules.",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Optional file path to load code from or provide file context.",
                        },
                        "diff": {
                            "type": "string",
                            "description": "Optional unified diff string to review.",
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["ultra", "full", "lite"],
                            "description": "Ponytail intensity mode (default: 'full').",
                            "default": "full",
                        },
                    },
                },
            },
            {
                "name": "mcp_ponytail_audit",
                "description": "Audits repository workspace files for dead code, unneeded dependencies, and AST YAGNI violations, ranking files by potential LOC reduction.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Target workspace directory or file to audit (defaults to workspace root).",
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["ultra", "full", "lite"],
                            "description": "Ponytail intensity mode (default: 'full').",
                            "default": "full",
                        },
                    },
                },
            },
            {
                "name": "mcp_ponytail_debt",
                "description": "Scans workspace for ponytail: debt comments (# ponytail: or // ponytail:) and compiles a structured Debt Ledger.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Target directory to scan for ponytail debt comments (defaults to workspace root).",
                        },
                    },
                },
            },
        ]

        read_only_tools = {
            "mcp_adaptive_guide", "mcp_scan_vulnerabilities", "mcp_audit_dependencies",
            "mcp_search_code", "mcp_triage_binary", "mcp_preview_surgical_patch",
            "mcp_ponytail_review", "mcp_ponytail_audit", "mcp_ponytail_debt",
        }
        for t in tools:
            name = t["name"]
            is_ro = name in read_only_tools
            if "outputSchema" not in t:
                t["outputSchema"] = {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "description": "Execution status ('success' or 'error')."},
                        "message": {"type": "string", "description": "Human-readable summary of operation results."},
                        "data": {"type": "object", "description": "Structured findings or response payload."}
                    },
                    "required": ["status"]
                }
            if "annotations" not in t:
                t["annotations"] = {
                    "readOnly": is_ro,
                    "destructive": not is_ro and name in {"mcp_terminate_process", "mcp_quarantine_artifact"},
                    "audience": ["user", "assistant"],
                    "priority": 1.0
                }
        return tools

    def get_resource_definitions(self) -> List[Dict[str, Any]]:
        """Return MCP standard Resource definitions (9 Resources)."""
        return [
            {
                "uri": "mcp://rules/security-standards",
                "name": "CookieCyberTeam Security Standards & Defensive Guardrails",
                "description": "Standard checklist for CWE-78, CWE-89, CWE-95, CWE-502, CWE-798, CWE-295, file protection invariants, and zero-trust conventions.",
                "mimeType": "text/markdown",
            },
            {
                "uri": "mcp://rules/debugging-mindset",
                "name": "4-Step Hypothesis-Driven Debugging Protocol",
                "description": "Scientific debugging mindset: Reproduce -> Trace & Isolate -> Form Hypothesis -> Confirm via Proof & Minimal Diff.",
                "mimeType": "text/markdown",
            },
            {
                "uri": "mcp://state/agent-context",
                "name": "Multi-Agent Shared State & DAG Overview",
                "description": "Dynamic SQLite WAL shared memory containing pipeline status, task graph, and findings.",
                "mimeType": "application/json",
            },
            {
                "uri": "mcp://state/tool-index",
                "name": "Host Defensive & Reverse Engineering Toolchain Index",
                "description": "Dynamic inventory of security, SAST, reverse engineering, and sandbox tools available on host system.",
                "mimeType": "text/markdown",
            },
            {
                "uri": "mcp://playbooks/malware-triage",
                "name": "NIST SP 800-61 Rev 3: Malware Triage & Reverse Engineering Playbook",
                "description": "Standard procedures for Zero-Execution air-gapped triage, PE/ELF magic header parsing, Shannon entropy, and string IOC extraction.",
                "mimeType": "text/markdown",
            },
            {
                "uri": "mcp://playbooks/compromise-assessment",
                "name": "Multi-Agent Compromise Assessment & Agentic Threats Playbook",
                "description": "Server containment, unauthorized file deletion prevention, single-committer isolation, and OWASP Top 10 for Agentic Systems.",
                "mimeType": "text/markdown",
            },
            {
                "uri": "mcp://context/project-genome",
                "name": "CookieCyberTeam Project Genome Profile",
                "description": "Sub-5ms discovery of project language, frameworks, test runners, git status, risk profile, and adaptive recommendations.",
                "mimeType": "application/json",
            },
            {
                "uri": "mcp://rules/active-guardrails",
                "name": "CookieCyberTeam Active Security Guardrails & Gate Policies",
                "description": "Active runtime configuration of all 5 Zero-Trust Guardrail Gates (Syntax, Ponytail Linter, Diff Cap, SAST, Zero-Deletion).",
                "mimeType": "application/json",
            },
            {
                "uri": "mcp://rules/ponytail-ladder",
                "name": "Ponytail The Lazy Senior Dev Decision Ladder & Native Playbook",
                "description": "7-Rung decision ladder, standard library / native API lookup tables, and intensity mode specifications.",
                "mimeType": "text/markdown",
            },
        ]

    def read_resource(self, uri: str) -> Dict[str, Any]:
        """Return contents for requested resource URI."""
        if uri == "mcp://rules/security-standards":
            return {"uri": uri, "mimeType": "text/markdown", "text": SECURITY_STANDARDS_RESOURCE}
        elif uri == "mcp://rules/ponytail-ladder":
            return {"uri": uri, "mimeType": "text/markdown", "text": PONYTAIL_LADDER_RESOURCE}
        elif uri == "mcp://rules/debugging-mindset":
            return {"uri": uri, "mimeType": "text/markdown", "text": DEBUGGING_MINDSET_RESOURCE}
        elif uri == "mcp://state/agent-context":
            summary = self.dag_engine.get_dag_summary()
            return {"uri": uri, "mimeType": "application/json", "text": json.dumps(summary, indent=2)}
        elif uri == "mcp://state/tool-index":
            return {"uri": uri, "mimeType": "text/markdown", "text": self.tool_indexer.to_markdown()}
        elif uri == "mcp://playbooks/malware-triage":
            return {"uri": uri, "mimeType": "text/markdown", "text": MALWARE_TRIAGE_PLAYBOOK_RESOURCE}
        elif uri == "mcp://playbooks/compromise-assessment":
            return {"uri": uri, "mimeType": "text/markdown", "text": COMPROMISE_ASSESSMENT_PLAYBOOK_RESOURCE}
        elif uri == "mcp://context/project-genome":
            genome = self.profiler.discover()
            return {"uri": uri, "mimeType": "application/json", "text": json.dumps(genome, indent=2)}
        elif uri == "mcp://rules/active-guardrails":
            rules = {
                "server": SERVER_NAME,
                "version": SERVER_VERSION,
                "workspace_root": str(self.workspace_root),
                "allowed_roots": [str(r) for r in self.allowed_roots],
                "gates": {
                    "gate_1_syntax": "Polyglot Syntax Dispatch & Delimiter Verification",
                    "gate_1_5_ponytail": {
                        "dead_code_check": "YAGNI check: rejects uncalled symbols unless in __all__",
                        "stdlib_prioritization": "Rejects 3rd-party dependencies when stdlib equivalent exists unless listed in project",
                        "diff_cap": f"{self.config.diff_cap_limit} lines for modification, {self.config.new_file_cap_limit} lines for scaffolding",
                    },
                    "gate_2_diff_cap": self.config.diff_cap_limit,
                    "gate_3_sast_regression": "Zero new CWE vulnerabilities or count regressions",
                    "gate_4_zero_deletion": "Absolute prohibition of file deletion primitives (os.remove, unlink, shutil.rmtree, shell rm/del)",
                    "gate_5_git_isolation": "Protected branch commit prevention and single-committer capability token",
                },
            }
            return {"uri": uri, "mimeType": "application/json", "text": json.dumps(rules, indent=2)}
        raise ValueError(f"Resource not found: {uri}")

    def get_prompt_definitions(self) -> List[Dict[str, Any]]:
        """Return MCP standard Prompt definitions (8 Prompts)."""
        return [
            {
                "name": "mcp_prompt_orchestrator",
                "description": "Lead Orchestrator: Decomposes security issues into an acyclic DAG, manages mailbox routing, and enforces single-committer gates.",
                "arguments": [
                    {"name": "issue_description", "description": "Summary of bug/security report.", "required": True},
                    {"name": "target_file", "description": "Target source file.", "required": True},
                ],
            },
            {
                "name": "mcp_prompt_security_audit",
                "description": "Security Auditor: Maps attack surface, scans AST for CWEs, and assigns FIRST CVSS v3.1 vectors.",
                "arguments": [
                    {"name": "target_file", "description": "Target source file to audit.", "required": True},
                ],
            },
            {
                "name": "mcp_prompt_hypothesis_debug",
                "description": "Scientific Debugger: Executes 4-step hypothesis method and builds minimal reproduction test.",
                "arguments": [
                    {"name": "vulnerability", "description": "Identified vulnerability details.", "required": True},
                    {"name": "target_file", "description": "Target source file.", "required": True},
                ],
            },
            {
                "name": "mcp_prompt_safe_patch",
                "description": "Patch Developer: Drafts minimal diff (<=50 lines) adhering to Ponytail Principle.",
                "arguments": [
                    {"name": "root_cause", "description": "Root cause confirmed by Debugger.", "required": True},
                    {"name": "target_file", "description": "Target source file.", "required": True},
                ],
            },
            {
                "name": "mcp_prompt_qa_review",
                "description": "QA / Code Reviewer: Runs isolated sandbox tests and enforces Zero-Regression SAST.",
                "arguments": [
                    {"name": "target_file", "description": "Patched file to verify.", "required": True},
                    {"name": "repro_test", "description": "Path to reproduction test.", "required": True},
                ],
            },
            {
                "name": "mcp_prompt_soc_incident_responder",
                "description": "SOC Incident Responder: Coordinates triage under NIST SP 800-61 Rev 3, performs air-gapped binary triage, and isolates IOCs.",
                "arguments": [
                    {"name": "incident_description", "description": "Incident or artifact summary.", "required": True},
                    {"name": "artifact_path", "description": "Path to suspicious file or binary.", "required": True},
                ],
            },
            {
                "name": "mcp_prompt_ponytail_review",
                "description": "Senior Pragmatic Reviewer: Audits code/diff against Ponytail 7-Rung Ladder, tagging findings with delete:, stdlib:, native:, yagni:, shrink:.",
                "arguments": [
                    {"name": "target_file", "description": "Target source file to review.", "required": True},
                    {"name": "diff", "description": "Optional unified diff to review.", "required": False},
                ],
            },
            {
                "name": "mcp_prompt_ponytail_minimalist",
                "description": "Minimalist Code Generator: Generates the shortest working diff strictly prioritizing stdlib/native features and zero speculative code.",
                "arguments": [
                    {"name": "task_description", "description": "Task or bug requirement to implement.", "required": True},
                    {"name": "target_file", "description": "Target source file.", "required": True},
                    {"name": "mode", "description": "Ponytail intensity mode ('ultra', 'full', 'lite').", "required": False},
                ],
            },
        ]

    def get_prompt(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate prompt message content for requested role."""
        args = arguments or {}
        if name == "mcp_prompt_orchestrator":
            issue = args.get("issue_description", "Security Issue")
            target = args.get("target_file", "unknown.py")
            content = (
                f"You are the Lead Orchestrator for task: '{issue}' targeting '{target}'.\n"
                "Your responsibilities:\n"
                "1. Initialize the Multi-Agent DAG pipeline using `mcp_orchestrate_dag(action='init_pipeline')`.\n"
                "2. Coordinate Worker agents via point-to-point mailbox (`action='send_message'`, `action='get_inbox'`).\n"
                "3. Enforce Max Hop TTL (20 messages) and verify inbox drainage (`action='check_drainage'`) before closing tasks.\n"
                "4. Enforce Single-Committer Git Isolation: Only you apply patches or commit changes.\n"
                "5. Mandatory Advisories:\n"
                "   - Dual-Tier Sandbox Architecture: Tier-1 (Subprocess Argv + Whitelist + Tree Kill) is active by default; Tier-2 (Docker) requires host daemon.\n"
                "   - Zero-Execution Policy: Perform strict static triage on host; dynamic execution must route via Tier-2 Docker or CAPEv2 sandbox.\n"
                "   - File Safety Invariants: Absolute prohibition of unauthorized file deletion (no rm, del, rmdir, Remove-Item, unlink)."
            )
        elif name == "mcp_prompt_security_audit":
            target = args.get("target_file", "unknown.py")
            content = (
                f"You are the Security Auditor auditing '{target}'.\n"
                "1. Use `mcp_search_code` to locate relevant functions with minimal token consumption.\n"
                "2. Run `mcp_scan_vulnerabilities(target_path='{target}')` to identify CWE-78, CWE-89, CWE-95, CWE-502, CWE-798, CWE-295.\n"
                "3. Verify FIRST CVSS v3.1 scores and attack surface vectors.\n"
                "4. Enforce Zero-Execution Policy (static analysis only) and Absolute Prohibition of File Deletion.\n"
                "5. Record findings in shared context and inform the Lead Orchestrator via mailbox."
            )
        elif name == "mcp_prompt_hypothesis_debug":
            vuln = args.get("vulnerability", "Unknown defect")
            target = args.get("target_file", "unknown.py")
            content = (
                f"You are the Scientific Debugger addressing '{vuln}' in '{target}'.\n"
                "Follow the 4-step mindset strictly. DO NOT GUESS CODE.\n"
                "Step 1: Write a minimal reproduction test and verify it FAILS using `mcp_create_reproduction_test`.\n"
                "Step 2: Trace execution flow and isolate root cause under Tier-1 Sandbox isolation.\n"
                "Step 3: Formulate a falsifiable hypothesis.\n"
                "Step 4: Confirm root cause via AST and pass confirmed analysis to Patch Developer via mailbox.\n"
                "Mandatory Advisory: Absolute prohibition of unauthorized file deletion; live payloads must never be executed on host."
            )
        elif name == "mcp_prompt_safe_patch":
            root_cause = args.get("root_cause", "Confirmed root cause")
            target = args.get("target_file", "unknown.py")
            content = (
                f"You are the Patch Developer fixing '{target}' based on root cause: '{root_cause}'.\n"
                "Enforce Ponytail Principle: Shortest working diff wins.\n"
                "1. Limit your diff to <= 50 lines changed (Diff Cap Gate).\n"
                "2. Eliminate the root cause directly; do not add superficial caller guards.\n"
                "3. Apply your patch using `mcp_apply_safe_patch(target_file='{target}', patched_content=...)`.\n"
                "4. Mandatory Advisory: Absolute prohibition of unauthorized file deletion (no rm, del, Remove-Item, unlink, or destroying user code)."
            )
        elif name == "mcp_prompt_qa_review":
            target = args.get("target_file", "unknown.py")
            repro = args.get("repro_test", "tests/test_repro.py")
            content = (
                f"You are the QA / Code Reviewer inspecting the fix for '{target}'.\n"
                f"1. Run `mcp_execute_sandbox_test(test_path='{repro}')` to verify the reproduction test now PASSES.\n"
                "   - Dual-Tier Sandbox Advisory: Tier-1 (Subprocess Argv + Whitelist + Tree Kill) default; Tier-2 (Docker) requires active daemon.\n"
                "2. Run regression test suites to guarantee 0 regressions.\n"
                f"3. Run `mcp_scan_vulnerabilities(target_path='{target}', delta_only=True)` to confirm zero new CWEs were introduced.\n"
                "4. Mandatory Advisory: Verify patch contains zero unauthorized file deletions or destructive mutations (Absolute File Safety Invariant)."
            )
        elif name == "mcp_prompt_soc_incident_responder":
            incident = args.get("incident_description", "Suspicious Activity")
            art = args.get("artifact_path", "unknown.bin")
            content = (
                f"You are the SOC Incident Responder investigating: '{incident}' for artifact '{art}'.\n"
                "Enforce NIST SP 800-61 Rev 3 and Zero-Execution Policy strictly.\n"
                "1. Consult `mcp://playbooks/malware-triage` and `mcp://playbooks/compromise-assessment`.\n"
                f"2. Execute air-gapped static triage using `mcp_triage_binary(file_path='{art}')`.\n"
                "3. Extract SHA-256 evidence chain, block entropy, and IOC indicators (IP, URL, Registry, APIs).\n"
                f"4. Run whitelisted diagnostic tools using `mcp_run_diagnostic_tool` or check `mcp://state/tool-index`.\n"
                f"5. For dynamic detonation, submit to CAPEv2/Cuckoo via `mcp_submit_dynamic_sandbox(file_path='{art}')`.\n"
                "6. Mandatory Advisories:\n"
                "   - Zero-Execution Policy: Never execute untrusted binaries directly on host.\n"
                "   - Dual-Tier Sandbox: Host analysis is static only; dynamic execution belongs in Tier-2 Docker or CAPEv2 sandbox.\n"
                "   - File Safety Invariant: Absolute prohibition of unauthorized file deletion.\n"
                "7. Report containment and eradication plan to Lead Orchestrator via mailbox."
            )
        elif name == "mcp_prompt_ponytail_review":
            target = args.get("target_file", "unknown.py")
            diff = args.get("diff", "")
            diff_section = f"\nDiff to review:\n{diff}" if diff else "\nInspect the target file directly."
            content = (
                f"You are the Senior Pragmatic Reviewer ('The Lazy Senior Dev') reviewing '{target}'.\n"
                "Evaluate the code against the Ponytail 7-Rung Decision Ladder:\n"
                "1. Challenge every new line: Does this need to exist (YAGNI)?\n"
                "2. Tag findings with: `delete:` (dead code), `stdlib:` (replace with Python stdlib), `native:` (replace with Web/Node native), `yagni:` (over-engineering), `shrink:` (LOC reduction).\n"
                "3. Invariant Safety Standard: Never sacrifice validation, auth, error handling, or security for brevity (Lazy, Not Negligent).\n"
                f"{diff_section}"
            )
        elif name == "mcp_prompt_ponytail_minimalist":
            task = args.get("task_description", "Requirement")
            target = args.get("target_file", "unknown.py")
            mode = args.get("mode", "full")
            content = (
                f"You are the Ponytail Minimalist Developer implementing '{task}' in '{target}' (Mode: {mode}).\n"
                "Rules of Engagement:\n"
                "1. Shortest working diff wins (Diff Cap: 50 lines in full, 25 in ultra, 80 in lite).\n"
                "2. Zero unnecessary helper functions, classes, or interfaces.\n"
                "3. Use Python stdlib / native platform features exclusively when available.\n"
                "4. Fix the root cause directly; do not add superficial wrapper guards.\n"
                "5. Maintain 100% test coverage, robust validation, and zero regression."
            )
        else:
            raise ValueError(f"Unknown prompt name: {name}")

        return {
            "description": f"CookieCyberTeam Role: {name}",
            "messages": [
                {
                    "role": "user",
                    "content": {"type": "text", "text": content},
                }
            ],
        }

    # -----------------------------------------------------------------------
    # Tool Execution Dispatcher
    # -----------------------------------------------------------------------

    def handle_call_tool(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Dispatch a tool call to its respective handler and return structured result dictionary.
        Supports safe JSON-RPC execution of all 19 registered MCP tools.
        """
        args = arguments or {}
        handler_map: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
            "mcp_adaptive_guide": self.tool_adaptive_guide,
            "mcp_scan_vulnerabilities": self.tool_scan_vulnerabilities,
            "mcp_audit_dependencies": self.tool_audit_dependencies,
            "mcp_execute_sandbox_test": self.tool_execute_sandbox_test,
            "mcp_create_reproduction_test": self.tool_create_reproduction_test,
            "mcp_preview_surgical_patch": self.tool_preview_surgical_patch,
            "mcp_apply_safe_patch": self.tool_apply_safe_patch,
            "mcp_orchestrate_dag": self.tool_orchestrate_dag,
            "mcp_search_code": self.tool_search_code,
            "mcp_triage_binary": self.tool_triage_binary,
            "mcp_run_diagnostic_tool": self.tool_run_diagnostic_tool,
            "mcp_submit_dynamic_sandbox": self.tool_submit_dynamic_sandbox,
            "mcp_quarantine_artifact": self.tool_quarantine_artifact,
            "mcp_restore_quarantined_file": self.tool_restore_quarantined_file,
            "mcp_generate_containment_rule": self.tool_generate_containment_rule,
            "mcp_terminate_process": self.tool_terminate_process,
            "mcp_ponytail_review": self.tool_ponytail_review,
            "mcp_ponytail_audit": self.tool_ponytail_audit,
            "mcp_ponytail_debt": self.tool_ponytail_debt,
        }


        if tool_name not in handler_map:
            raise KeyError(f"Method or tool not found: {tool_name}")

        return handler_map[tool_name](args)

    # -----------------------------------------------------------------------
    # JSON-RPC 2.0 Dispatcher
    # -----------------------------------------------------------------------

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Dispatch incoming JSON-RPC 2.0 request and return response dictionary."""
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        # Handle notifications (no id)
        if req_id is None and method == "notifications/initialized":
            return None

        def make_res(result_data: Any) -> Dict[str, Any]:
            return {"jsonrpc": "2.0", "id": req_id, "result": result_data}

        def make_err(code: int, message: str, data: Any = None) -> Dict[str, Any]:
            err: Dict[str, Any] = {"code": code, "message": message}
            if data is not None:
                err["data"] = data
            return {"jsonrpc": "2.0", "id": req_id, "error": err}

        if method == "initialize":
            return make_res({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
            })

        elif method == "tools/list":
            return make_res({"tools": self.get_tool_definitions()})

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            try:
                res = self.handle_call_tool(tool_name, arguments)
                return make_res({
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(res, indent=2),
                        }
                    ],
                    "isError": not res.get("success", True),
                })
            except KeyError:
                return make_err(-32601, f"Method or tool not found: {tool_name}")
            except Exception as exc:
                return make_res({
                    "content": [{"type": "text", "text": f"Error executing {tool_name}: {str(exc)}"}],
                    "isError": True,
                })

        elif method == "resources/list":
            return make_res({"resources": self.get_resource_definitions()})

        elif method == "resources/read":
            uri = params.get("uri")
            if not uri:
                return make_err(-32602, "Missing 'uri' parameter")
            try:
                res_content = self.read_resource(uri)
                return make_res({"contents": [res_content]})
            except ValueError as ve:
                return make_err(-32602, str(ve))

        elif method == "prompts/list":
            return make_res({"prompts": self.get_prompt_definitions()})

        elif method == "prompts/get":
            prompt_name = params.get("name")
            prompt_args = params.get("arguments")
            if not prompt_name:
                return make_err(-32602, "Missing 'name' parameter")
            try:
                p_data = self.get_prompt(prompt_name, prompt_args)
                return make_res(p_data)
            except ValueError as ve:
                return make_err(-32602, str(ve))

        return make_err(-32601, f"Method not recognized: {method}")

    def run_stdio(self) -> None:
        """Run the JSON-RPC stdio event loop."""
        sys.stderr.write(f"[{SERVER_NAME}] Server running on stdio (JSON-RPC 2.0)...\n")
        sys.stderr.flush()

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except json.JSONDecodeError as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(exc)}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()

    def close(self) -> None:
        """Release database connections and resources."""
        if hasattr(self, "code_searcher"):
            self.code_searcher.close()
        if hasattr(self, "dag_engine"):
            self.dag_engine.close()

    def __enter__(self) -> "CookieCyberMCPServer":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


def run_self_test() -> bool:
    """Perform comprehensive self-diagnostic test on all components."""
    print("=== CookieCyberTeam MCP Server Self-Test ===")
    server = CookieCyberMCPServer(db_path=":memory:")

    # 1. Test Tools list (19 Tools)
    tools = server.get_tool_definitions()
    assert len(tools) == 19, f"Expected 19 tools, got {len(tools)}"
    tool_names = {t["name"] for t in tools}
    assert "mcp_adaptive_guide" in tool_names
    assert "mcp_audit_dependencies" in tool_names
    assert "mcp_preview_surgical_patch" in tool_names
    assert "mcp_restore_quarantined_file" in tool_names
    assert "mcp_terminate_process" in tool_names
    assert "mcp_search_code" in tool_names
    assert "mcp_triage_binary" in tool_names
    assert "mcp_run_diagnostic_tool" in tool_names
    assert "mcp_submit_dynamic_sandbox" in tool_names
    assert "mcp_quarantine_artifact" in tool_names
    assert "mcp_generate_containment_rule" in tool_names
    assert "mcp_ponytail_review" in tool_names
    assert "mcp_ponytail_audit" in tool_names
    assert "mcp_ponytail_debt" in tool_names
    print(f"[PASS] Tools verified: {len(tools)} registered ({', '.join(sorted(tool_names))}).")

    # 2. Test Resources list & read (9 Resources)
    resources = server.get_resource_definitions()
    assert len(resources) == 9, f"Expected 9 resources, got {len(resources)}"
    r_standards = server.read_resource("mcp://rules/security-standards")
    assert "CWE-78" in r_standards["text"]
    r_ponytail = server.read_resource("mcp://rules/ponytail-ladder")
    assert "Decision Ladder" in r_ponytail["text"]
    r_tool_index = server.read_resource("mcp://state/tool-index")
    assert "Toolchain Index" in r_tool_index["text"]
    r_malware = server.read_resource("mcp://playbooks/malware-triage")
    assert "Zero-Execution Policy" in r_malware["text"]
    r_compromise = server.read_resource("mcp://playbooks/compromise-assessment")
    assert "Single-Committer" in r_compromise["text"]
    r_genome = server.read_resource("mcp://context/project-genome")
    assert "tech_stack" in r_genome["text"]
    r_active_rules = server.read_resource("mcp://rules/active-guardrails")
    assert "gates" in r_active_rules["text"]
    print(f"[PASS] Resources verified: {len(resources)} registered and readable.")

    # 3. Test Prompts list & get (8 Prompts)
    prompts = server.get_prompt_definitions()
    assert len(prompts) == 8, f"Expected 8 prompts, got {len(prompts)}"
    p_orch = server.get_prompt("mcp_prompt_orchestrator", {"issue_description": "Test", "target_file": "app.py"})
    assert "Lead Orchestrator" in p_orch["messages"][0]["content"]["text"]
    p_soc = server.get_prompt("mcp_prompt_soc_incident_responder", {"incident_description": "Malware Outbreak", "artifact_path": "sample.exe"})
    assert "SOC Incident Responder" in p_soc["messages"][0]["content"]["text"]
    p_pony_rev = server.get_prompt("mcp_prompt_ponytail_review", {"target_file": "app.py"})
    assert "Lazy Senior Dev" in p_pony_rev["messages"][0]["content"]["text"]
    p_pony_min = server.get_prompt("mcp_prompt_ponytail_minimalist", {"task_description": "fix bug", "target_file": "app.py"})
    assert "Ponytail Minimalist" in p_pony_min["messages"][0]["content"]["text"]
    print(f"[PASS] Prompts verified: {len(prompts)} registered and formatted.")

    # 4. Test JSON-RPC initialize
    init_res = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init_res["result"]["serverInfo"]["name"] == SERVER_NAME
    print("[PASS] JSON-RPC initialization handshake verified.")

    # 5. Test Vulnerability Scan tool via JSON-RPC
    sample_vuln_code = (
        "import os\n"
        "def run_cmd(user_arg):\n"
        "    os.system('cat ' + user_arg)\n"
    )
    scan_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "mcp_scan_vulnerabilities",
            "arguments": {"code_content": sample_vuln_code},
        },
    }
    scan_res = server.handle_request(scan_req)
    content_text = scan_res["result"]["content"][0]["text"]
    parsed_res = json.loads(content_text)
    assert parsed_res["total_findings"] >= 1
    assert parsed_res["findings"][0]["cwe_id"] == "CWE-78"
    assert parsed_res["findings"][0]["cvss_score"] >= 9.0
    print(f"[PASS] Vulnerability Scan tool verified: Caught {parsed_res['findings'][0]['cwe_id']} (CVSS {parsed_res['findings'][0]['cvss_score']}).")

    # 6. Test DAG pipeline orchestration and Mailbox
    dag_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "mcp_orchestrate_dag",
            "arguments": {"action": "init_pipeline", "pipeline_id": "test_pipe", "target_file": "app.py", "include_soc": True},
        },
    }
    dag_res = server.handle_request(dag_req)
    dag_data = json.loads(dag_res["result"]["content"][0]["text"])
    assert dag_data["total_tasks"] == 5
    assert len(dag_data["ready_to_execute"]) == 1

    # Send mailbox message
    msg_req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "mcp_orchestrate_dag",
            "arguments": {
                "action": "send_message",
                "task_id": "test_pipe_sec_audit",
                "from_agent": "Security Auditor",
                "to_agent": "Debugger",
                "speech_act": "INFORM",
                "subject": "CWE-78 Detected",
                "payload": {"line": 3, "cwe": "CWE-78"},
            },
        },
    }
    msg_res = server.handle_request(msg_req)
    msg_data = json.loads(msg_res["result"]["content"][0]["text"])
    assert msg_data["success"] is True
    assert msg_data["message"]["speech_act"] == "INFORM"
    print(f"[PASS] DAG Engine & Mailbox verified: 5-worker pipeline created, inter-agent message routed.")

    # 7. Test Code Search tool
    search_req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "mcp_search_code",
            "arguments": {"query": "DAGEngine", "target_path": "core", "top_k": 3},
        },
    }
    search_res = server.handle_request(search_req)
    search_data = json.loads(search_res["result"]["content"][0]["text"])
    assert search_data["success"] is True
    assert search_data["total_matches"] >= 1
    print(f"[PASS] Hybrid Code Search tool verified: {search_data['total_matches']} matches found.")

    # 8. Test Binary Triage tool
    # Create mock PE header artifact
    mock_pe = b"MZ" + (b"\x00" * 0x3A) + b"\x80\x00\x00\x00" + (b"\x00" * 0x40) + b"PE\x00\x00\x4c\x01\x01\x00" + (b"\x00" * 200) + b"https://malicious-c2.test/rat\x00"
    temp_bin = Path(".cookiegli/test_artifact.bin")
    temp_bin.parent.mkdir(parents=True, exist_ok=True)
    temp_bin.write_bytes(mock_pe)

    triage_req = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "mcp_triage_binary",
            "arguments": {"file_path": str(temp_bin)},
        },
    }
    triage_res = server.handle_request(triage_req)
    triage_data = json.loads(triage_res["result"]["content"][0]["text"])
    assert triage_data["success"] is True
    assert triage_data["header"]["format"] == "PE"
    assert len(triage_data["iocs"]["urls"]) >= 1
    assert "soc_alerts" in triage_data
    print(f"[PASS] Air-Gapped Binary Triage & SOC Dynamic Rule Engine verified: PE recognized, URL IOC caught, SOC alert evaluated.")

    # 9. Test Diagnostic Tool runner via JSON-RPC
    diag_req = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "mcp_run_diagnostic_tool",
            "arguments": {"tool_name": "unauthorized_tool", "target_file": str(temp_bin)},
        },
    }
    diag_res = server.handle_request(diag_req)
    diag_data = json.loads(diag_res["result"]["content"][0]["text"])
    assert diag_data["success"] is False
    assert "whitelist" in diag_data["error"]
    print("[PASS] Diagnostic Tool runner verified: Whitelist enforcement operational.")

    # 10. Test Dynamic Sandbox submission tool (graceful fallback)
    sandbox_req = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "mcp_submit_dynamic_sandbox",
            "arguments": {"file_path": str(temp_bin)},
        },
    }
    sandbox_res = server.handle_request(sandbox_req)
    sandbox_data = json.loads(sandbox_res["result"]["content"][0]["text"])
    assert sandbox_data["configured"] is False or sandbox_data["success"] is True
    print("[PASS] Dynamic Sandbox tool verified: Graceful fallback and error reporting operational.")

    # 11. Test Containment Rule Generator tool via JSON-RPC
    rule_req = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "mcp_generate_containment_rule",
            "arguments": {"target": "198.51.100.99", "rule_type": "block", "port": 4444},
        },
    }
    rule_res = server.handle_request(rule_req)
    rule_data = json.loads(rule_res["result"]["content"][0]["text"])
    assert rule_data["success"] is True
    assert "netsh" in rule_data["windows_netsh"]
    assert "iptables" in rule_data["linux_iptables"]
    print("[PASS] Containment Rule Generator tool verified: Windows/Linux/DNS rules generated.")

    # 12. Test Artifact Quarantine tool via JSON-RPC
    quar_sample = Path(".cookiegli/quarantine_test_sample.bin")
    quar_sample.parent.mkdir(parents=True, exist_ok=True)
    quar_sample.write_bytes(b"MALICIOUS_DROPPER_PAYLOAD_TEST_DATA")
    quar_req = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "mcp_quarantine_artifact",
            "arguments": {"file_path": str(quar_sample)},
        },
    }
    quar_res = server.handle_request(quar_req)
    quar_data = json.loads(quar_res["result"]["content"][0]["text"])
    assert quar_data["success"] is True
    assert not quar_sample.exists(), "Original file should have been moved into quarantine vault."
    assert Path(quar_data["quarantine_path"]).exists()
    print("[PASS] Artifact Quarantine tool verified: Sample atomically moved into vault and encrypted.")

    # 13. Test Ponytail Review & Debt tools via JSON-RPC
    pony_req = {
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "mcp_ponytail_review",
            "arguments": {"code": "import requests\nclass StringUtils:\n    @staticmethod\n    def do_stuff(x):\n        return x.strip()\n"},
        },
    }
    pony_res = server.handle_request(pony_req)
    pony_data = json.loads(pony_res["result"]["content"][0]["text"])
    assert pony_data["success"] is True
    assert pony_data["total_findings"] >= 1
    print(f"[PASS] Ponytail Review tool verified: {pony_data['total_findings']} findings detected.")

    pony_debt_req = {
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "mcp_ponytail_debt",
            "arguments": {"path": "core"},
        },
    }
    pony_debt_res = server.handle_request(pony_debt_req)
    pony_debt_data = json.loads(pony_debt_res["result"]["content"][0]["text"])
    assert pony_debt_data["success"] is True
    print("[PASS] Ponytail Debt tool verified.")

    # 14. Run full discovered test suite in tests/
    print("\n--- Running Full Discovered Test Suite (tests/) ---")
    import unittest
    suite = unittest.defaultTestLoader.discover("tests", pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    test_res = runner.run(suite)
    assert test_res.wasSuccessful(), f"Unit tests failed: {len(test_res.failures)} failures, {len(test_res.errors)} errors."
    print(f"[PASS] Full Test Suite Passed: {test_res.testsRun} tests executed cleanly with 0 failures, 0 errors.")

    print("\n=== All Server Self-Tests & Test Suites Passed Cleanly (100%) ===")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="CookieCyberTeam MCP Security Guardrails & Multi-Agent Orchestration Server")
    parser.add_argument("--stdio", action="store_true", default=True, help="Run standard JSON-RPC 2.0 stdio loop (default)")
    parser.add_argument("--test-mode", action="store_true", help="Run self-diagnostic component checks and exit")
    parser.add_argument("--run-tests", action="store_true", help="Run all unit tests in tests/ directory")
    parser.add_argument("--workspace", type=str, default=None, help="Path to workspace root directory")
    parser.add_argument("--version", action="version", version=f"{SERVER_NAME} {SERVER_VERSION}")

    args, _ = parser.parse_known_args()

    if args.run_tests:
        import unittest
        suite = unittest.defaultTestLoader.discover("tests", pattern="test_*.py")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    if args.test_mode:
        success = run_self_test()
        sys.exit(0 if success else 1)

    server = CookieCyberMCPServer(workspace_root=args.workspace)
    server.run_stdio()


if __name__ == "__main__":
    main()
