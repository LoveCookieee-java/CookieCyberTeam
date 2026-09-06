"""
Blue Team MCP Security Guardrails & Multi-Agent Orchestration Server.
Standard JSON-RPC 2.0 stdio MCP Server.
Packages 7 Tools, 6 Resources, and 6 Prompts for safe, scientific defensive engineering,
zero-regression patching, air-gapped binary triage, and multi-agent coordination.
"""

from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.ast_scanner import ASTScanner
from core.binary_triage import BinaryTriageEngine
from core.code_search import HybridCodeSearch
from core.cvss_calculator import cvss_for_cwe, calculate_cvss_score
from core.dag_engine import DAGEngine, DAGCycleError, MAX_HOP_TTL
from core.guardrails import SafePatchManager, GuardrailViolation, find_git_root
from core.sandbox_runner import SandboxRunner
from core.semgrep_adapter import SemgrepAdapter
from core.tool_indexer import ToolchainIndexer


SERVER_NAME = "blue-team-security-guardrails"
SERVER_VERSION = "1.1.0"
PROTOCOL_VERSION = "2024-11-05"


# ---------------------------------------------------------------------------
# Static Security Resources Content
# ---------------------------------------------------------------------------

SECURITY_STANDARDS_RESOURCE = """# Blue Team Security Standards & Defensive Guardrails

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


# ---------------------------------------------------------------------------
# MCP Server Implementation
# ---------------------------------------------------------------------------

class BlueTeamMCPServer:
    """Standard JSON-RPC 2.0 Stdio MCP Server."""

    def __init__(self, db_path: Optional[str | Path] = None):
        self.scanner = ASTScanner()
        self.semgrep = SemgrepAdapter()
        self.sandbox = SandboxRunner()
        self.patch_manager = SafePatchManager()
        self.dag_engine = DAGEngine(db_path=db_path)
        self.code_searcher = HybridCodeSearch()
        self.tool_indexer = ToolchainIndexer()
        self.binary_triage_engine = BinaryTriageEngine()

    # -----------------------------------------------------------------------
    # Tool Handlers (7 Tools)
    # -----------------------------------------------------------------------

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
            p = Path(target_path)
            if p.suffix.lower() == ".py" or not use_semgrep:
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

        return {
            "success": True,
            "total_findings": len(findings),
            "max_cvss_score": max_cvss,
            "overall_severity": "Critical" if max_cvss >= 9.0 else ("High" if max_cvss >= 7.0 else ("Medium" if max_cvss >= 4.0 else "Low")),
            "severity_distribution": severity_counts,
            "residual_vulnerabilities": residual_vulnerabilities,
            "findings": findings,
        }

    def tool_execute_sandbox_test(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run tests under isolated sandbox environment."""
        test_path = args.get("test_path")
        timeout = int(args.get("timeout", 30))
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

        target = Path(save_path).resolve()
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
        task_id = args.get("task_id", "bugfix")
        repo_path = args.get("repo_path")

        if not target_file or patched_content is None:
            return {"success": False, "error": "target_file and patched_content are required."}

        try:
            res = self.patch_manager.apply_safe_patch(
                target_file_path=target_file,
                patched_content=patched_content,
                task_id=task_id,
                repo_path=repo_path,
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
        action = args.get("action", "get_summary")

        if action == "init_pipeline":
            pipeline_id = args.get("pipeline_id", f"pipe_{int(time.time())}")
            target_file = args.get("target_file", "unknown.py")
            include_soc = bool(args.get("include_soc", False))
            return self.dag_engine.create_standard_security_pipeline(pipeline_id, target_file, include_soc=include_soc)

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

        # Default: get_summary
        return {"success": True, "summary": self.dag_engine.get_dag_summary()}

    def tool_search_code(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Search code using Syntactic AST Chunking and SQLite FTS5 BM25."""
        query = args.get("query")
        target_path = args.get("target_path", ".")
        top_k = int(args.get("top_k", 5))

        if not query:
            return {"success": False, "error": "query parameter is required."}

        return self.code_searcher.search(query=query, target_path=target_path, top_k=top_k)

    def tool_triage_binary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Safely triage binary artifacts (PE/ELF/ZIP/DEX) under Zero-Execution Policy."""
        file_path = args.get("file_path")
        if not file_path:
            return {"success": False, "error": "file_path parameter is required."}

        return self.binary_triage_engine.triage_file(file_path=file_path)

    # -----------------------------------------------------------------------
    # Specifications & Metadata (7 Tools, 6 Resources, 6 Prompts)
    # -----------------------------------------------------------------------

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return MCP standard Tool definitions (7 Tools)."""
        return [
            {
                "name": "mcp_scan_vulnerabilities",
                "description": "Performs SAST security scan using Pure-Python AST Engine (CWE-78, CWE-89, CWE-95, CWE-502, CWE-798, CWE-295), Delta Git scanning, CVSS v3.1 scoring, and optional Semgrep CLI adapter.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "description": "Absolute or relative path to file to scan."},
                        "code_content": {"type": "string", "description": "Optional in-memory code string to scan directly."},
                        "delta_only": {"type": "boolean", "description": "If true, scans only modified lines from git diff."},
                        "base_commit": {"type": "string", "description": "Base Git commit for diff comparison (default: 'HEAD')."},
                        "use_semgrep": {"type": "boolean", "description": "If true, enables Semgrep multi-language adapter."},
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
                "name": "mcp_apply_safe_patch",
                "description": "Applies source code patch protected by 3 safety guardrails: Diff Cap (<=50 lines), Zero-Regression SAST, and Git Branch Isolation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_file": {"type": "string", "description": "File path to apply the patch to."},
                        "patched_content": {"type": "string", "description": "Complete new content for the target file."},
                        "task_id": {"type": "string", "description": "Identifier of the fixing task (default: 'bugfix')."},
                        "repo_path": {"type": "string", "description": "Optional Git repository root path."},
                    },
                    "required": ["target_file", "patched_content"],
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
                                "check_drainage", "get_messages",
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
                        "status": {"type": "string", "enum": ["PENDING", "READY", "RUNNING", "COMPLETED", "FAILED"]},
                        "result": {"type": "object", "description": "Task output payload."},
                        "key": {"type": "string", "description": "Shared context key."},
                        "value": {"description": "Shared context JSON value."},
                        "from_agent": {"type": "string", "description": "Sender agent for mailbox message."},
                        "to_agent": {"type": "string", "description": "Recipient agent for mailbox message."},
                        "speech_act": {"type": "string", "enum": ["INFORM", "REQUEST", "PROPOSE", "CONFIRM", "ESCALATE"]},
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
                "description": "Surgical code search using AST Syntactic Chunking + SQLite FTS5 BM25 + Reciprocal Rank Fusion. Returns targeted class/function chunks (<100 tokens).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query keywords or function/class symbols."},
                        "target_path": {"type": "string", "description": "Target file or directory path to index and search."},
                        "top_k": {"type": "integer", "description": "Maximum number of chunks to return (default: 5)."},
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
        ]

    def get_resource_definitions(self) -> List[Dict[str, Any]]:
        """Return MCP standard Resource definitions (6 Resources)."""
        return [
            {
                "uri": "mcp://rules/security-standards",
                "name": "Blue Team Security Standards & Defensive Guardrails",
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
        ]

    def read_resource(self, uri: str) -> Dict[str, Any]:
        """Return contents for requested resource URI."""
        if uri == "mcp://rules/security-standards":
            return {"uri": uri, "mimeType": "text/markdown", "text": SECURITY_STANDARDS_RESOURCE}
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
        raise ValueError(f"Resource not found: {uri}")

    def get_prompt_definitions(self) -> List[Dict[str, Any]]:
        """Return MCP standard Prompt definitions (6 Prompts)."""
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
                "5. Agent Safety Invariant: Absolute prohibition of unauthorized file deletion (no rm, del, rmdir, Remove-Item, unlink, or destroying user files)."
            )
        elif name == "mcp_prompt_security_audit":
            target = args.get("target_file", "unknown.py")
            content = (
                f"You are the Security Auditor auditing '{target}'.\n"
                "1. Use `mcp_search_code` to locate relevant functions with minimal token consumption.\n"
                "2. Run `mcp_scan_vulnerabilities(target_path='{target}')` to identify CWE-78, CWE-89, CWE-95, CWE-502, CWE-798, CWE-295.\n"
                "3. Verify FIRST CVSS v3.1 scores and attack surface vectors.\n"
                "4. Record findings in shared context and inform the Lead Orchestrator via mailbox."
            )
        elif name == "mcp_prompt_hypothesis_debug":
            vuln = args.get("vulnerability", "Unknown defect")
            target = args.get("target_file", "unknown.py")
            content = (
                f"You are the Scientific Debugger addressing '{vuln}' in '{target}'.\n"
                "Follow the 4-step mindset strictly. DO NOT GUESS CODE.\n"
                "Step 1: Write a minimal reproduction test and verify it FAILS using `mcp_create_reproduction_test`.\n"
                "Step 2: Trace execution flow and isolate root cause.\n"
                "Step 3: Formulate a falsifiable hypothesis.\n"
                "Step 4: Confirm root cause via AST and pass confirmed analysis to Patch Developer via mailbox."
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
                "4. Agent Safety Rule: Absolute prohibition of unauthorized file deletion (no rm, del, Remove-Item, unlink, or destroying user code)."
            )
        elif name == "mcp_prompt_qa_review":
            target = args.get("target_file", "unknown.py")
            repro = args.get("repro_test", "tests/test_repro.py")
            content = (
                f"You are the QA / Code Reviewer inspecting the fix for '{target}'.\n"
                f"1. Run `mcp_execute_sandbox_test(test_path='{repro}')` to verify the reproduction test now PASSES.\n"
                "2. Run regression test suites to guarantee 0 regressions.\n"
                f"3. Run `mcp_scan_vulnerabilities(target_path='{target}', delta_only=True)` to confirm zero new CWEs were introduced.\n"
                "4. Agent Safety Verification: Verify patch contains zero unauthorized file deletions or destructive mutations."
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
                "4. Check available host tools using `mcp://state/tool-index` for deeper analysis (Ghidra, radare2, strings).\n"
                "5. Report containment and eradication plan to Lead Orchestrator via mailbox."
            )
        else:
            raise ValueError(f"Unknown prompt name: {name}")

        return {
            "description": f"Blue Team Role: {name}",
            "messages": [
                {
                    "role": "user",
                    "content": {"type": "text", "text": content},
                }
            ],
        }

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

            handler_map: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
                "mcp_scan_vulnerabilities": self.tool_scan_vulnerabilities,
                "mcp_execute_sandbox_test": self.tool_execute_sandbox_test,
                "mcp_create_reproduction_test": self.tool_create_reproduction_test,
                "mcp_apply_safe_patch": self.tool_apply_safe_patch,
                "mcp_orchestrate_dag": self.tool_orchestrate_dag,
                "mcp_search_code": self.tool_search_code,
                "mcp_triage_binary": self.tool_triage_binary,
            }

            if tool_name not in handler_map:
                return make_err(-32601, f"Method or tool not found: {tool_name}")

            try:
                res = handler_map[tool_name](arguments)
                return make_res({
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(res, indent=2),
                        }
                    ],
                    "isError": not res.get("success", True),
                })
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


def run_self_test() -> bool:
    """Perform comprehensive self-diagnostic test on all components."""
    print("=== Blue Team MCP Server Self-Test ===")
    server = BlueTeamMCPServer(db_path=":memory:")

    # 1. Test Tools list (7 Tools)
    tools = server.get_tool_definitions()
    assert len(tools) == 7, f"Expected 7 tools, got {len(tools)}"
    tool_names = {t["name"] for t in tools}
    assert "mcp_search_code" in tool_names
    assert "mcp_triage_binary" in tool_names
    print(f"[PASS] Tools verified: {len(tools)} registered ({', '.join(sorted(tool_names))}).")

    # 2. Test Resources list & read (6 Resources)
    resources = server.get_resource_definitions()
    assert len(resources) == 6, f"Expected 6 resources, got {len(resources)}"
    r_standards = server.read_resource("mcp://rules/security-standards")
    assert "CWE-78" in r_standards["text"]
    r_tool_index = server.read_resource("mcp://state/tool-index")
    assert "Toolchain Index" in r_tool_index["text"]
    r_malware = server.read_resource("mcp://playbooks/malware-triage")
    assert "Zero-Execution Policy" in r_malware["text"]
    r_compromise = server.read_resource("mcp://playbooks/compromise-assessment")
    assert "Single-Committer" in r_compromise["text"]
    print(f"[PASS] Resources verified: {len(resources)} registered and readable.")

    # 3. Test Prompts list & get (6 Prompts)
    prompts = server.get_prompt_definitions()
    assert len(prompts) == 6, f"Expected 6 prompts, got {len(prompts)}"
    p_orch = server.get_prompt("mcp_prompt_orchestrator", {"issue_description": "Test", "target_file": "app.py"})
    assert "Lead Orchestrator" in p_orch["messages"][0]["content"]["text"]
    p_soc = server.get_prompt("mcp_prompt_soc_incident_responder", {"incident_description": "Malware Outbreak", "artifact_path": "sample.exe"})
    assert "SOC Incident Responder" in p_soc["messages"][0]["content"]["text"]
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
    print(f"[PASS] Air-Gapped Binary Triage tool verified: PE recognized, URL IOC caught.")

    # 9. Run full discovered test suite in tests/
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
    parser = argparse.ArgumentParser(description="Blue Team MCP Security Guardrails & Multi-Agent Orchestration Server")
    parser.add_argument("--stdio", action="store_true", default=True, help="Run standard JSON-RPC 2.0 stdio loop (default)")
    parser.add_argument("--test-mode", action="store_true", help="Run self-diagnostic component checks and exit")
    parser.add_argument("--run-tests", action="store_true", help="Run all unit tests in tests/ directory")
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

    server = BlueTeamMCPServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
