# Blue Team MCP Security Guardrails & Multi-Agent Orchestration Server

An elite Model Context Protocol (MCP) defensive security server and multi-agent DAG orchestrator designed to eliminate LLM guesswork, hallucinated patches, and new security regressions during vulnerability remediation.

Built following the **CookieGli Core** token economy (<600 tokens) and **Ponytail Principle** ("Shortest working diff wins", zero bloat, stdlib first).

---

## 🏛️ Architecture & System Components

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│               LLM CLIENTS (Cursor, Claude Code, Windsurf, Antigravity)                 │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ (MCP Protocol - JSON-RPC 2.0 Stdio)
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                    BLUE-TEAM MCP SECURITY & ORCHESTRATION SERVER                       │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. MINDSET & RULE ENGINE                                                               │
│    • 4-Step Hypothesis-Driven Debugging: Reproduce -> Trace -> Hypothesize -> Confirm  │
│    • Pure-Python AST SAST Engine (OWASP Top 10 & CWE Top 25 with Import Aliasing)      │
│    • Local Taint Tracking (CWE-89) & Shannon Entropy (CWE-798)                         │
│    • True Git Delta Scanning Engine (scan modified diff lines only)                    │
│    • FIRST.org CVSS v3.1 Vector Parser & Accurate Roundup Calculator                   │
│    • 3 Mandatory Patching Guardrails (Diff Cap <= 50, AST Pre-flight, Branch Guard)    │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 2. MCP TOOLS (JSON-RPC Dispatcher - 7 Tools)                                           │
│    • mcp_scan_vulnerabilities       : AST CWE/OWASP + Delta Scan + CVSS + Semgrep CLI   │
│    • mcp_execute_sandbox_test      : Isolated test runner (No shell=True, Whitelist)   │
│    • mcp_create_reproduction_test   : Minimal test generator (must fail before fix)     │
│    • mcp_apply_safe_patch          : Safe patch engine with 3 mandatory gates          │
│    • mcp_orchestrate_dag           : Multi-agent DAG coordinator & Mailbox via SQLite  │
│    • mcp_search_code               : Token-efficient syntactic AST chunking & FTS5     │
│    • mcp_triage_binary             : Air-gapped static binary triage (Zero-Execution)  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 3. MCP RESOURCES (Standards, Playbooks & Shared Memory - 6 Resources)                  │
│    • mcp://rules/security-standards: CWE/OWASP checklists & safe coding invariants     │
│    • mcp://rules/debugging-mindset : 4-Step scientific debugging process               │
│    • mcp://state/agent-context     : SQLite WAL shared state (DAG tasks & findings)    │
│    • mcp://state/tool-index        : Dynamic toolchain index (Decompilers, SAST, etc.) │
│    • mcp://playbooks/malware-triage: NIST SP 800-61 Rev 3 4-tier malware triage SOP   │
│    • mcp://playbooks/compromise-assessment: Containment & incident response playbook   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 4. MCP PROMPTS (Workflow Personas - 6 Prompts)                                         │
│    • mcp_prompt_orchestrator       : Lead Orchestrator: DAG decomposition & oversight  │
│    • mcp_prompt_security_audit     : Security Auditor: STRIDE threat model & SAST scan │
│    • mcp_prompt_hypothesis_debug   : Scientific Debugger: 4-step mindset & repro test  │
│    • mcp_prompt_safe_patch         : Patch Developer: Minimal diff <= 50 lines         │
│    • mcp_prompt_qa_review          : QA Reviewer: Sandbox execution & regression gate  │
│    • mcp_prompt_soc_incident_responder: SOC Responder: Incident containment & triage   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 The 3 Mandatory Patching Guardrails

1. **Diff Cap Gate ($\le 50$ lines changed):**
   Enforces the Ponytail Principle. Rejects bloated modifications, preventing hallucinations and unwanted refactoring.
2. **Syntax Pre-Flight & Zero-Regression SAST Gate:**
   Verifies syntax via `ast.parse` and guarantees zero newly introduced CWE vulnerabilities before files are modified on disk.
3. **Git Branch Isolation Gate:**
   Blocks direct commits or patches on protected branches (`main`, `master`, `prod`), requiring atomic feature branches (`fix/<task-id>`).

---

## 🚀 Quickstart & Usage

### 1. Run Diagnostic Self-Tests & Full Test Suite (78 Tests, 100% Pass)
```powershell
python server.py --test-mode
```

### 2. Launch MCP Server on Stdio (JSON-RPC 2.0)
```powershell
python server.py --stdio
```

### 3. MCP Client Configuration Example (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "blue-team-security": {
      "command": "python",
      "args": ["e:/AI/CookieAgent/BlueTeamAgent/server.py", "--stdio"]
    }
  }
}
```

---

## 📁 Repository Structure

- `server.py`: MCP Protocol Server (JSON-RPC 2.0 Stdio, 7 tools, 6 resources, 6 prompts).
- `core/ast_scanner.py`: Zero-dependency AST SAST engine with import alias tracking, local taint analysis, and Shannon entropy.
- `core/cvss_calculator.py`: FIRST.org standard CVSS v3.1 vector parser & floating-point accurate roundup.
- `core/code_search.py`: Hybrid code search (Syntactic AST Chunking + SQLite FTS5 BM25 + Reciprocal Rank Fusion), reducing context tokens by 98–99%.
- `core/binary_triage.py`: Air-gapped static binary triage (Zero-Execution Policy, magic byte identification, 1KB block Shannon entropy, string IOC extraction, SHA-256 evidence chain).
- `core/tool_indexer.py`: Dynamic toolchain indexer detecting local decompilers, disassemblers, and security scanners.
- `core/semgrep_adapter.py`: Multi-language SAST adapter (JS/TS, Go, Java, C/C++).
- `core/sandbox_runner.py`: Isolated test execution (argv list, zero `shell=True`, environment whitelist, Windows process tree termination, Docker isolation option).
- `core/guardrails.py`: Safe patching manager enforcing the 3 gates (Diff Cap <= 50, Syntax Pre-flight, Zero-Regression SAST).
- `core/dag_engine.py`: Multi-agent DAG task scheduler with SQLite WAL shared memory, point-to-point mailbox messaging, and Max Hop TTL = 20.
- `tests/`: 78 automated unit tests verifying all components with 100% pass rate.
- `.agents/`: Project rules (`AGENTS.md`) and architecture genome (`GENOME.md`).
