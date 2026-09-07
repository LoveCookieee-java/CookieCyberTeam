# BlueTeamAgent

Defensive security server implementing the Model Context Protocol (MCP) for automated vulnerability detection, patch validation guardrails, static binary triage, and multi-agent DAG task orchestration.

## Overview

BlueTeamAgent integrates defensive cybersecurity workflows into LLM programming environments (Cursor, Claude Code, Windsurf, Antigravity) via the standard MCP JSON-RPC protocol. It enforces verifiable patching rules to prevent hallucinations and regression vulnerabilities while coordinating multi-agent remediation pipelines.

### Core Capabilities

- **AST Security Analysis**: Static analysis engine (OWASP Top 10, CWE Top 25) with local taint tracking, import alias resolution, high-entropy secret detection, and Git delta scanning for modified lines.
- **Defensive Patch Guardrails**: 4-gate verification pipeline ensuring patch diffs do not exceed 50 lines, pass syntax pre-flight, introduce zero SAST regressions, and maintain single-committer branch isolation.
- **Air-Gapped Binary Triage**: Zero-execution static inspection of PE, ELF, Mach-O, DEX, and archive binaries with section header parsing (W^X detection), block Shannon entropy, and byte-offset IOC extraction.
- **Dynamic Sandbox Bridge**: REST client for automated detonation in external CAPEv2 and Cuckoo Sandbox environments.
- **Multi-Agent Orchestration**: Directed Acyclic Graph (DAG) task engine with FIPA ACL-compliant point-to-point mailbox messaging, SQLite WAL state persistence, and deadlock prevention.
- **Token-Efficient Code Search**: Syntactic AST chunking and SQLite FTS5 BM25 search reducing LLM context consumption by up to 98%.
- **Pure-Python Foundation**: Runs out-of-the-box on Python 3.9+ standard library with zero mandatory external dependencies; seamlessly accelerates when external toolchains are present.

---

## System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│           LLM Client (Cursor / Claude Code / Windsurf / AGY)           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ JSON-RPC 2.0 (stdio)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        BlueTeamAgent MCP Server                        │
├───────────────────────────────────┬────────────────────────────────────┤
│ MCP Tools (Execution)             │ MCP Resources (Context & State)    │
│ - mcp_scan_vulnerabilities        │ - mcp://rules/security-standards   │
│ - mcp_execute_sandbox_test        │ - mcp://rules/debugging-mindset    │
│ - mcp_create_reproduction_test    │ - mcp://state/agent-context        │
│ - mcp_apply_safe_patch            │ - mcp://state/tool-index           │
│ - mcp_orchestrate_dag             │ - mcp://playbooks/malware-triage   │
│ - mcp_search_code                 │ - mcp://playbooks/compromise-...   │
│ - mcp_triage_binary               ├────────────────────────────────────┤
│ - mcp_run_diagnostic_tool         │ MCP Prompts (Agent Mindsets)       │
│ - mcp_submit_dynamic_sandbox      │ - mcp_prompt_orchestrator          │
├───────────────────────────────────┤ - mcp_prompt_security_audit        │
│ Core Engines                      │ - mcp_prompt_hypothesis_debug      │
│ - AST Scanner & Taint Tracker     │ - mcp_prompt_safe_patch            │
│ - 4-Gate Patch Guardrails         │ - mcp_prompt_qa_review             │
│ - DAG Mailbox & Task Scheduler    │ - mcp_prompt_soc_incident_...      │
│ - Binary Triage & CAPEv2 Client   │                                    │
└───────────────────────────────────┴────────────────────────────────────┘
```

---

## Safety Invariants & Policies

### Zero-Execution Static Triage
Untrusted binaries and suspicious payloads are never executed on the host system. The triage engine inspects file structures, section headers, entropy distributions, and strings strictly through passive byte parsing. Dynamic behavioral analysis is isolated to Tier-2 Docker containers (`--network none`) or delegated to an external CAPEv2 sandbox.

### Absolute Prohibition of File Deletion
Autonomous agents operating through this server cannot execute destructive file operations (`rm`, `del`, `rmdir`, `Remove-Item`, `unlink`, `git clean`, `shutil.rmtree`, `os.remove`). All remediations must use targeted diff patching through the Safe Patch Manager.

### Dual-Tier Execution Sandboxing
- **Tier 1 (Subprocess Isolation)**: Active by default. Strips host environment variables using a strict whitelist (`PATH`, `SYSTEMROOT`, `TEMP`), forbids shell wrappers (`shell=False`), and forcefully terminates orphaned process trees on timeout.
- **Tier 2 (Container Isolation)**: Wraps test execution in Docker containers with disabled networking (`--network none`), read-only root filesystems, and temporary scratch volumes. Falls back to Tier 1 when Docker is unavailable.

---

## The 4 Patching Guardrails

All modifications applied through `mcp_apply_safe_patch` must clear four deterministic gates:

| Gate | Requirement | Failure Mode |
| :--- | :--- | :--- |
| **1. Diff Cap** | Changed lines $\le 50$ | Rejects patch to prevent hallucinated scope creep. |
| **2. Syntax Pre-Flight** | Valid AST syntax check before writing to disk | Rejects patch containing syntax errors. |
| **3. SAST Zero-Regression** | Finding count and CWE instances must not increase | Rejects patch if new or duplicate vulnerabilities are detected. |
| **4. Single-Committer** | Modification must originate from Lead Orchestrator | Rejects uncoordinated worker commits. |

---

## MCP Interface Reference

### Tools

| Tool | Purpose | Key Parameters |
| :--- | :--- | :--- |
| `mcp_scan_vulnerabilities` | AST SAST scanning with CWE matching, CVSS scoring, and Git delta filtering. | `target_path`, `git_delta_only`, `use_semgrep` |
| `mcp_execute_sandbox_test` | Run reproduction or unit tests in an isolated subprocess or Docker sandbox. | `test_file`, `test_args`, `sandbox_type`, `timeout` |
| `mcp_create_reproduction_test` | Create an automated reproduction test that validates vulnerability existence. | `target_module`, `reproduction_code`, `test_name` |
| `mcp_apply_safe_patch` | Apply a unified patch through the 4-gate verification engine. | `file_path`, `patch_diff`, `committer` |
| `mcp_orchestrate_dag` | Manage multi-agent task execution, status transitions, and mailbox messaging. | `action`, `task_id`, `recipient`, `message_content` |
| `mcp_search_code` | Syntactic AST chunk search with SQLite FTS5 BM25 scoring. | `query`, `target_dir`, `extensions`, `limit` |
| `mcp_triage_binary` | Passive static analysis of binaries: format, entropy, PE sections, IOCs. | `file_path`, `max_bytes` |
| `mcp_run_diagnostic_tool` | Execute whitelisted host reverse-engineering tools (`strings`, `r2`, `jadx`, etc.). | `tool_name`, `target_file`, `args` |
| `mcp_submit_dynamic_sandbox` | Submit binary to external CAPEv2/Cuckoo sandbox via REST API and retrieve analysis report. | `file_path`, `timeout` |

### Resources

| URI | Content |
| :--- | :--- |
| `mcp://rules/security-standards` | OWASP Top 10, CWE Top 25 guidelines, CVSS evaluation standards, and secure coding practices. |
| `mcp://rules/debugging-mindset` | 4-step scientific debugging methodology: Reproduce, Trace, Hypothesize, Confirm. |
| `mcp://state/agent-context` | SQLite WAL state containing active DAG tasks, dependency graphs, findings, and mailbox messages. |
| `mcp://state/tool-index` | Dynamic catalog of detected host tools (Semgrep, Radare2, Ghidra, JADX, CFR, Docker). |
| `mcp://playbooks/malware-triage` | NIST SP 800-61 Rev 3 static triage operating procedure. |
| `mcp://playbooks/compromise-assessment` | Incident containment, log correlation, and post-compromise remediation steps. |

### Prompts

| Name | Role | Workflow Focus |
| :--- | :--- | :--- |
| `mcp_prompt_orchestrator` | Lead Orchestrator | Task decomposition, DAG dependency scheduling, single-committer patch sign-off. |
| `mcp_prompt_security_audit` | Security Auditor | Attack surface mapping, STRIDE threat modeling, and SAST vulnerability scanning. |
| `mcp_prompt_hypothesis_debug` | Debugger | Minimal reproduction test generation, stack trace analysis, and root-cause hypothesis validation. |
| `mcp_prompt_safe_patch` | Patch Developer | Minimal diff patch generation ($\le 50$ lines) addressing confirmed root causes. |
| `mcp_prompt_qa_review` | QA Reviewer | Isolated test execution, regression verification, and patch sign-off. |
| `mcp_prompt_soc_incident_responder` | SOC Analyst | MITRE ATT&CK log correlation, binary IOC extraction, and containment playbooks. |

---

## Toolchain & Dependencies

BlueTeamAgent operates on a two-tier capability model:

1. **Core Runtime (Zero Dependencies)**: The full server, AST scanner, CVSS calculator, code search, binary triage, and DAG engine run using standard Python 3.9+ libraries (`ast`, `sqlite3`, `subprocess`, `hashlib`, `math`, `urllib`).
2. **Accelerators (Optional)**: If external tools are present in system `PATH`, the server automatically discovers and utilizes them.

### Optional Toolchain Installation

```bash
# Multi-language SAST (JavaScript, TypeScript, Go, Java, C/C++)
pip install semgrep

# Embedding-based code search
pip install semble

# Binary disassembly & analysis
# Windows: winget install radareorg.radare2
# macOS:   brew install radare2
# Linux:   sudo apt install radare2 binutils

# Java & Android bytecode decompilation
# Windows: choco install jadx
# macOS:   brew install jadx cfr
```

---

## Configuration

### MCP Client Setup

Add BlueTeamAgent to your client configuration (e.g. `claude_desktop_config.json`, Windsurf, or Cursor):

```json
{
  "mcpServers": {
    "blue-team-security": {
      "command": "python",
      "args": ["/path/to/BlueTeamAgent/server.py", "--stdio"],
      "env": {
        "CAPE_API_URL": "https://cape.example.internal",
        "CAPE_API_KEY": "optional-api-token"
      }
    }
  }
}
```

### Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `CAPE_API_URL` | Base URL of CAPEv2 or Cuckoo Sandbox REST API. | `None` (dynamic submission returns configuration advisory) |
| `CAPE_API_KEY` | Bearer/token credential for CAPEv2 API authentication. | `None` |
| `DOCKER_HOST` | Docker daemon endpoint for Tier-2 container isolation. | System default |

---

## Verification & Testing

The test suite contains 123 automated unit tests covering all scanners, calculators, sandboxes, guardrails, and adapters.

```bash
# Run server diagnostic self-test
python server.py --test-mode

# Run full unittest suite
python -m unittest discover -s tests -v

# Run MCP server over stdio
python server.py --stdio
```

---

## Project Structure

```
BlueTeamAgent/
├── server.py                 # MCP server entry point (JSON-RPC stdio dispatcher)
├── core/
│   ├── ast_scanner.py        # AST SAST engine, taint tracker, entropy detector
│   ├── binary_triage.py      # Air-gapped static binary inspection & PE parser
│   ├── cape_adapter.py       # CAPEv2 / Cuckoo REST API dynamic sandbox bridge
│   ├── code_search.py        # AST syntactic chunking & SQLite FTS5 search
│   ├── cvss_calculator.py    # FIRST CVSS v3.1 vector parser & scoring
│   ├── dag_engine.py         # Multi-agent DAG task scheduler & mailbox
│   ├── guardrails.py         # 4-gate safe patch validation engine
│   ├── sandbox_runner.py     # Subprocess & Docker isolated test execution
│   ├── semgrep_adapter.py    # Multi-language external SAST bridge
│   ├── soc_rules.py          # Dynamic SOC detection rules & MITRE ATT&CK mapping
│   └── tool_indexer.py       # Host reverse-engineering toolchain catalog & runner
├── tests/                    # 123 automated unit tests (100% pass rate)
└── .agents/                  # Autonomous rulesets and architecture genomes
```

## License

Apache License 2.0. See LICENSE for details.
