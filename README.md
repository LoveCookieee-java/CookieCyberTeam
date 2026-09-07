# CookieCyberTeam (CookieCyperTeam)

<p align="center">
  <strong>Single Unified Intelligent MCP Server, Defensive Guardrails & Autonomous Cyber Defense System</strong><br>
  <em>Next-Generation Model Context Protocol (MCP) JSON-RPC 2.0 implementation for autonomous vulnerability remediation, inter-procedural taint flow analysis, air-gapped binary triage, and zero-regression patch verification.</em>
</p>

<p align="center">
  <a href="https://github.com/LoveCookieee-java/CookieCyberTeam"><img src="https://img.shields.io/badge/Release-v1.0.0-blue.svg?style=flat-square" alt="Release"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.9+-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python"></a>
  <a href="#verification--testing"><img src="https://img.shields.io/badge/Tests-100%25%20Passed-success.svg?style=flat-square" alt="Tests"></a>
  <a href="#system-architecture"><img src="https://img.shields.io/badge/Protocol-MCP%20JSON--RPC%202.0-8A2BE2.svg?style=flat-square" alt="MCP"></a>
  <a href="#safety-invariants--policies"><img src="https://img.shields.io/badge/Safety-Zero--Deletion%20%7C%20Air--Gapped-red.svg?style=flat-square" alt="Safety"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square" alt="License"></a>
</p>

---

### Navigation
[Overview](#overview) • [Why CookieCyberTeam](#the-problem--why-cookiecyberteam) • [Architecture](#system-architecture) • [Single Intelligent MCP](#single-unified-intelligent-mcp-server) • [5 Guardrail Gates](#the-5-patching-guardrails) • [MCP Interface](#mcp-interface-reference) • [Toolchain](#toolchain--dependencies) • [Configuration](#configuration) • [Testing](#verification--testing)

---

## Overview

When LLMs attempt to fix security vulnerabilities or debug complex codebases, they routinely introduce new bugs, modify unrelated files, generate non-minimal patches, and hallucinate invalid syntax. When analyzing malware, unconstrained agents risk executing malicious binaries directly on host environments.

**CookieCyberTeam** (also recognized as **CookieCyperTeam**) is an enterprise-grade defensive Model Context Protocol (MCP) server that interfaces with LLM clients (Cursor, Claude Code, Windsurf, Antigravity) to enforce deterministic engineering guardrails. It eliminates tool fragmentation by providing a **Single Unified Intelligent MCP Server** powered by the **Project Genome Profiler**, Semble-style syntactic search, inter-procedural taint flow analysis, supply chain composition scanning (SCA), dual-format hunk/diff patching with auto-rollback, and air-gapped binary triage.

---

## The Problem & Why CookieCyberTeam

| Risk / Failure Mode in Unconstrained LLMs | CookieCyberTeam Defensive Guardrail | Verification Mechanism |
| :--- | :--- | :--- |
| **Tool Overload & Context Bloat**<br>Installing 5+ MCP servers loads 70+ schemas, burning 15K tokens and causing tool hallucination. | **Single Unified Intelligent MCP Server**<br>Project Genome Profiler (<5ms discovery) + Adaptive Meta-Guide (`mcp_adaptive_guide`) selects optimal tools per task intent. | Sub-5ms stack inspection, targeted commands, and zero schema fragmentation. |
| **Guesswork Debugging**<br>LLM modifies code based on assumptions without confirming root causes. | **Hypothesis-Driven Workflow**<br>Requires a minimal reproduction test case that fails before any patch is accepted. | Subprocess/Docker sandbox execution via `mcp_execute_sandbox_test`. |
| **Patch Hallucination & Scope Creep**<br>LLM rewrites 200+ lines, breaking unrelated features and coding conventions. | **Enforced Diff Cap & Ponytail Linter**<br>Hard limit of $\le 50$ modified lines ($\le 250$ for new scaffolding), dead code check (YAGNI), and stdlib priority. | AST analysis and diff parsing in `core/guardrails.py`. |
| **Regression Vulnerabilities**<br>Fixing one issue introduces another (e.g., SQL Injection, XXE, SSRF, or command execution). | **Zero-Regression SAST Gate & Inter-Procedural Taint**<br>Compares AST findings before and after patching; blocks any new or duplicated CWE findings across 17 CWE categories. | Inter-procedural call graph taint analysis (`core/ast_scanner.py`) + Semgrep CLI. |
| **Accidental Host Compromise**<br>Agent executes an untrusted binary or malware sample to "inspect" its behavior. | **Zero-Execution Policy**<br>Only passive binary triage (PE/ELF headers, section entropy, string IOC offsets) is allowed on host. | `core/binary_triage.py` parses file structures without executing payloads. Dynamic detonation is isolated to external CAPEv2 sandboxes. |
| **Destructive Actions**<br>Agent runs `rm`, `del`, or `unlink` to "clean up" directories. | **Absolute Zero-Deletion Invariant (Gate 4)**<br>Destructive primitives are strictly barred. Vault relocation uses atomic byte scrambling without unlinking. | AST/token scanning rejects `os.remove`, `unlink`, `rmdir`, `shutil.rmtree`, shell `rm`/`del`. |

---

## Single Unified Intelligent MCP Server

Instead of fragmenting defensive capabilities across multiple servers, **CookieCyberTeam** provides an all-in-one, intelligent server:

1. **Project Genome Profiler (`core/project_profiler.py`)**:
   - Executes in **< 5ms** using pure Python stdlib.
   - Detects primary programming languages (Python, TypeScript/JavaScript, Go, Rust, Java, C/C++), active frameworks (FastAPI, Django, Flask, Express, Next.js, React, Spring Boot), test runners (`pytest`, `unittest`, `jest`, `cargo test`, `go test`), git status (branch, dirty tree, protected branch check), and host diagnostic toolchains (`docker`, `semgrep`, `r2`, `ghidra`, `cfr`, `jadx`).
   - Categorizes repository risk profiles (`source_code_repository`, `embedded_system`, `malware_triage_vault`).

2. **Adaptive Meta-Guide (`mcp_adaptive_guide`)**:
   - Acts as a **Cognitive Anchor** for LLMs.
   - When the agent starts a task (`task_intent="security_audit"`, `"bugfix_patch"`, `"test_verification"`, etc.), calling `mcp_adaptive_guide` immediately returns:
     - **Exact recommended tool call sequence** (2–4 tools, preventing unnecessary tool calls).
     - **Active safety rules and guardrails** (diff cap, disallowed actions).
     - **Targeted test command lines** for the active file under test.
     - **Prohibited actions** (absolute prohibition of file deletion, no bloat).

---

## System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│           LLM Client (Cursor / Claude Code / Windsurf / AGY)           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ JSON-RPC 2.0 (stdio)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      CookieCyberTeam MCP Server                        │
│ MCP Tools (Execution - 16 Tools)  │ MCP Resources (Context & State)    │
│ • mcp_adaptive_guide (Genome)     │ • mcp://context/project-genome     │
│ • mcp_search_code (Semble FTS5)   │ • mcp://rules/active-guardrails    │
│ • mcp_scan_vulnerabilities (17CWE)│ • mcp://rules/security-standards   │
│ • mcp_audit_dependencies (SCA)    │ • mcp://rules/debugging-mindset    │
│ • mcp_create_reproduction_test    │ • mcp://state/agent-context        │
│ • mcp_execute_sandbox_test        │ • mcp://state/tool-index           │
│ • mcp_preview_surgical_patch      │ • mcp://playbooks/malware-triage   │
│ • mcp_apply_safe_patch (Dual/Roll)│ • mcp://playbooks/compromise-...   │
│ • mcp_triage_binary (Air-Gapped)  ├────────────────────────────────────┤
│ • mcp_run_diagnostic_tool         │ MCP Prompts (Agent Personas)       │
│ • mcp_submit_dynamic_sandbox      │ • mcp_prompt_orchestrator          │
│ • mcp_quarantine_artifact         │ • mcp_prompt_security_audit        │
│ • mcp_restore_quarantined_file    │ • mcp_prompt_hypothesis_debug      │
│ • mcp_generate_containment_rule   │ • mcp_prompt_safe_patch            │
│ • mcp_terminate_process           │ • mcp_prompt_qa_review             │
│ • mcp_orchestrate_dag (Mailbox)   │ • mcp_prompt_soc_incident_...      │
├───────────────────────────────────┴────────────────────────────────────┤
│ Core Engines                                                           │
│ • Project Genome Profiler (<5ms stack & test runner discovery)         │
│ • Offline Supply Chain SCA Scanner (OSV JSON database)                 │
│ • Inter-Procedural Call Graph & Taint Engine (17 CWEs)                 │
│ • 5-Gate Safe Patch Engine (Hunk JSON + Unified Diff + Auto-Rollback)  │
│ • Semble Syntactic Search (FTS5 BM25 + Identifier Tokenization)        │
│ • Air-Gapped Binary Triage & Zero-Execution Quarantine Vault           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## The 5 Patching Guardrails

Every patch dispatched to `mcp_apply_safe_patch` or `mcp_preview_surgical_patch` must pass all five gates:

```
Proposed Patch ──► [Gate 1: Polyglot Syntax Dispatch & Delimiter Check]
                         │ Pass
                         ▼
                   [Gate 1.5: Ponytail Linter (Dead Code & Stdlib First)]
                         │ Pass
                         ▼
                   [Gate 2: Dual-Threshold Diff Cap (<=50 mod, <=250 new)]
                         │ Pass
                         ▼
                   [Gate 3: Zero-Regression Inter-Procedural SAST]
                         │ Pass
                         ▼
                   [Gate 4: Absolute Zero-Deletion Invariant]
                         │ Pass
                         ▼
                   [Gate 5: Single-Committer Capability Token] ──► Verified Application
```

### Gate Breakdown

1. **Gate 1: Polyglot Syntax Dispatch**:
   Parses Python via `ast.parse()`, JSON via `json.loads()`, YAML via `yaml.safe_load()`, Markdown code fences, and balanced delimiter stacks `()`, `[]`, `{}` for C/C++/Java/Go/JS/TS without external toolchain requirements.
2. **Gate 1.5: Ponytail Linter (Zero-Bloat Gate)**:
   - **Dead Code Check (YAGNI)**: Rejects newly created functions or classes that have no call sites in the codebase or tests (unless exported in `__all__`).
   - **Stdlib Prioritization**: Rejects adding external 3rd-party dependencies when Python stdlib equivalents exist, unless already listed in the project's dependency manifests.
3. **Gate 2: Dual-Threshold Diff Cap**:
   Applies a strict $\le 50$ modified lines limit for existing files, and a generous $\le 250$ lines limit for new scaffolding/test files.
4. **Gate 3: Zero-Regression Inter-Procedural SAST**:
   Validates AST findings before and after patching across 17 CWEs. Blocks new CWE additions and per-CWE finding count increases (`patched_counts[cwe] > orig_counts[cwe]`).
5. **Gate 4: Absolute Zero-Deletion Invariant**:
   Scans AST and tokens to reject destructive file operations (`os.remove`, `os.unlink`, `shutil.rmtree`, `rmdir`, shell `rm`/`del`).
6. **Gate 5: Single-Committer Isolation**:
   Requires ephemeral capability session tokens issued exclusively to `Lead Orchestrator` to prevent git lock contention and uncoordinated writes.

---

## MCP Interface Reference

### Tools (16 Tools)

| Tool | Description | Key Parameters |
| :--- | :--- | :--- |
| `mcp_adaptive_guide` | Cognitive anchor: discovers project genome and outputs optimal tool sequence, rules, and commands. | `task_intent`, `active_file` |
| `mcp_scan_vulnerabilities` | Inter-procedural AST SAST analysis across 17 CWEs with FIRST CVSS v3.1/v4.0 scoring and Git delta filtering. | `target_path`, `code_content`, `delta_only`, `output_format` |
| `mcp_audit_dependencies` | Offline Software Composition Analysis (SCA) checking requirements and lockfiles against curated OSV database. | `path` |
| `mcp_execute_sandbox_test` | Runs tests in isolated subprocess (argv whitelist, process tree kill) or optional Docker container. | `test_path`, `sandbox_type`, `timeout` |
| `mcp_create_reproduction_test` | Generates a minimal reproduction test that must fail before patch authoring (Hypothesis Step 1). | `save_path`, `test_code`, `vulnerability_type` |
| `mcp_preview_surgical_patch` | Dry-run gate verification (Gate 1.5, Gate 2, Gate 4) returning unified diff preview without touching disk. | `target_file`, `hunks`, `unified_diff`, `patched_content` |
| `mcp_apply_safe_patch` | Applies patch supporting hunks JSON, unified diff, or full content with Transactional Auto-Rollback. | `target_file`, `hunks`, `unified_diff`, `committer_token` |
| `mcp_orchestrate_dag` | Multi-Agent DAG workflow management, topological dependency checks, and mailbox routing. | `action`, `pipeline_id`, `task_id`, `from_agent`, `to_agent` |
| `mcp_search_code` | Semble-style identifier tokenization, method/skeleton chunking, and SQLite FTS5 BM25 search. | `query`, `target_path`, `mode`, `top_k` |
| `mcp_triage_binary` | Air-gapped static inspection of PE/ELF/Mach-O/DEX binaries ($W \oplus X$, Shannon entropy, safe IOCs). | `file_path` |
| `mcp_run_diagnostic_tool` | Executes whitelisted host CLI tools (`strings`, `readelf`, `objdump`, `cfr`, `jadx`, `r2`) with input sanitization. | `tool_name`, `target_file`, `args` |
| `mcp_submit_dynamic_sandbox` | Submits binary to CAPEv2/Cuckoo REST API or polls status non-blockingly (`async_mode=True`). | `file_path`, `task_id`, `async_mode` |
| `mcp_quarantine_artifact` | Relocates suspicious file to encrypted `.quarantine/` vault using atomic byte scrambling. | `file_path`, `quarantine_dir` |
| `mcp_restore_quarantined_file` | Safely restores quarantined file from encrypted vault back to original destination. | `quarantine_path`, `original_destination` |
| `mcp_generate_containment_rule` | Generates firewall & sinkhole containment rules (Windows netsh, Linux iptables, UFW, DNS). | `target`, `rule_type`, `port` |
| `mcp_terminate_process` | Terminates suspicious processes and entire descendant process trees (`taskkill /T` on Windows). | `pid`, `timeout` |

### Resources (8 Resources)

| Resource URI | Description |
| :--- | :--- |
| `mcp://context/project-genome` | Dynamic JSON genome: languages, frameworks, test runners, git status, host tools, risk profile. |
| `mcp://rules/active-guardrails` | Live status and thresholds for all 5 security guardrail gates. |
| `mcp://rules/security-standards` | Defensive coding standards for CWE-78, CWE-89, CWE-95, CWE-502, CWE-798, CWE-295, etc. |
| `mcp://rules/debugging-mindset` | 4-step scientific debugging methodology: Reproduce -> Trace -> Hypothesize -> Confirm. |
| `mcp://state/agent-context` | SQLite WAL state containing active DAG tasks, dependency graphs, findings, and mailboxes. |
| `mcp://state/tool-index` | Dynamic catalog of detected host analysis tools (Semgrep, Radare2, Ghidra, JADX, CFR, Docker). |
| `mcp://playbooks/malware-triage` | NIST SP 800-61 Rev 3 static triage operating procedures. |
| `mcp://playbooks/compromise-assessment` | Incident containment, log correlation, and agentic compromise assessment playbooks. |

---

## Configuration

### MCP Client Integration

Add CookieCyberTeam to your client configuration (e.g. `claude_desktop_config.json`, Windsurf, Cursor, Antigravity):

```json
{
  "mcpServers": {
    "cookie-cyber-team": {
      "command": "python",
      "args": ["/path/to/CookieCyberTeam/server.py", "--stdio"],
      "env": {
        "CAPE_API_URL": "https://cape.example.internal",
        "CAPE_API_KEY": "optional-api-token"
      }
    }
  }
}
```

### Repository Configuration (`.cookiecyber.toml` or `cookiecyber.json`)

CookieCyberTeam loads `.cookiecyber.toml` or `cookiecyber.json` at repository root:

```toml
# .cookiecyber.toml
[cookiecyber]
diff_cap_limit = 50
new_file_cap_limit = 250
restricted_branches = ["main", "master", "prod", "production", "release"]
exclude_dirs = ["vendor", "node_modules", ".git", "dist", "build", "__pycache__"]
shannon_entropy_threshold = 7.5
cvss_version = "3.1"
log_level = "INFO"

[cookiecyber.guardrails]
enable_ponytail_linter = true
enable_zero_deletion = true
enforce_single_committer = true
```

---

## Standalone Headless CLI & Pre-Commit Hook

CookieCyberTeam includes a standalone CLI (`core/cli.py`) for CI/CD pipelines and local terminal workflows:

```bash
# 1. Run SAST security scan with exit-code gating
python -m core.cli scan --path . --format json --fail-on high

# 2. Export OASIS SARIF v2.1.0 for GitHub Code Scanning
python -m core.cli scan --path src/ --format sarif > results.sarif

# 3. Supply chain SCA dependency audit
python -m core.cli audit --path .

# 4. Air-gapped static binary triage
python -m core.cli triage --file suspicious_sample.bin

# 5. Generate multi-platform containment firewall rules
python -m core.cli contain --target 198.51.100.42 --rule-type block --port 4444

# 6. Adaptive meta-guide exploration
python -m core.cli guide --intent security_audit
```

### Pre-Commit Hook Integration

Add CookieCyberTeam directly into your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/LoveCookieee-java/CookieCyberTeam
    rev: v1.0.0
    hooks:
      - id: cookiecyber-scan
```

---

## Verification & Testing

The test suite contains **comprehensive automated unit tests** verifying all scanners, calculators, sandboxes, guardrails, containment vaults, profilers, SCA engines, and MCP tools with a 100% pass rate.

```bash
# Run server diagnostic self-test
python server.py --test-mode

# Run full unittest suite
python -m unittest discover -s tests -v

# Run MCP server over stdio
python server.py --stdio
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
