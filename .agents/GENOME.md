# Project Genome: CookieCyberTeam Security Guardrails & Autonomous Defense System

## 1. DNA & Frameworks
- **Version**: CookieCyberTeam V1.0.1 (Enterprise)
- **Runtime**: Python 3.9+ (Verified on 3.11/3.13)
- **Protocol**: Model Context Protocol (MCP) JSON-RPC 2.0 over Stdio
- **Core Architecture**: Zero external dependencies (Python stdlib: `ast`, `sqlite3`, `subprocess`, `graphlib`, `math`, `difflib`, `hashlib`, `re`, `struct`, `dataclasses`, `urllib`, `json`)
- **Isolation**: Subprocess Argv Whitelist + Windows Process Tree Termination (`taskkill`) + Optional Docker Container
- **Single Unified Intelligent Server**: 1 MCP Server with Project Genome Profiler and Adaptive Meta-Guide

## 2. Key Modules & Entrypoints
- `server.py`: JSON-RPC 2.0 MCP server (`cookie-cyber-team`), 16 tools, 8 resources, 6 prompts & self-diagnostic harness
- `core/project_profiler.py`: ProjectGenomeProfiler (<5ms tech stack, test runner, git status, risk profile discovery & adaptive guidance)
- `core/sca_scanner.py`: Offline pure-Python Software Composition Analysis (OSV JSON database)
- `core/guardrails.py`: 5 Mandatory gates (Syntax dispatch, Ponytail linter/Zero-Bloat, Diff cap, Zero-regression SAST, Zero-deletion, Transactional auto-rollback)
- `core/ast_scanner.py`: Inter-procedural Call Graph & Taint tracking, 17 CWEs, Shannon entropy & Git Delta scanner
- `core/code_search.py`: Semble-style identifier tokenization, method/skeleton chunking, and SQLite FTS5 BM25 column weights
- `core/config.py`: `CookieCyberConfig` loader supporting `.cookiecyber.toml` and `cookiecyber.json`
- `core/cvss_calculator.py`: FIRST.org CVSS v3.1 & v4.0 vector parser & exact integer modular `cvss_roundup`
- `core/containment.py`: Zero-deletion scramble vault, firewall rule generation (Windows/Linux/DNS), safe process tree termination
- `core/binary_triage.py`: Air-gapped static binary triage (PE/ELF/ZIP/DEX headers, 1KB block Shannon entropy, safe string IOCs)
- `core/cape_adapter.py`: Dynamic malware sandbox REST API adapter (CAPEv2 / Cuckoo integration bridge, non-blocking polling)
- `core/dag_engine.py`: DAG task coordinator with `graphlib.TopologicalSorter`, SQLite WAL shared memory, Point-to-Point Mailbox (TTL=20)
- `core/soc_rules.py`: Pure-Python SOC dynamic detection rule engine (MITRE ATT&CK mapping & playbooks)
- `core/tool_indexer.py`: Diagnostic reverse-engineering toolchain indexer & runner (strings, readelf, objdump, cfr, jadx, r2)
- `core/sandbox_runner.py`: Secure test runner (argv list, zero `shell=True`, env whitelist, Docker isolation)
- `core/semgrep_adapter.py`: Multi-language CLI adapter (JS/TS, Go, Java, C/C++)
- `core/cli.py`: CookieCyberTeam CLI tool (`scan`, `search`, `audit`, `triage`, `guide`, `sandbox`)

## 3. Registered MCP Interfaces
- **Tools (16)**:
  1. `mcp_adaptive_guide` (Project Genome & Adaptive Meta-Guide)
  2. `mcp_scan_vulnerabilities` (17 CWEs AST & Call Graph Taint)
  3. `mcp_audit_dependencies` (Supply Chain SCA)
  4. `mcp_execute_sandbox_test` (Sandboxed Execution)
  5. `mcp_create_reproduction_test` (Hypothesis Testing)
  6. `mcp_preview_surgical_patch` (Dry-Run Gate 1.5 & Diff Preview)
  7. `mcp_apply_safe_patch` (Dual-Format Hunk + Diff with Auto-Rollback)
  8. `mcp_orchestrate_dag` (Multi-Agent DAG & Mailbox)
  9. `mcp_search_code` (Semble & FTS5 BM25 Syntactic Search)
  10. `mcp_triage_binary` (Air-Gapped Header & Entropy Inspection)
  11. `mcp_run_diagnostic_tool` (Whitelisted CLI Tools)
  12. `mcp_submit_dynamic_sandbox` (CAPEv2/Cuckoo REST Detonation)
  13. `mcp_quarantine_artifact` (Zero-Deletion Scramble Vault)
  14. `mcp_restore_quarantined_file` (Safe Vault Restoration)
  15. `mcp_generate_containment_rule` (Firewall Rule Generation)
  16. `mcp_terminate_process` (Safe Process Tree Termination)
- **Resources (8)**:
  1. `mcp://rules/security-standards`
  2. `mcp://rules/debugging-mindset`
  3. `mcp://state/agent-context`
  4. `mcp://state/tool-index`
  5. `mcp://playbooks/malware-triage`
  6. `mcp://playbooks/compromise-assessment`
  7. `mcp://context/project-genome`
  8. `mcp://rules/active-guardrails`
- **Prompts (6)**:
  1. `mcp_prompt_orchestrator`
  2. `mcp_prompt_security_audit`
  3. `mcp_prompt_hypothesis_debug`
  4. `mcp_prompt_safe_patch`
  5. `mcp_prompt_qa_review`
  6. `mcp_prompt_soc_incident_responder`

## 4. Testing & Verification
- `tests/`: Automated unit and integration test suite executing via `python -m unittest discover -s tests -v` and `python server.py --test-mode`.
