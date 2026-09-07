# Project Genome: Blue Team MCP Security Guardrails & Defensive Operations

## 1. DNA & Frameworks
- **Version**: 1.2.0
- **Runtime**: Python 3.9+ (Verified on 3.11/3.13)
- **Protocol**: Model Context Protocol (MCP) JSON-RPC 2.0 over Stdio
- **Core Architecture**: Zero external dependencies (Python stdlib: `ast`, `sqlite3`, `subprocess`, `graphlib`, `math`, `difflib`, `hashlib`, `re`, `struct`, `dataclasses`)
- **Isolation**: Subprocess Argv Whitelist + Windows Process Tree Termination (`taskkill`) + Optional Docker Container

## 2. Key Modules & Entrypoints
- `server.py`: JSON-RPC 2.0 MCP server, tools/resources/prompts registry & self-diagnostic harness (v1.2.0)
- `core/cvss_calculator.py`: FIRST.org CVSS v3.1 vector parser & exact integer modular `cvss_roundup`
- `core/ast_scanner.py`: Pure-Python SAST engine (CWE-78, CWE-89, CWE-95, CWE-502, CWE-798, CWE-295), Shannon entropy & Git Delta scanner
- `core/semgrep_adapter.py`: Multi-language CLI adapter (JS/TS, Go, Java, C/C++)
- `core/sandbox_runner.py`: Secure test runner (argv list, zero `shell=True`, env whitelist, Docker isolation)
- `core/guardrails.py`: 4 Mandatory gates (Diff cap <= 50, AST syntax/Zero-regression SAST, Git branch guard, Single-Committer isolation)
- `core/dag_engine.py`: DAG task coordinator with `graphlib.TopologicalSorter`, SQLite WAL shared memory, Point-to-Point Mailbox (TTL=20), and orphaned task recovery
- `core/code_search.py`: Hybrid code search (Syntactic AST multi-lang chunking, SQLite FTS5 BM25 WAL persistent cache, Reciprocal Rank Fusion)
- `core/binary_triage.py`: Air-gapped static binary triage (PE section table W^X, streaming chunk hash, hex offset IOCs, Java Class vs Mach-O FAT disambiguation)
- `core/soc_rules.py`: Pure-Python SOC dynamic detection rule engine (MITRE ATT&CK mapping: T1055, T1059.001, T1003, T1071, T1547.001 & incident playbooks)
- `core/tool_indexer.py`: Diagnostic reverse-engineering toolchain indexer & runner (strings, readelf, objdump, cfr, jadx, r2)
- `core/cape_adapter.py`: Dynamic malware sandbox REST API adapter (CAPEv2 / Cuckoo integration bridge, task polling & IOC extraction)

## 3. Registered MCP Interfaces
- **Tools (9)**:
  1. `mcp_scan_vulnerabilities`
  2. `mcp_execute_sandbox_test`
  3. `mcp_create_reproduction_test`
  4. `mcp_apply_safe_patch` (Single-Committer gate enforced)
  5. `mcp_orchestrate_dag` (Mailbox routing & orphan recovery)
  6. `mcp_search_code` (AST chunks & persistent SQLite WAL cache)
  7. `mcp_triage_binary` (Zero-execution static inspection & SOC analytic evaluation)
  8. `mcp_run_diagnostic_tool` (Whitelisted host reverse-engineering runner)
  9. `mcp_submit_dynamic_sandbox` (CAPEv2/Cuckoo external dynamic sandbox bridge)
- **Resources (6)**:
  1. `mcp://rules/security-standards`
  2. `mcp://rules/debugging-mindset`
  3. `mcp://state/agent-context`
  4. `mcp://rules/binary-triage-policy`
  5. `mcp://state/code-search-index`
  6. `mcp://rules/soc-incident-playbooks`
- **Prompts (6)**:
  1. `mcp_prompt_orchestrator`
  2. `mcp_prompt_security_audit`
  3. `mcp_prompt_hypothesis_debug`
  4. `mcp_prompt_safe_patch`
  5. `mcp_prompt_qa_review`
  6. `mcp_prompt_soc_responder`

## 4. Testing & Verification
- `tests/`: 123 automated tests across 7 test suites (100% pass) executed via `python server.py --test-mode` and `python -m unittest discover -s tests -v`.
