# Project Genome: Blue Team MCP Security Guardrails

## 1. DNA & Frameworks
- **Runtime**: Python 3.9+ (Verified on 3.11/3.13)
- **Protocol**: Model Context Protocol (MCP) JSON-RPC 2.0 over Stdio
- **Core Architecture**: Zero external dependencies (Python stdlib: `ast`, `sqlite3`, `subprocess`, `graphlib`, `math`, `difflib`)
- **Isolation**: Subprocess Argv Whitelist + Windows Process Tree Termination + Optional Docker Container

## 2. Key Modules & Entrypoints
- `server.py`: JSON-RPC 2.0 MCP server, tools/resources/prompts registry & self-diagnostic harness
- `core/cvss_calculator.py`: FIRST.org CVSS v3.1 vector parser & exact `cvss_roundup`
- `core/ast_scanner.py`: SAST engine (CWE-78, CWE-89, CWE-95, CWE-502, CWE-798, CWE-295), Shannon entropy & Git Delta scanner
- `core/semgrep_adapter.py`: Multi-language CLI adapter (JS/TS, Go, Java, C/C++)
- `core/sandbox_runner.py`: Secure test runner (argv list, zero `shell=True`, env whitelist, Docker option)
- `core/guardrails.py`: 3 Mandatory gates (Diff cap <= 50, AST syntax/Zero-regression SAST, Git branch guard)
- `core/dag_engine.py`: DAG task coordinator with `graphlib.TopologicalSorter` & SQLite WAL shared memory

## 3. Registered MCP Interfaces
- **Tools**: `mcp_scan_vulnerabilities`, `mcp_execute_sandbox_test`, `mcp_create_reproduction_test`, `mcp_apply_safe_patch`, `mcp_orchestrate_dag`
- **Resources**: `mcp://rules/security-standards`, `mcp://rules/debugging-mindset`, `mcp://state/agent-context`
- **Prompts**: `mcp_prompt_orchestrator`, `mcp_prompt_security_audit`, `mcp_prompt_hypothesis_debug`, `mcp_prompt_safe_patch`, `mcp_prompt_qa_review`

## 4. Testing & Verification
- `tests/`: 39 automated tests (100% pass) executed via `python server.py --test-mode`
