# Blue Team MCP Security Guardrails & Multi-Agent Orchestration Server

An elite Model Context Protocol (MCP) defensive security server and multi-agent DAG orchestrator designed to eliminate LLM guesswork, hallucinated patches, and new security regressions during vulnerability remediation.

Built following the **CookieGli Core** token economy (<600 tokens) and **Ponytail Principle** ("Shortest working diff wins", zero bloat, stdlib first).

---

> [!IMPORTANT]
> **Advisory: Zero-Execution Policy & Host Safety Invariant**
> - **Strict Static Triage**: BlueTeamAgent performs zero-execution static analysis directly on host. Live, untrusted malware samples and suspicious binaries must **NEVER** be executed directly on the host system.
> - **Detonation Containment**: When dynamic execution or behavioural analysis is required, always route through either:
>   1. **Tier-2 Docker Isolation** (`sandbox_type="docker"` with `--network none` and read-only mounts).
>   2. **External Dedicated Dynamic Sandboxes** via the CAPEv2 / Cuckoo REST API bridge (`mcp_submit_dynamic_sandbox`).

> [!WARNING]
> **Advisory: Mandatory Safety Invariant — Absolute Prohibition of File Deletion**
> - Autonomous agents are **strictly prohibited** from performing destructive actions or deleting files (`rm`, `del`, `rmdir`, `Remove-Item`, `unlink`, `git clean`, `shutil.rmtree`, `os.remove`).
> - The **Safe Patch Manager** enforces four automated gates before modifying files: Diff Cap ($\le 50$ lines), AST Pre-Flight Syntax Check, Zero-Regression SAST Gate, and Lead Orchestrator Single-Committer Isolation.

> [!NOTE]
> **Advisory: Dual-Tier Sandbox Architecture**
> - **Tier-1 (Subprocess Argv + Env Whitelist + Process Tree Kill)**: Active out-of-the-box with **zero host prerequisites**. Enforces strict `argv` array passing, strips environment secrets via whitelist, and cleanly terminates spawned process subtrees on timeout (`taskkill /F /T /PID` on Windows, process groups on POSIX).
> - **Tier-2 (Containerized Docker Sandbox)**: Optional containerized runtime for complete filesystem and network isolation (`--network none`). Requires an active Docker daemon on host; automatically falls back gracefully to Tier-1 if Docker is not running.

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
│    • 4 Mandatory Patching Guardrails (Diff Cap <= 50, AST Pre-flight, Branch Guard)    │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 2. MCP TOOLS (JSON-RPC Dispatcher - 9 Tools)                                           │
│    • mcp_scan_vulnerabilities       : AST CWE/OWASP + Delta Scan + CVSS + Semgrep CLI   │
│    • mcp_execute_sandbox_test      : Isolated test runner (No shell=True, Whitelist)   │
│    • mcp_create_reproduction_test   : Minimal test generator (must fail before fix)     │
│    • mcp_apply_safe_patch          : Safe patch engine with 4 mandatory gates          │
│    • mcp_orchestrate_dag           : Multi-agent DAG coordinator & Mailbox via SQLite  │
│    • mcp_search_code               : Token-efficient syntactic AST chunking & FTS5     │
│    • mcp_triage_binary             : Air-gapped static binary triage (Zero-Execution)  │
│    • mcp_run_diagnostic_tool       : Whitelisted host RE runner (strings, r2, cfr...)  │
│    • mcp_submit_dynamic_sandbox    : CAPEv2/Cuckoo external dynamic sandbox bridge     │
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

## 🔒 The 4 Mandatory Patching Guardrails

1. **Diff Cap Gate ($\le 50$ lines changed):**
   Enforces the Ponytail Principle. Rejects bloated modifications, preventing hallucinations and unwanted refactoring.
2. **Syntax Pre-Flight & Zero-Regression SAST Gate:**
   Verifies syntax via `ast.parse` and guarantees zero newly introduced CWE vulnerabilities before files are modified on disk.
3. **Git Branch Isolation Gate:**
   Blocks direct commits or patches on protected branches (`main`, `master`, `prod`), requiring atomic feature branches (`fix/<task-id>`).
4. **Single-Committer Gate:**
   Guarantees that only the Lead Orchestrator agent persona can commit modifications to the repository, eliminating race conditions and unauthorized worker commits.

---

## 🛠️ External Toolchains & Multi-Language Prerequisites

BlueTeamAgent uses a **Two-Tier Capability Architecture**:

| Tier | Status | Dependencies | Capabilities |
| :--- | :--- | :--- | :--- |
| **Tier 1: Pure-Python Standard Library Fallback** | **Active out-of-the-box** | **Zero external dependencies** (Standard Python 3.9+) | AST SAST Engine (Python CWEs), SQLite FTS5 Code Search, Binary Header & Entropy Triage, DAG Mailbox, CVSS v3.1 Calculator. |
| **Tier 2: External Toolchain Acceleration** | **Optional** | External CLI tools installed in system `PATH` | Multi-language SAST (Semgrep), Vector Embedding Search (Semble), Decompilation & Disassembly (Radare2, Ghidra, JADX, CFR, GNU binutils), and Container Isolation (Docker). |

When an external tool is not installed, BlueTeamAgent **automatically falls back** to its pure-Python internal engines without throwing fatal errors.

### Installation Instructions by Tool

#### 1. Multi-Language SAST (`semgrep`)
Enables deep CWE pattern matching across JavaScript, TypeScript, Go, Java, C, and C++.
```bash
# Via pip (All platforms)
pip install semgrep

# macOS (Homebrew)
brew install semgrep

# Windows (Winget / Chocolatey)
winget install semgrep
# or: choco install semgrep

# Linux (Ubuntu/Debian)
pip install semgrep
```

#### 2. Embedding-Based Code Search (`semble`)
Accelerates syntactic AST code search with local model vector embeddings.
```bash
pip install semble
```

#### 3. Reverse Engineering & Binary Decompilers
Used by `mcp_run_diagnostic_tool` to inspect artifacts under strict input sanitization:

- **Radare2 (`r2` / `radare2`)**: Portable reverse engineering framework and command-line disassembler.
  ```bash
  # Windows
  winget install radareorg.radare2
  # or: choco install radare2

  # macOS
  brew install radare2

  # Linux (Ubuntu/Debian)
  sudo apt install radare2
  ```

- **JADX (`jadx`)**: Dex to Java decompiler for Android APK and DEX bytecode inspection.
  ```bash
  # Windows
  choco install jadx
  # or: winget install Skylot.jadx

  # macOS
  brew install jadx

  # Linux (Manual binary release)
  # Download from https://github.com/skylot/jadx/releases and add bin/ to PATH
  ```

- **CFR (`cfr`)**: Modern Java class file decompiler.
  ```bash
  # macOS
  brew install cfr

  # Windows / Linux
  # Download cfr.jar from https://www.benf.org/other/cfr/
  # Place in PATH as an executable script or alias: 'java -jar cfr.jar "$@"'
  ```

- **Ghidra (`ghidra`)**: NSA software reverse engineering framework.
  ```bash
  # Prerequisites: OpenJDK 17+
  # macOS
  brew install --cask ghidra

  # Windows
  choco install ghidra

  # Linux / Manual
  # Download from https://ghidra-sre.org/ and add installation directory to PATH
  ```

- **GNU Binutils (`strings`, `readelf`, `objdump`)**:
  ```bash
  # Linux (Ubuntu/Debian)
  sudo apt install binutils

  # macOS (Included with Xcode Command Line Tools)
  xcode-select --install

  # Windows
  # Available via Git for Windows: 'C:\Program Files\Git\usr\bin' (add to PATH)
  # Or Sysinternals strings: winget install Microsoft.Sysinternals.Strings
  ```

- **Docker (`docker`)**:
  Enables Tier-2 containerized sandbox execution with `--network none`.
  ```bash
  # Install Docker Desktop from https://www.docker.com/products/docker-desktop/
  # Ensure the Docker daemon is running.
  ```

---

## 🌐 Dynamic Sandbox Integration (CAPEv2 / Cuckoo REST API)

BlueTeamAgent includes an integration bridge (`core/cape_adapter.py`) to connect AI agents with external automated malware analysis systems like **CAPEv2** and **Cuckoo Sandbox**.

### How It Works

```
┌─────────────────┐       mcp_submit_dynamic_sandbox       ┌──────────────────────────────┐
│  AI Client /    │ ─────────────────────────────────────► │   BlueTeamAgent MCP Server   │
│  Agent Persona  │ ◄───────────────────────────────────── │     (core/cape_adapter.py)   │
└─────────────────┘             Full JSON Report           └──────────────┬───────────────┘
                                                                          │ POST /api/v2/tasks/create/file/
                                                                          │ GET  /api/v2/tasks/view/{id}/
                                                                          │ GET  /api/v2/tasks/get/report/{id}/
                                                                          ▼
                                                           ┌──────────────────────────────┐
                                                           │  External Isolated Sandbox   │
                                                           │     (CAPEv2 / Cuckoo API)    │
                                                           │  • Windows 10/11 Detonation  │
                                                           │  • C2 Traffic Capture        │
                                                           │  • API & Process Tracing     │
                                                           └──────────────────────────────┘
```

### Configuration

Provide the target sandbox endpoint and optional API token via environment variables:

```bash
# PowerShell (Windows)
$env:CAPE_API_URL = "https://cape.yourorganization.internal"
$env:CAPE_API_KEY = "your-api-token-here"

# Bash (Linux / macOS)
export CAPE_API_URL="https://cape.yourorganization.internal"
export CAPE_API_KEY="your-api-token-here"
```

Or configure directly in your MCP client configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "blue-team-security": {
      "command": "python",
      "args": ["e:/AI/CookieAgent/BlueTeamAgent/server.py", "--stdio"],
      "env": {
        "CAPE_API_URL": "https://cape.yourorganization.internal",
        "CAPE_API_KEY": "your-api-token-here"
      }
    }
  }
}
```

### Fallback Behavior
When `CAPE_API_URL` is not set, `mcp_submit_dynamic_sandbox` returns a structured advisory guiding the user on how to configure the connection, while **pure-Python static triage (`mcp_triage_binary`) remains fully operational**.

---

## 🚀 Quickstart & Usage

### 1. Run Diagnostic Self-Tests & Full Test Suite (123 Tests, 100% Pass)
```powershell
python server.py --test-mode
```

### 2. Launch MCP Server on Stdio (JSON-RPC 2.0)
```powershell
python server.py --stdio
```

### 3. Run Discovered Unit Tests via Unittest
```powershell
python -m unittest discover -s tests -v
```

---

## 📁 Repository Structure

- `server.py`: MCP Protocol Server (JSON-RPC 2.0 Stdio, 9 tools, 6 resources, 6 prompts).
- `core/ast_scanner.py`: Zero-dependency AST SAST engine with import alias tracking, local taint analysis, and Shannon entropy.
- `core/cvss_calculator.py`: FIRST.org standard CVSS v3.1 vector parser & floating-point accurate roundup.
- `core/code_search.py`: Hybrid code search (Syntactic AST Chunking + SQLite FTS5 BM25 + Reciprocal Rank Fusion), reducing context tokens by 98–99%.
- `core/binary_triage.py`: Air-gapped static binary triage (Zero-Execution Policy, magic byte identification, PE section table W^X inspection, 1KB block Shannon entropy, string IOC extraction with hex offsets, SHA-256 evidence chain).
- `core/cape_adapter.py`: Dynamic sandbox REST API client (CAPEv2 / Cuckoo file submission, task polling, C2 extraction, and dropped artifact analysis).
- `core/soc_rules.py`: Pure-Python SOC dynamic detection rule engine (MITRE ATT&CK mappings T1055, T1059.001, T1003, T1071, T1547.001 & incident playbooks).
- `core/tool_indexer.py`: Diagnostic reverse-engineering toolchain indexer & runner (strings, readelf, objdump, cfr, jadx, r2).
- `core/semgrep_adapter.py`: Multi-language SAST adapter (JS/TS, Go, Java, C/C++).
- `core/sandbox_runner.py`: Isolated test execution (argv list, zero `shell=True`, environment whitelist, Windows process tree termination, Docker isolation option).
- `core/guardrails.py`: Safe patching manager enforcing the 4 gates (Diff Cap <= 50, Syntax Pre-flight, Zero-Regression SAST, Single-Committer isolation).
- `core/dag_engine.py`: Multi-agent DAG task scheduler with SQLite WAL shared memory, point-to-point mailbox messaging, Max Hop TTL = 20, and orphaned task recovery.
- `tests/`: 123 automated unit tests verifying all components with 100% pass rate.
- `.agents/`: Project rules (`AGENTS.md`) and architecture genome (`GENOME.md`).
