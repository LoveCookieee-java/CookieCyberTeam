# External Intelligence Provenance

CookieCyberTeam derives **defensive knowledge only** from prior public security
research. No offensive code, exploit, or live malware sample is vendored into
this repository. Everything extracted is either a descriptive signature, a
knowledge structure, a validation heuristic, or a data schema.

## Sources and what was taken

| Source | License posture | What CookieCyberTeam uses |
| :--- | :--- | :--- |
| Ignitetechnologies/Mindmap | Public mindmap collection (reference) | ATT&CK tactic ordering and kill-chain methodology reflected in `core/technique_catalog.py` and `core/attack_path.py`. |
| Whitecat18 / smukx `Rust-for-Malware-Development` (mirrors exist) | Offensive reference (reference only) | **Data-only** technique primitives (API/string combinations) converted into defensive detection signatures in `core/technique_catalog.py`. No Rust source is copied. |
| Awarexone/Agentic-Bug-Hunter | Public toolkit (reference) | The *concept* of a 7-question finding-validation gate (`core/finding_validator.py`), a bounded JSONL hunt memory with rotation (`core/finding_memory.py`), bug-chaining, and bug-bounty report templates (`core/report_export.py`). Independent reimplementation. |
| Kritt-ai/open-kritt | AGPL-3.0 (reference only) | The *concept* of focused task decomposition, de-duplication, severity ranking, and a canonical finding schema/bundle (`core/scan_planner.py`, `core/finding_memory.py`, `core/report_export.py`). No code copied. |
| GreyDGL/PentestGPT | MIT (reference) | The *concept* of a Pentesting Task Tree with reasoning/generation/parsing roles and session persistence (`core/attack_path.py`). Independent reimplementation. |
| darama22/Malware-Research-Hub | Research archive (reference only) | Malware **family metadata** (names, aliases, categories, ATT&CK mappings, descriptive markers) and the *concept* of fuzzy hashing + STIX/MAEC export (`core/malware_intel.py`). **No samples are included**; hashing algorithms are original implementations. |
| METATRON | Reference | The *concept* of an offline exposure-to-remediation advisory (`core/remediation_advisor.py`). |
| mukul975/Anthropic-Cybersecurity-Skills | Apache-2.0 (data, attributed) | The `SKILL.md` schema, the security-domain taxonomy, and the six-framework mapping *structure* (`core/skill_library.py`, `core/framework_catalog.py`). No skill scripts are vendored or executed. |
| agentskills.io Agent Skills specification | Open specification (reference) | Frontmatter field rules (name regex, description bounds, `allowed-tools`, progressive disclosure) used for skill validation (`core/skill_library.py`). |
| MITRE ATT&CK v19.1, D3FEND v1.4.0, ATLAS 2026.07, NIST CSF 2.0, NIST AI RMF 1.0, MITRE F3 v1.1 | Public framework metadata (data) | Tactic, technique, countermeasure, and function identifiers, including the ATT&CK v19.1 Stealth / Defense Impairment split and the F3 Positioning / Monetization tactics (`core/framework_catalog.py`, `core/technique_catalog.py`). |
| OWASP Top 10 for Agentic Applications 2026 | Public framework (reference) | The `ASI-0X` agentic threat-class scheme and its defensive controls, adapted into the project's own taxonomy (`core/agent_surface.py`, `core/soc_rules.py`). |
| luckyPipewrench/pipelock | Reference only | The *concept* of mediated egress inspection and tamper-evident, mediator-signed action receipts (`core/agent_surface.py`). No code copied; nothing is routed or proxied. |
| cynative/cynative | Reference only | The *concept* of markdown-defined, read-only agent roles, reflected in the extended DAG agent-role set (`core/dag_engine.py`). |
| SigmaHQ/sigma | Reference only | Detection rule *patterns* that inform SOC rule generation (`core/soc_rules.py`). No upstream rules are vendored. |
| usestrix/strix | Offensive toolkit (reference only) | The *concept* of proof-backed finding validation, reimplemented defensively as reproducible-evidence assessment (`core/finding_validator.py`). **No exploitation, scanner, or offensive code is included.** |
| x64dbg/x64dbg | GPL-3.0 (reference only) | Static reverse-engineering *heuristics* (deep PE structure, implant markers) and a gated non-interactive debugger entry in the diagnostic whitelist (`core/binary_triage.py`, `core/tool_indexer.py`). No source is copied. |

## Explicit exclusions

- No malware binaries, loaders, shellcode, or source code from any offensive repository.
- No exploitation or attack-orchestration capabilities.
- No network scanning, no target interaction, no live detonation.
- No LLM dependency: all reasoning is deterministic and runs on the standard library only.
- No skill, plugin, or MCP script from any ingested source is ever executed: the skill library parses and indexes `SKILL.md` metadata only.
- GUI-capable debuggers are never launched interactively; they are refused unless an explicit non-interactive acknowledgement is supplied.

## Reporting

Suspected provenance or licensing issues should be raised privately before any
redistribution of derived signature data.
