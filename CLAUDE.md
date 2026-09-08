# CookieCyberTeam Guidelines for Claude Code

This repository contains the Single Unified Intelligent MCP Server & 5-Gate Defensive Cyber Guardrails for AI Coding Agents.

When analyzing or modifying code in this repository:
1. **Gate 1.5 Ponytail Minimalism**: Strictly prioritize Python standard library (`ast`, `sqlite3`, `subprocess`, `graphlib`, `difflib`, `re`, `hashlib`). Do NOT introduce speculative third-party runtime dependencies.
2. **Gate 2 Diff Cap**: Ensure modifications to existing files remain surgical and under 50 lines. New modules/fixtures under 250 lines.
3. **Gate 4 Absolute Zero-Deletion Invariant**: Never execute destructive file deletion primitives (`rm`, `del`, `unlink`, `shutil.rmtree`, `os.remove`). Use quarantine vault logic (`core/containment.py`) with XOR byte scramble and `os.replace`.
4. **Inter-Procedural SAST Verification**: All fixes must maintain zero new CWE findings across 17 vulnerability categories.
5. **Continuous Verification Loop**: Always run self-diagnostics before committing:
   - `python server.py --test-mode`
   - `python -m unittest discover -s tests -v`
