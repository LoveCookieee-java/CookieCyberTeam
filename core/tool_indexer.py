"""
Dynamic Host Toolchain Indexer.
Discovers static analysis, reverse engineering, sandbox, and network inspection tools
available in PATH without executing arbitrary binary code or triggering AV alerts.
"""

from __future__ import annotations
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


TOOL_REGISTRY: Dict[str, Dict[str, str]] = {
    # Static Analysis & Security Scanning
    "semgrep": {"category": "sast", "description": "Fast multi-language AST pattern scanner"},
    "bandit": {"category": "sast", "description": "Python security flaw static analyzer"},
    "semble": {"category": "sast", "description": "Embedding-based hybrid AST code search CLI"},
    "flake8": {"category": "linting", "description": "Python code style and error checker"},
    "mypy": {"category": "typecheck", "description": "Static type checker for Python"},
    # Reverse Engineering & Binary Inspection
    "radare2": {"category": "reverse_engineering", "description": "Unix-like reverse engineering framework"},
    "r2": {"category": "reverse_engineering", "description": "Radare2 shortcut binary"},
    "ghidra": {"category": "reverse_engineering", "description": "NSA software reverse engineering framework"},
    "cfr": {"category": "reverse_engineering", "description": "Modern Java decompiler CLI"},
    "jadx": {"category": "reverse_engineering", "description": "Dex to Java decompiler"},
    "strings": {"category": "reverse_engineering", "description": "Print printable character sequences in files"},
    "objdump": {"category": "reverse_engineering", "description": "Display information from object files"},
    "readelf": {"category": "reverse_engineering", "description": "Display ELF file header and section structures"},
    "gdb": {"category": "reverse_engineering", "description": "GNU Project debugger"},
    "x64dbg": {"category": "reverse_engineering", "description": "Open source x64/x32 debugger for Windows"},
    "ida64": {"category": "reverse_engineering", "description": "Interactive Disassembler Professional"},
    # Sandbox & Isolation
    "docker": {"category": "sandbox", "description": "Container runtime for Tier-2 isolated sandboxing"},
    "podman": {"category": "sandbox", "description": "Daemonless container engine for sandbox isolation"},
    # Network & Packet Triage
    "tshark": {"category": "network", "description": "Terminal-based Wireshark packet capture analyzer"},
    "tcpdump": {"category": "network", "description": "Command-line packet analyzer"},
    "curl": {"category": "network", "description": "Command line tool for transferring data with URLs"},
    "nmap": {"category": "network", "description": "Network exploration tool and security scanner"},
}


class ToolchainIndexer:
    """Discovers and caches available defensive security and reverse engineering tools on host."""

    def __init__(self, custom_registry: Optional[Dict[str, Dict[str, str]]] = None):
        self.registry = custom_registry or TOOL_REGISTRY
        self._cached_index: Optional[Dict[str, Any]] = None

    def discover(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Probe system PATH for all registered security tools."""
        if self._cached_index is not None and not force_refresh:
            return self._cached_index

        discovered_tools: Dict[str, Dict[str, Any]] = {}
        category_counts: Dict[str, int] = {}
        available_tools: List[str] = []

        for name, meta in self.registry.items():
            cat = meta["category"]
            bin_path = shutil.which(name)
            is_available = bin_path is not None
            
            tool_entry = {
                "name": name,
                "available": is_available,
                "category": cat,
                "description": meta["description"],
                "path": str(Path(bin_path).resolve()) if bin_path else None,
            }
            discovered_tools[name] = tool_entry

            if is_available:
                available_tools.append(name)
                category_counts[cat] = category_counts.get(cat, 0) + 1

        self._cached_index = {
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python_version": sys.version.split()[0],
            },
            "total_tools_scanned": len(self.registry),
            "available_tools_count": len(available_tools),
            "category_summary": category_counts,
            "available_tools": available_tools,
            "tools": discovered_tools,
        }
        return self._cached_index

    def to_markdown(self) -> str:
        """Format index as readable Markdown for MCP Resource `mcp://state/tool-index`."""
        data = self.discover()
        lines = [
            "# Host Defensive & Reverse Engineering Toolchain Index",
            f"**Host Platform:** {data['platform']['system']} {data['platform']['release']} ({data['platform']['machine']})",
            f"**Python Runtime:** {data['platform']['python_version']}",
            f"**Available Tools:** {data['available_tools_count']} / {data['total_tools_scanned']}",
            "",
            "## Category Distribution",
        ]
        for cat, cnt in data["category_summary"].items():
            lines.append(f"- **{cat.upper()}**: {cnt} installed")

        lines.append("")
        lines.append("## Detailed Tool Inventory")
        lines.append("| Tool | Category | Status | Path / Notes |")
        lines.append("| :--- | :--- | :--- | :--- |")

        for name, info in data["tools"].items():
            status = "✅ Installed" if info["available"] else "❌ Missing"
            note = f"`{info['path']}`" if info["path"] else info["description"]
            lines.append(f"| `{name}` | {info['category']} | {status} | {note} |")

        return "\n".join(lines)

    ALLOWED_DIAGNOSTIC_TOOLS = {"strings", "readelf", "objdump", "cfr", "jadx", "r2", "radare2"}

    def run_diagnostic_tool(
        self,
        tool_name: str,
        target_file: str | Path,
        args: Optional[List[str]] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """
        Safely execute diagnostic or reverse engineering tool against a target file.
        Enforces tool whitelisting, argument validation, and execution via SandboxRunner.
        """
        tool_clean = tool_name.lower().strip()
        if tool_clean not in self.ALLOWED_DIAGNOSTIC_TOOLS:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' is not in allowed diagnostic whitelist: {sorted(self.ALLOWED_DIAGNOSTIC_TOOLS)}",
            }

        # Validate arguments: disallow dangerous shell metacharacters first
        sanitized_args: List[str] = []
        if args:
            disallowed_chars = {";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r"}
            for a in args:
                if not isinstance(a, str) or any(c in a for c in disallowed_chars):
                    return {
                        "success": False,
                        "error": f"Argument '{a}' contains forbidden shell metacharacters.",
                    }
                sanitized_args.append(a)

        target_p = Path(target_file).resolve()
        if not target_p.is_file():
            return {
                "success": False,
                "error": f"Target file not found: {target_p}",
            }

        bin_path = shutil.which(tool_clean)
        if not bin_path:
            return {
                "success": False,
                "error": f"Diagnostic tool '{tool_clean}' is not installed or not found in system PATH.",
            }

        argv = [bin_path, *sanitized_args, str(target_p)]

        from core.sandbox_runner import SandboxRunner
        runner = SandboxRunner(default_timeout=timeout)
        run_res = runner.run_command(argv, cwd=target_p.parent, timeout=timeout)

        return {
            "success": run_res.get("exit_code") == 0,
            "tool_name": tool_clean,
            "target_file": str(target_p),
            "argv": argv,
            "stdout": run_res.get("stdout", ""),
            "stderr": run_res.get("stderr", ""),
            "exit_code": run_res.get("exit_code", -1),
            "timed_out": run_res.get("timed_out", False),
            "duration_ms": run_res.get("duration_ms", 0),
            "duration_sec": round(run_res.get("duration_ms", 0) / 1000.0, 4),
        }
