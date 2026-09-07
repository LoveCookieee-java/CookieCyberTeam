"""
Blue Team Repository Configuration Engine.
Loads repository-level settings from `.blueteam.toml` or `blueteam.json`.
Zero external dependencies (supports Python stdlib tomllib / tomli or pure-Python fallback).
"""

from __future__ import annotations
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union


DEFAULT_DIFF_CAP_LIMIT = 50
DEFAULT_NEW_FILE_CAP_LIMIT = 250
DEFAULT_RESTRICTED_BRANCHES = {"main", "master", "prod", "production", "release"}
DEFAULT_EXCLUDE_DIRS = {"vendor", "node_modules", ".git", "dist", "build", "__pycache__"}
DEFAULT_SHANNON_ENTROPY_THRESHOLD = 7.5
DEFAULT_CVSS_VERSION = "3.1"


def _strip_toml_comment(s: str) -> str:
    """Strip trailing comment (#) from TOML string outside quotes."""
    in_quote = None
    escaped = False
    for i, ch in enumerate(s):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_quote:
            if ch == in_quote:
                in_quote = None
        else:
            if ch in ('"', "'"):
                in_quote = ch
            elif ch == "#":
                return s[:i].strip()
    return s.strip()


def _bracket_balance(s: str) -> int:
    """Return net bracket depth [ vs ] outside string quotes."""
    bal = 0
    in_q = None
    esc = False
    for ch in s:
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if in_q:
            if ch == in_q:
                in_q = None
        elif ch in ('"', "'"):
            in_q = ch
        elif ch == "[":
            bal += 1
        elif ch == "]":
            bal -= 1
    return bal


def _parse_simple_toml(text: str) -> Dict[str, Any]:
    """
    Lightweight, pure-Python TOML parser for basic key-value pairs, arrays, and tables.
    Used as a zero-dependency fallback when neither tomllib nor tomli is installed.
    """
    result: Dict[str, Any] = {}
    current_table = result

    lines = text.splitlines()
    i = 0
    n = len(lines)

    while i < n:
        raw_line = lines[i]
        line = raw_line.strip()
        if not line or line.startswith("#"):
            i += 1
            continue

        # Table header: [section] or [section.subsection]
        if line.startswith("[") and line.endswith("]"):
            section_name = line[1:-1].strip()
            parts = section_name.split(".")
            curr = result
            for p in parts:
                if p not in curr or not isinstance(curr[p], dict):
                    curr[p] = {}
                curr = curr[p]
            current_table = curr
            i += 1
            continue

        if "=" in line:
            key, val_str = line.split("=", 1)
            key = key.strip()
            val_str = _strip_toml_comment(val_str)

            # Buffer multi-line arrays
            bal = _bracket_balance(val_str)
            while bal > 0 and i + 1 < n:
                i += 1
                next_line = _strip_toml_comment(lines[i].strip())
                if next_line:
                    val_str += " " + next_line
                    bal += _bracket_balance(next_line)

            val = _parse_toml_value(val_str)
            current_table[key] = val

        i += 1

    return result


def _parse_toml_value(val_str: str) -> Any:
    """Parse a single TOML value string into Python primitive."""
    val_str = val_str.strip()
    if not val_str:
        return ""

    # Strings
    if (val_str.startswith('"') and val_str.endswith('"')) or (val_str.startswith("'") and val_str.endswith("'")):
        return val_str[1:-1]

    # Booleans
    if val_str.lower() == "true":
        return True
    if val_str.lower() == "false":
        return False

    # Arrays: [ ... ]
    if val_str.startswith("[") and val_str.endswith("]"):
        inner = val_str[1:-1].strip()
        if not inner:
            return []
        items = []
        current_item: List[str] = []
        in_quote = None
        escaped = False
        bracket_depth = 0
        for ch in inner:
            if escaped:
                current_item.append(ch)
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                current_item.append(ch)
                continue
            if in_quote:
                current_item.append(ch)
                if ch == in_quote:
                    in_quote = None
            else:
                if ch in ('"', "'"):
                    in_quote = ch
                    current_item.append(ch)
                elif ch == "[":
                    bracket_depth += 1
                    current_item.append(ch)
                elif ch == "]":
                    bracket_depth -= 1
                    current_item.append(ch)
                elif ch == "," and bracket_depth == 0:
                    item_str = "".join(current_item).strip()
                    if item_str:
                        items.append(_parse_toml_value(item_str))
                    current_item = []
                else:
                    current_item.append(ch)
        last_str = "".join(current_item).strip()
        if last_str:
            items.append(_parse_toml_value(last_str))
        return items

    # Integers
    try:
        return int(val_str)
    except ValueError:
        pass

    # Floats
    try:
        return float(val_str)
    except ValueError:
        pass

    return val_str


@dataclass
class BlueTeamConfig:
    """Repository configuration model with defaults and file persistence."""
    diff_cap_limit: int = DEFAULT_DIFF_CAP_LIMIT
    new_file_cap_limit: int = DEFAULT_NEW_FILE_CAP_LIMIT
    restricted_branches: Set[str] = field(default_factory=lambda: set(DEFAULT_RESTRICTED_BRANCHES))
    exclude_dirs: Set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))
    shannon_entropy_threshold: float = DEFAULT_SHANNON_ENTROPY_THRESHOLD
    cvss_version: str = DEFAULT_CVSS_VERSION
    config_source: Optional[str] = None

    def __post_init__(self):
        # Normalize and validate types
        self.diff_cap_limit = max(1, int(self.diff_cap_limit))
        self.new_file_cap_limit = max(1, int(self.new_file_cap_limit))
        self.shannon_entropy_threshold = max(0.0, min(8.0, float(self.shannon_entropy_threshold)))
        cvss_v = str(self.cvss_version).strip()
        self.cvss_version = cvss_v if cvss_v in ("3.0", "3.1", "4.0") else DEFAULT_CVSS_VERSION
        if isinstance(self.restricted_branches, (list, tuple)):
            self.restricted_branches = {str(b).strip().lower() for b in self.restricted_branches}
        else:
            self.restricted_branches = {str(b).strip().lower() for b in self.restricted_branches}
        if isinstance(self.exclude_dirs, (list, tuple)):
            self.exclude_dirs = {str(d).strip() for d in self.exclude_dirs}
        else:
            self.exclude_dirs = {str(d).strip() for d in self.exclude_dirs}

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "diff_cap_limit": self.diff_cap_limit,
            "new_file_cap_limit": self.new_file_cap_limit,
            "restricted_branches": sorted(list(self.restricted_branches)),
            "exclude_dirs": sorted(list(self.exclude_dirs)),
            "shannon_entropy_threshold": self.shannon_entropy_threshold,
            "cvss_version": self.cvss_version,
            "config_source": self.config_source,
        }

    @classmethod
    def load_from_dict(cls, data: Dict[str, Any], source: Optional[str] = None) -> BlueTeamConfig:
        """Create a BlueTeamConfig instance from dictionary data."""
        config_data = dict(data)
        # Flatten nested sections like [blueteam], [guardrails], or [tool.blueteam]
        if "blueteam" in config_data and isinstance(config_data["blueteam"], dict):
            for k, v in config_data["blueteam"].items():
                config_data.setdefault(k, v)
        if "guardrails" in config_data and isinstance(config_data["guardrails"], dict):
            for k, v in config_data["guardrails"].items():
                config_data.setdefault(k, v)
        if "tool" in config_data and isinstance(config_data["tool"], dict):
            tool_dict = config_data["tool"]
            if "blueteam" in tool_dict and isinstance(tool_dict["blueteam"], dict):
                for k, v in tool_dict["blueteam"].items():
                    config_data.setdefault(k, v)

        return cls(
            diff_cap_limit=config_data.get("diff_cap_limit", DEFAULT_DIFF_CAP_LIMIT),
            new_file_cap_limit=config_data.get("new_file_cap_limit", DEFAULT_NEW_FILE_CAP_LIMIT),
            restricted_branches=config_data.get("restricted_branches", set(DEFAULT_RESTRICTED_BRANCHES)),
            exclude_dirs=config_data.get("exclude_dirs", set(DEFAULT_EXCLUDE_DIRS)),
            shannon_entropy_threshold=config_data.get("shannon_entropy_threshold", DEFAULT_SHANNON_ENTROPY_THRESHOLD),
            cvss_version=config_data.get("cvss_version", DEFAULT_CVSS_VERSION),
            config_source=source,
        )

    @classmethod
    def load_from_file(cls, file_path: Union[str, Path]) -> BlueTeamConfig:
        """Load configuration from a TOML or JSON file."""
        p = Path(file_path).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Configuration file not found: {p}")

        content = p.read_text(encoding="utf-8", errors="replace")
        suffix = p.suffix.lower()

        if suffix == ".json":
            data = json.loads(content)
        elif suffix in (".toml", "") or p.name.endswith(".toml"):
            try:
                import tomllib
                data = tomllib.loads(content)
            except ImportError:
                try:
                    import tomli as tomllib
                    data = tomllib.loads(content)
                except ImportError:
                    data = _parse_simple_toml(content)
        else:
            # Try JSON first, then TOML
            try:
                data = json.loads(content)
            except Exception:
                data = _parse_simple_toml(content)

        return cls.load_from_dict(data, source=str(p))

    @classmethod
    def load_from_repo(cls, repo_path: Optional[Union[str, Path]] = None) -> BlueTeamConfig:
        """
        Discover and load `.blueteam.toml` or `blueteam.json` starting at repo_path.
        If not found, searches parent directories until filesystem root.
        If no configuration file is located, returns default BlueTeamConfig.
        """
        start = Path(repo_path).resolve() if repo_path else Path.cwd().resolve()
        if start.is_file():
            start = start.parent
        candidates = [start, *start.parents]

        for directory in candidates:
            # Check for .blueteam.toml
            toml_path = directory / ".blueteam.toml"
            if toml_path.is_file():
                return cls.load_from_file(toml_path)

            alt_toml = directory / "blueteam.toml"
            if alt_toml.is_file():
                return cls.load_from_file(alt_toml)

            # Check for blueteam.json
            json_path = directory / "blueteam.json"
            if json_path.is_file():
                return cls.load_from_file(json_path)

            alt_json = directory / ".blueteam.json"
            if alt_json.is_file():
                return cls.load_from_file(alt_json)

            # Stop at git boundary if reached
            if (directory / ".git").exists():
                break

        return cls()
