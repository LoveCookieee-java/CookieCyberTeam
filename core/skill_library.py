"""
Agent Skills (``SKILL.md``) Knowledge Library.

Ingests structured security knowledge authored in the open ``agentskills.io``
Agent Skills format -- a directory containing a ``SKILL.md`` file with YAML
frontmatter (``name``, ``description``, ``license``, ``compatibility``,
``metadata``, ``allowed-tools``) followed by Markdown instructions.

This module is *data-only*: it parses, validates, indexes, and searches skill
metadata. It never executes skill scripts, never fetches from the network, and
holds no offensive capability. Framework tags (MITRE ATT&CK, NIST CSF 2.0,
MITRE ATLAS, MITRE D3FEND, NIST AI RMF, MITRE F3) are extracted so a skill can
be correlated with the technique and detection catalogs.

The frontmatter parser is a deliberately small YAML subset written against the
standard library only -- the same approach the project already takes for TOML in
``core/config.py`` -- to preserve the zero-dependency guarantee.

Zero external dependencies (Python stdlib only).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

#: Skill directory/file conventions.
SKILL_FILENAME = "SKILL.md"

#: ``agentskills.io`` name rule: lowercase alphanumerics and single hyphens.
SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

MAX_NAME_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 1024
MAX_COMPATIBILITY_LENGTH = 500

#: Frontmatter keys mapped to their human-readable framework label.
FRAMEWORK_KEYS: Dict[str, str] = {
    "mitre_attack": "MITRE ATT&CK",
    "nist_csf": "NIST CSF 2.0",
    "mitre_atlas": "MITRE ATLAS",
    "mitre_d3fend": "MITRE D3FEND",
    "nist_ai_rmf": "NIST AI RMF",
    "mitre_f3": "MITRE F3 (Fight Fraud)",
}

#: Reference taxonomy of the security domains the upstream corpus spans. Used
#: for domain suggestions and coverage reporting; not a hard allow-list.
DOMAIN_TAXONOMY: List[str] = [
    "ai-security", "application-security", "binary-analysis", "cloud-security",
    "compliance-and-governance", "container-security", "cryptography",
    "data-security", "detection-engineering", "devsecops", "dfir",
    "endpoint-security", "exploit-development", "forensics", "fraud-prevention",
    "identity-and-access", "incident-response", "iot-and-ot-security",
    "malware-analysis", "mobile-security", "network-security", "osint",
    "penetration-testing", "privacy-engineering", "reverse-engineering",
    "risk-management", "secure-architecture", "security-awareness",
    "software-supply-chain", "threat-hunting", "threat-intelligence",
    "vulnerability-management", "web-security", "zero-trust",
]

_FRONTMATTER_DELIM = "---"
_BLOCK_SCALAR_MARKERS = (">", "|", ">-", "|-", ">+", "|+")


# ---------------------------------------------------------------------------
# YAML-subset frontmatter parser
# ---------------------------------------------------------------------------


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("\"", "'"):
        return value[1:-1]
    return value


def _split_inline_list(inner: str) -> List[Any]:
    items: List[Any] = []
    current: List[str] = []
    quote: Optional[str] = None
    escaped = False
    for ch in inner:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            current.append(ch)
            continue
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("\"", "'"):
            quote = ch
            current.append(ch)
        elif ch == ",":
            token = "".join(current).strip()
            if token:
                items.append(_parse_scalar(token))
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        items.append(_parse_scalar(tail))
    return items


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value.startswith("[") and value.endswith("]"):
        return _split_inline_list(value[1:-1])
    if value[0] in ("\"", "'"):
        return _strip_quotes(value)
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    if value.lower() in ("null", "~"):
        return None
    return value


def _next_significant(lines: List[str], start: int) -> Optional[Tuple[int, int]]:
    """Return (index, indent) of the next non-blank, non-comment line."""
    for idx in range(start, len(lines)):
        stripped = lines[idx].strip()
        if stripped and not stripped.startswith("#"):
            return idx, _indent_of(lines[idx])
    return None


def _parse_block(lines: List[str], start: int, indent: int) -> Tuple[Any, int]:
    """
    Parse a same-or-greater-indent block into a dict (mapping) or list (sequence).

    Returns the parsed value and the index of the first line not consumed.
    """
    mapping: Dict[str, Any] = {}
    sequence: List[Any] = []
    is_sequence: Optional[bool] = None
    i = start
    n = len(lines)

    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        current_indent = _indent_of(raw)
        if current_indent < indent:
            break

        if stripped.startswith("- "):
            if is_sequence is False:
                break
            is_sequence = True
            sequence.append(_parse_scalar(stripped[2:].strip()))
            i += 1
            continue

        if ":" not in stripped:
            i += 1
            continue

        if is_sequence is True:
            break
        is_sequence = False

        key, _, rest = stripped.partition(":")
        key = key.strip()
        rest = rest.strip()

        if rest == "":
            nxt = _next_significant(lines, i + 1)
            if nxt is not None and nxt[1] > current_indent:
                child, i = _parse_block(lines, i + 1, nxt[1])
                mapping[key] = child
            elif nxt is not None and nxt[1] == current_indent and lines[nxt[0]].strip().startswith("- "):
                child, i = _parse_block(lines, nxt[0], nxt[1])
                mapping[key] = child
            else:
                mapping[key] = None
                i += 1
            continue

        if rest in _BLOCK_SCALAR_MARKERS:
            buffer: List[str] = []
            j = i + 1
            while j < n:
                if lines[j].strip() and _indent_of(lines[j]) <= current_indent:
                    break
                buffer.append(lines[j].strip())
                j += 1
            joiner = "\n" if rest.startswith("|") else " "
            mapping[key] = joiner.join(part for part in buffer if part)
            i = j
            continue

        mapping[key] = _parse_scalar(rest)
        i += 1

    if is_sequence:
        return sequence, i
    return mapping, i


def split_frontmatter(text: str) -> Tuple[Optional[str], str, str]:
    """
    Split a ``SKILL.md`` document into (frontmatter, body, error).

    ``frontmatter`` is ``None`` and ``error`` non-empty when the document does
    not open with a well-formed ``---`` fenced block.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or lines[i].strip().lstrip("\ufeff") != _FRONTMATTER_DELIM:
        return None, text, "missing YAML frontmatter block"
    start = i + 1
    j = start
    while j < len(lines) and lines[j].strip() != _FRONTMATTER_DELIM:
        j += 1
    if j >= len(lines):
        return None, text, "unterminated YAML frontmatter block"
    return "\n".join(lines[start:j]), "\n".join(lines[j + 1:]), ""


def parse_frontmatter(frontmatter: str) -> Dict[str, Any]:
    """Parse a frontmatter block into a dictionary (YAML subset)."""
    value, _ = _parse_block(frontmatter.split("\n"), 0, 0)
    if isinstance(value, dict):
        return value
    return {}


# ---------------------------------------------------------------------------
# Skill record + validation
# ---------------------------------------------------------------------------


@dataclass
class SkillRecord:
    """A single parsed ``SKILL.md`` skill."""

    name: str
    description: str
    path: str = ""
    domain: str = ""
    license: str = ""
    compatibility: str = ""
    allowed_tools: List[str] = field(default_factory=list)
    frameworks: Dict[str, List[str]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    body_lines: int = 0
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "path": self.path,
            "domain": self.domain,
            "license": self.license,
            "compatibility": self.compatibility,
            "allowed_tools": list(self.allowed_tools),
            "frameworks": {k: list(v) for k, v in self.frameworks.items()},
            "metadata": dict(self.metadata),
            "body_lines": self.body_lines,
            "valid": not self.issues,
            "issues": list(self.issues),
        }


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if str(v).strip()]
    text = str(value).strip()
    if not text:
        return []
    return [part for part in re.split(r"[,\s]+", text) if part]


def _extract_frameworks(data: Dict[str, Any]) -> Dict[str, List[str]]:
    """Collect framework tag lists from top-level keys and the metadata map."""
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    frameworks: Dict[str, List[str]] = {}
    for key in FRAMEWORK_KEYS:
        values = _as_list(data.get(key))
        if not values:
            values = _as_list(metadata.get(key))
        if values:
            frameworks[FRAMEWORK_KEYS[key]] = sorted(set(values))
    return frameworks


def validate_skill(name: str, description: str, directory_name: str = "",
                   compatibility: str = "") -> List[str]:
    """Validate a skill against the ``agentskills.io`` frontmatter rules."""
    issues: List[str] = []
    if not name:
        issues.append("missing required 'name' field")
    else:
        if len(name) > MAX_NAME_LENGTH:
            issues.append(f"name exceeds {MAX_NAME_LENGTH} characters")
        if not SKILL_NAME_RE.match(name):
            issues.append("name must be lowercase alphanumerics separated by single hyphens")
        if directory_name and name != directory_name:
            issues.append(f"name '{name}' does not match parent directory '{directory_name}'")
    if not description:
        issues.append("missing required 'description' field")
    elif len(description) > MAX_DESCRIPTION_LENGTH:
        issues.append(f"description exceeds {MAX_DESCRIPTION_LENGTH} characters")
    if compatibility and len(compatibility) > MAX_COMPATIBILITY_LENGTH:
        issues.append(f"compatibility exceeds {MAX_COMPATIBILITY_LENGTH} characters")
    return issues


def parse_skill_text(text: str, path: str = "", directory_name: str = "") -> SkillRecord:
    """Parse a single ``SKILL.md`` document into a :class:`SkillRecord`."""
    frontmatter, body, error = split_frontmatter(text)
    if frontmatter is None:
        return SkillRecord(name="", description="", path=path, issues=[error])
    data = parse_frontmatter(frontmatter)
    name = str(data.get("name") or "").strip()
    description = str(data.get("description") or "").strip()
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    domain = str(data.get("domain") or metadata.get("domain") or "").strip()
    compatibility = str(data.get("compatibility") or "").strip()
    record = SkillRecord(
        name=name,
        description=description,
        path=path,
        domain=domain,
        license=str(data.get("license") or "").strip(),
        compatibility=compatibility,
        allowed_tools=_as_list(data.get("allowed-tools")),
        frameworks=_extract_frameworks(data),
        metadata={str(k): v for k, v in metadata.items()},
        body_lines=len([ln for ln in body.split("\n") if ln.strip()]),
    )
    record.issues = validate_skill(name, description, directory_name or "", compatibility)
    return record


def parse_skill_file(path: Union[str, Path]) -> SkillRecord:
    """Read and parse a ``SKILL.md`` file from disk."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return SkillRecord(name="", description="", path=str(p), issues=[f"unreadable: {exc}"])
    return parse_skill_text(text, path=str(p), directory_name=p.parent.name)


# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------


class SkillLibrary:
    """
    An indexable collection of :class:`SkillRecord` objects.

    The library is deliberately offline: it is populated either from parsed
    records or by walking a local clone of a skills repository.
    """

    def __init__(self, records: Optional[Iterable[SkillRecord]] = None, source: str = ""):
        self.records: List[SkillRecord] = list(records or [])
        self.source = source

    # -- construction --------------------------------------------------------

    @classmethod
    def from_dicts(cls, items: Iterable[Dict[str, Any]], source: str = "") -> "SkillLibrary":
        records: List[SkillRecord] = []
        for item in items:
            name = str(item.get("name") or "")
            description = str(item.get("description") or "")
            compatibility = str(item.get("compatibility") or "")
            rec = SkillRecord(
                name=name,
                description=description,
                path=str(item.get("path") or ""),
                domain=str(item.get("domain") or ""),
                license=str(item.get("license") or ""),
                compatibility=compatibility,
                allowed_tools=_as_list(item.get("allowed_tools")),
                frameworks={str(k): _as_list(v) for k, v in (item.get("frameworks") or {}).items()},
                metadata=dict(item.get("metadata") or {}),
                body_lines=int(item.get("body_lines") or 0),
            )
            rec.issues = validate_skill(name, description, "", compatibility)
            records.append(rec)
        return cls(records, source=source)

    @classmethod
    def load(
        cls,
        root: Union[str, Path],
        max_skills: int = 2000,
        exclude_dirs: Optional[Iterable[str]] = None,
    ) -> "SkillLibrary":
        """
        Walk ``root`` for ``SKILL.md`` files and load them into a library.

        Never raises on unreadable files: a failure becomes an invalid record
        carrying an ``issues`` note. Bounded by ``max_skills`` to keep memory
        predictable on very large clones.
        """
        base = Path(root)
        records: List[SkillRecord] = []
        if not base.exists():
            return cls(records, source=str(base))
        excluded = {str(d).lower() for d in (exclude_dirs or
                    {"node_modules", ".git", "dist", "build", "__pycache__", "vendor"})}
        for dirpath, dirnames, filenames in _walk(base, excluded):
            for fname in filenames:
                if fname.lower() != SKILL_FILENAME.lower():
                    continue
                if len(records) >= max_skills:
                    return cls(records, source=str(base))
                records.append(parse_skill_file(Path(dirpath) / fname))
        records.sort(key=lambda r: r.name)
        return cls(records, source=str(base))

    # -- queries -------------------------------------------------------------

    def search(
        self,
        query: Optional[str] = None,
        framework: Optional[str] = None,
        domain: Optional[str] = None,
        top_k: int = 10,
        include_invalid: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Rank skills by keyword relevance over name/description/body keywords.

        Filters are conjunctive: ``framework`` matches a framework label or a
        technique id inside any framework tag list, and ``domain`` matches the
        (normalised) domain.
        """
        terms = [t for t in re.split(r"[^a-z0-9_.\-]+", (query or "").lower()) if t]
        fw = (framework or "").strip().lower()
        dom = (domain or "").strip().lower()
        scored: List[Tuple[float, SkillRecord]] = []

        for rec in self.records:
            if rec.issues and not include_invalid:
                continue
            if dom and dom not in rec.domain.lower():
                continue
            if fw:
                flat = [rec.domain.lower()] + [
                    str(v).lower() for vals in rec.frameworks.values() for v in vals
                ] + [k.lower() for k in rec.frameworks]
                if not any(fw in item or item in fw for item in flat):
                    continue
            if terms:
                haystack_name = rec.name.lower()
                haystack_desc = rec.description.lower()
                score = 0.0
                for term in terms:
                    if term in haystack_name:
                        score += 3.0
                    if term in haystack_desc:
                        score += 2.0
                    if term in rec.domain.lower() or term in rec.path.lower():
                        score += 1.0
                if score <= 0:
                    continue
            else:
                score = 1.0
            scored.append((score, rec))

        scored.sort(key=lambda pair: (-pair[0], pair[1].name))
        return [rec.to_dict() for _, rec in scored[: max(1, top_k)]]

    def list_domains(self) -> List[str]:
        """Return the sorted set of domains present in the library."""
        return sorted({rec.domain for rec in self.records if rec.domain})

    def stats(self) -> Dict[str, Any]:
        """Return summary statistics over the library."""
        total = len(self.records)
        valid = sum(1 for r in self.records if not r.issues)
        framework_counts: Dict[str, int] = {}
        for rec in self.records:
            for label in rec.frameworks:
                framework_counts[label] = framework_counts.get(label, 0) + 1
        domain_counts: Dict[str, int] = {}
        for rec in self.records:
            if rec.domain:
                domain_counts[rec.domain] = domain_counts.get(rec.domain, 0) + 1
        return {
            "source": self.source,
            "total_skills": total,
            "valid_skills": valid,
            "invalid_skills": total - valid,
            "domains": self.list_domains(),
            "domain_counts": domain_counts,
            "framework_counts": framework_counts,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stats": self.stats(),
            "skills": [rec.to_dict() for rec in self.records],
        }


def _walk(base: Path, excluded: Iterable[str]):
    """Yield (dirpath, dirnames, filenames) skipping excluded directories."""
    import os

    excluded_lower = {str(d).lower() for d in excluded}
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames
                       if d.lower() not in excluded_lower and not d.startswith(".")]
        yield dirpath, dirnames, filenames


def load_skills(root: Union[str, Path], max_skills: int = 2000) -> SkillLibrary:
    """Convenience wrapper around :meth:`SkillLibrary.load`."""
    return SkillLibrary.load(root, max_skills=max_skills)


__all__ = [
    "DOMAIN_TAXONOMY",
    "FRAMEWORK_KEYS",
    "SKILL_FILENAME",
    "SKILL_NAME_RE",
    "SkillLibrary",
    "SkillRecord",
    "load_skills",
    "parse_frontmatter",
    "parse_skill_file",
    "parse_skill_text",
    "split_frontmatter",
    "validate_skill",
]
