"""
Persistent Finding Memory & Dedup/Ranking Engine.

A lightweight JSONL store that lets repeated scans build on each other:
findings are fingerprinted, de-duplicated, ranked, remembered across sessions,
and can be dismissed so already-triaged noise does not resurface.

Also provides multi-step *chain* detection: several low-severity findings in the
same file that compose into a higher-impact attack path are surfaced together.

Zero external dependencies (Python stdlib only). Respects the zero-deletion
invariant: rotation only ever uses ``os.replace`` (never ``unlink``).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from core.finding_validator import fingerprint_finding, _as_dict  # noqa: F401


DEFAULT_MEMORY_PATH = Path(".cookiegli/finding_memory.jsonl")
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BACKUPS = 3

#: Ordered severity weights for ranking.
SEVERITY_WEIGHT = {"Critical": 4.0, "High": 3.0, "Medium": 2.0, "Low": 1.0, "Info": 0.0}

#: Findings that compose into a higher-impact chain when co-located.
CHAIN_RECIPES: List[Dict[str, Any]] = [
    {
        "id": "CHAIN-LFI-RCE",
        "requires": ["CWE-22", "CWE-78"],
        "title": "Path Traversal escalating to Command Execution",
        "impact": "Critical",
        "narrative": "A traversal sink can read a controllable path whose content is later executed.",
    },
    {
        "id": "CHAIN-SQLI-AUTH",
        "requires": ["CWE-89", "CWE-352"],
        "title": "SQL Injection reachable through a CSRF-exposed action",
        "impact": "High",
        "narrative": "A state-changing, CSRF-exempt route reaches a SQL sink.",
    },
    {
        "id": "CHAIN-DESERIALIZE-RCE",
        "requires": ["CWE-502", "CWE-78"],
        "title": "Insecure Deserialization reaching a Command Sink",
        "impact": "Critical",
        "narrative": "Attacker-controlled serialized data can drive a command sink.",
    },
    {
        "id": "CHAIN-XSS-SESSION",
        "requires": ["CWE-79", "CWE-352"],
        "title": "Stored XSS against a state-changing endpoint",
        "impact": "High",
        "narrative": "Stored script content can act on behalf of an authenticated user.",
    },
    {
        "id": "CHAIN-SSRF-CLOUD",
        "requires": ["CWE-918"],
        "title": "SSRF with potential cloud metadata access",
        "impact": "High",
        "narrative": "An SSRF sink can reach internal endpoints and metadata services.",
    },
]


class FindingMemory:
    """Append-only JSONL finding memory with rotation, dedup, and dismissal."""

    def __init__(
        self,
        path: Optional[Union[str, Path]] = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backups: int = DEFAULT_BACKUPS,
    ):
        self.path = Path(path) if path else DEFAULT_MEMORY_PATH
        self.max_bytes = max_bytes
        self.backups = max(1, backups)

    # -- persistence ----------------------------------------------------------

    def _ensure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def rotate_if_needed(self) -> bool:
        """Rotate the log when it exceeds ``max_bytes``; returns True if rotated."""
        if not self.path.is_file() or self.path.stat().st_size <= self.max_bytes:
            return False
        # Shift backups: .N-1 -> .N (oldest overwritten via replace, never deleted).
        for idx in range(self.backups, 0, -1):
            src = self.path.with_suffix(self.path.suffix + f".{idx - 1}") if idx > 1 else self.path
            dst = self.path.with_suffix(self.path.suffix + f".{idx}")
            if src.is_file():
                os.replace(src, dst)
        return True

    def _read_lines(self, include_backups: bool = False) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        sources: List[Path] = []
        if include_backups:
            for idx in range(self.backups, 0, -1):
                sources.append(self.path.with_suffix(self.path.suffix + f".{idx}"))
        sources.append(self.path)
        for src in sources:
            if not src.is_file():
                continue
            try:
                for line in src.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            except OSError:
                continue
        return records

    def record(
        self,
        finding: Union[Dict[str, Any], Any],
        verdict: Optional[str] = None,
        confidence: Optional[float] = None,
        tags: Optional[Sequence[str]] = None,
        source: str = "scan",
    ) -> Dict[str, Any]:
        """Append a finding to memory and return the stored record."""
        self.rotate_if_needed()
        self._ensure_parent()
        d = _as_dict(finding)
        fp = d.get("fingerprint") or fingerprint_finding(d)
        record = dict(d)
        record["fingerprint"] = fp
        record["verdict"] = verdict or d.get("validation_verdict")
        record["confidence"] = confidence if confidence is not None else d.get("confidence")
        record["tags"] = list(tags or [])
        record["source"] = source
        record["recorded_at"] = time.time()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return record

    def record_many(self, findings: Iterable[Union[Dict[str, Any], Any]], **kwargs: Any) -> int:
        """Record several findings; returns the number written."""
        count = 0
        for f in findings:
            self.record(f, **kwargs)
            count += 1
        return count

    # -- query ----------------------------------------------------------------

    def load(self, include_backups: bool = False) -> List[Dict[str, Any]]:
        """Load all stored records."""
        return self._read_lines(include_backups=include_backups)

    def dismissed_fingerprints(self) -> set:
        """Fingerprints the analyst has explicitly dismissed."""
        dismissed = set()
        for rec in self.load(include_backups=True):
            if rec.get("verdict") == "dismissed":
                dismissed.add(rec.get("fingerprint"))
        return dismissed

    def dismiss(self, fingerprint: str, reason: str = "") -> Dict[str, Any]:
        """Mark a fingerprint as dismissed so it does not resurface."""
        return self.record(
            {"fingerprint": fingerprint, "cwe_id": "", "file_path": ""},
            verdict="dismissed",
            tags=[reason] if reason else [],
            source="dismissal",
        )

    def recall(
        self,
        cwe: Optional[str] = None,
        file_path: Optional[str] = None,
        min_confidence: Optional[float] = None,
        include_dismissed: bool = False,
    ) -> List[Dict[str, Any]]:
        """Recall remembered findings matching the supplied filters."""
        dismissed = set() if include_dismissed else self.dismissed_fingerprints()
        seen: Dict[str, Dict[str, Any]] = {}
        for rec in self.load(include_backups=False):
            if rec.get("verdict") == "dismissed":
                continue
            fp = rec.get("fingerprint")
            if fp in dismissed:
                continue
            if cwe and rec.get("cwe_id") != cwe:
                continue
            if file_path and rec.get("file_path") != file_path:
                continue
            if min_confidence is not None and (rec.get("confidence") or 0.0) < min_confidence:
                continue
            if fp and fp not in seen:
                seen[fp] = rec
        return sorted(seen.values(), key=lambda r: r.get("recorded_at", 0), reverse=True)

    # -- dedup / ranking ------------------------------------------------------

    @staticmethod
    def rank(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank findings by severity weight and confidence, descending."""

        def key(rec: Dict[str, Any]) -> float:
            sev = SEVERITY_WEIGHT.get(str(rec.get("severity", "")), 1.0)
            conf = rec.get("confidence")
            if conf is None:
                conf = 1.0
            cvss = float(rec.get("cvss_score") or 0.0)
            return sev * 10.0 + cvss + conf

        return sorted(findings, key=key, reverse=True)

    @staticmethod
    def dedupe(findings: Sequence[Union[Dict[str, Any], Any]]) -> List[Dict[str, Any]]:
        """De-duplicate a finding list by fingerprint, keeping the highest confidence."""
        seen: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            d = _as_dict(f)
            fp = d.get("fingerprint") or fingerprint_finding(d)
            d["fingerprint"] = fp
            existing = seen.get(fp)
            if existing is None or (d.get("confidence") or 0.0) > (existing.get("confidence") or 0.0):
                seen[fp] = d
        return list(seen.values())

    # -- chaining -------------------------------------------------------------

    @staticmethod
    def find_chains(findings: Sequence[Union[Dict[str, Any], Any]]) -> List[Dict[str, Any]]:
        """Detect chained attack paths among co-located findings."""
        by_file: Dict[str, set] = {}
        for f in findings:
            d = _as_dict(f)
            by_file.setdefault(str(d.get("file_path", "")), set()).add(str(d.get("cwe_id", "")))
        chains: List[Dict[str, Any]] = []
        for path, cwes in by_file.items():
            for recipe in CHAIN_RECIPES:
                if all(req in cwes for req in recipe["requires"]):
                    chains.append({
                        "chain_id": recipe["id"],
                        "title": recipe["title"],
                        "impact": recipe["impact"],
                        "narrative": recipe["narrative"],
                        "file_path": path,
                        "components": recipe["requires"],
                    })
        chains.sort(key=lambda c: SEVERITY_WEIGHT.get(c["impact"], 0.0), reverse=True)
        return chains

    def stats(self) -> Dict[str, Any]:
        """Return summary statistics over stored records."""
        recs = self.load()
        by_cwe: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        by_verdict: Dict[str, int] = {}
        for r in recs:
            by_cwe[r.get("cwe_id", "?")] = by_cwe.get(r.get("cwe_id", "?"), 0) + 1
            by_sev[r.get("severity", "?")] = by_sev.get(r.get("severity", "?"), 0) + 1
            v = r.get("verdict") or "unvalidated"
            by_verdict[v] = by_verdict.get(v, 0) + 1
        return {
            "path": str(self.path),
            "total_records": len(recs),
            "unique_fingerprints": len({r.get("fingerprint") for r in recs}),
            "by_cwe": by_cwe,
            "by_severity": by_sev,
            "by_verdict": by_verdict,
        }
