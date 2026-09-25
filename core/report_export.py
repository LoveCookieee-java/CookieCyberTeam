"""
Report Bundle Exporter.

Packages the results of a scan into a single, shareable bundle: canonical
findings, OASIS SARIF 2.1.0, STIX 2.1 / MAEC 5.x indicators and behaviours, a
human-readable Markdown report, and submission-ready bug-bounty templates.

Files are only ever created or overwritten via normal writes (no deletion),
preserving the zero-deletion invariant.

Zero external dependencies (Python stdlib only).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from core.ast_scanner import findings_to_sarif
from core.finding_memory import FindingMemory, SEVERITY_WEIGHT
from core.malware_intel import to_maec_package, to_stix_bundle


def _severity_rank(sev: str) -> float:
    return SEVERITY_WEIGHT.get(sev, 1.0)


_UNSAFE_FILENAME_CHARS = re.compile(r"[^\w.\-]+")


def _safe_component(value: Any, fallback: str = "finding") -> str:
    """
    Reduce a finding field to a single, inert path component.

    Finding records can arrive from callers (``mcp_export_bundle`` accepts a
    ``findings`` array), so a ``cwe_id`` such as ``../escape`` or ``a/b`` must not
    be allowed to steer, or crash, the report filenames.
    """
    cleaned = _UNSAFE_FILENAME_CHARS.sub("_", str(value if value is not None else "")).strip("._")
    return cleaned[:64] or fallback


def render_markdown_report(
    title: str,
    findings: Sequence[Dict[str, Any]],
    meta: Optional[Dict[str, Any]] = None,
    chains: Optional[Sequence[Dict[str, Any]]] = None,
) -> str:
    """Render a findings markdown report."""
    meta = meta or {}
    lines: List[str] = [f"# {title}", ""]
    if meta:
        lines.append("## Scan Metadata")
        for k, v in meta.items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")
    lines.append(f"## Summary")
    lines.append(f"- Total findings: **{len(findings)}**")
    by_sev: Dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity", "Unknown")] = by_sev.get(f.get("severity", "Unknown"), 0) + 1
    for sev in sorted(by_sev, key=_severity_rank, reverse=True):
        lines.append(f"- {sev}: {by_sev[sev]}")
    lines.append("")

    if chains:
        lines.append("## Attack Chains")
        for chain in chains:
            lines.append(f"- **{chain['title']}** ({chain['impact']}) in `{chain['file_path']}`")
            lines.append(f"  - {chain['narrative']}")
        lines.append("")

    lines.append("## Findings")
    for idx, f in enumerate(findings, 1):
        lines.append(f"### {idx}. {f.get('cwe_id', '')} — {f.get('title', 'Finding')}")
        lines.append(f"- **File**: `{f.get('file_path', '')}`:{f.get('line_number', 0)}")
        lines.append(f"- **Severity**: {f.get('severity', '')} (CVSS {f.get('cvss_score', '')})")
        if f.get("confidence") is not None:
            lines.append(f"- **Confidence**: {round(float(f['confidence']) * 100)}%")
        if f.get("validation_verdict"):
            lines.append(f"- **Gate verdict**: {f['validation_verdict']}")
        lines.append(f"- **Description**: {f.get('description', '')}")
        if f.get("code_snippet"):
            lines.append("```")
            lines.append(str(f["code_snippet"]).strip())
            lines.append("```")
        lines.append(f"- **Remediation**: {f.get('remediation', '')}")
        lines.append("")
    return "\n".join(lines)


def render_hackerone_report(finding: Dict[str, Any]) -> str:
    """Render a HackerOne-style submission for a single finding."""
    return "\n".join([
        "## Title",
        f"{finding.get('cwe_id', '')} in {Path(str(finding.get('file_path', ''))).name}",
        "",
        "## Severity",
        f"{finding.get('severity', '')} (CVSS {finding.get('cvss_score', '')} — {finding.get('cvss_vector', '')})",
        "",
        "## Description",
        str(finding.get("description", "")),
        "",
        "## Steps To Reproduce",
        "1. Locate the sink described below.",
        "2. Supply attacker-controlled input reaching it without a sanitizer.",
        f"3. Observe the vulnerable behaviour at `{finding.get('file_path', '')}:{finding.get('line_number', 0)}`.",
        "",
        "## Supporting Material",
        "```",
        str(finding.get("code_snippet", "")).strip(),
        "```",
        "",
        "## Remediation",
        str(finding.get("remediation", "")),
        "",
        "## Impact",
        f"Direct exploitation of {finding.get('cwe_id', 'the weakness')} at the identified sink.",
    ])


def render_bugcrowd_report(finding: Dict[str, Any]) -> str:
    """Render a Bugcrowd-style submission for a single finding."""
    return "\n".join([
        f"# {finding.get('cwe_id', '')}: {finding.get('title', 'Finding')}",
        "",
        f"**Location**: `{finding.get('file_path', '')}:{finding.get('line_number', 0)}`",
        f"**Severity**: {finding.get('severity', '')}",
        "",
        "## Description",
        str(finding.get("description", "")),
        "",
        "## Proof of Concept",
        "```",
        str(finding.get("code_snippet", "")).strip(),
        "```",
        "",
        "## Remediation",
        str(finding.get("remediation", "")),
    ])


def build_bundle(
    findings: Sequence[Dict[str, Any]],
    title: str = "CookieCyberTeam Security Report",
    meta: Optional[Dict[str, Any]] = None,
    include_chains: bool = True,
    stix_inputs: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Build a complete report bundle dictionary.

    ``stix_inputs`` optionally carries binary-triage enrichment blocks (with
    ``sha256``/``md5``/``families``) to include as STIX/MAEC objects.
    """
    ranked = FindingMemory.rank(list(findings))
    chains = FindingMemory.find_chains(ranked) if include_chains else []
    sarif = findings_to_sarif(ranked)
    stix_objects: List[Dict[str, Any]] = []
    maec_objects: List[Dict[str, Any]] = []
    for item in stix_inputs or []:
        stix_objects.append(to_stix_bundle(
            indicator_name=f"sample-{str(item.get('sha256', ''))[:12]}",
            sha256=str(item.get("sha256", "")),
            md5=item.get("md5"),
            imphash=item.get("imphash"),
            fuzzy=item.get("fuzzy_hash"),
            families=item.get("family_matches"),
        ))
        maec_objects.append(to_maec_package(
            indicator_name=f"sample-{str(item.get('sha256', ''))[:12]}",
            sha256=str(item.get("sha256", "")),
            families=item.get("family_matches"),
            techniques=item.get("techniques"),
        ))

    reports = []
    for f in ranked[:20]:
        reports.append({
            "fingerprint": f.get("fingerprint"),
            "cwe_id": f.get("cwe_id"),
            "hackerone": render_hackerone_report(f),
            "bugcrowd": render_bugcrowd_report(f),
        })

    return {
        "success": True,
        "title": title,
        "meta": meta or {},
        "finding_count": len(ranked),
        "findings": ranked,
        "chains": chains,
        "sarif": sarif,
        "stix_bundles": stix_objects,
        "maec_packages": maec_objects,
        "markdown": render_markdown_report(title, ranked, meta=meta, chains=chains),
        "reports": reports,
    }


def export_bundle(
    bundle: Dict[str, Any],
    dest_dir: Union[str, Path],
    include_stix: bool = True,
    include_reports: bool = True,
) -> Dict[str, Any]:
    """
    Write a bundle to ``dest_dir`` as discrete files.

    Only creates/overwrites files; never deletes. Returns the written paths.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    written: Dict[str, str] = {}

    (dest / "report.md").write_text(bundle.get("markdown", ""), encoding="utf-8")
    written["markdown"] = str(dest / "report.md")

    (dest / "findings.sarif").write_text(json.dumps(bundle.get("sarif", {}), indent=2), encoding="utf-8")
    written["sarif"] = str(dest / "findings.sarif")

    (dest / "findings.json").write_text(json.dumps({
        "title": bundle.get("title"),
        "meta": bundle.get("meta"),
        "finding_count": bundle.get("finding_count"),
        "findings": bundle.get("findings"),
        "chains": bundle.get("chains"),
    }, indent=2), encoding="utf-8")
    written["findings_json"] = str(dest / "findings.json")

    if include_stix and bundle.get("stix_bundles"):
        (dest / "indicators.stix.json").write_text(
            json.dumps(bundle["stix_bundles"], indent=2), encoding="utf-8"
        )
        written["stix"] = str(dest / "indicators.stix.json")
    if include_stix and bundle.get("maec_packages"):
        (dest / "behaviors.maec.json").write_text(
            json.dumps(bundle["maec_packages"], indent=2), encoding="utf-8"
        )
        written["maec"] = str(dest / "behaviors.maec.json")

    if include_reports and bundle.get("reports"):
        reports_dir = dest / "submissions"
        reports_dir.mkdir(parents=True, exist_ok=True)
        for idx, rep in enumerate(bundle["reports"], 1):
            cwe = _safe_component(rep.get("cwe_id"))
            h1_path = reports_dir / f"{idx:02d}_{cwe}_hackerone.md"
            bc_path = reports_dir / f"{idx:02d}_{cwe}_bugcrowd.md"
            h1_path.write_text(rep["hackerone"], encoding="utf-8")
            bc_path.write_text(rep["bugcrowd"], encoding="utf-8")
        written["submissions_dir"] = str(reports_dir)

    return {"success": True, "dest_dir": str(dest), "written": written}
