"""
Multi-Framework Security Catalog.

Data-only reference structures for the six frameworks an agent-facing security
catalog benefits from, so techniques can be reasoned about defensively across
more than ATT&CK alone:

* MITRE ATT&CK v19.1 -- tactics, including the v19.1 split of Defense Evasion
  into **Stealth** (TA0005) and **Defense Impairment** (TA0112).
* MITRE D3FEND v1.4.0 -- defensive countermeasure techniques (``D3-*``).
* MITRE ATLAS -- adversarial threats against AI/ML systems (``AML.T*``).
* NIST CSF 2.0 -- the six functions and their categories.
* NIST AI RMF 1.0 -- Govern / Map / Measure / Manage.
* MITRE F3 (Fight Fraud Framework v1.1) -- fraud tactics including Positioning
  (FA0001) and Monetization (FA0002).

Entries explicitly flag when a list is *representative* rather than exhaustive,
so consumers never mistake a curated subset for the complete upstream catalog.
Nothing here executes or describes an offensive capability.

Zero external dependencies (Python stdlib only).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

# ---------------------------------------------------------------------------
# MITRE ATT&CK v19.1 -- tactic ordering
# ---------------------------------------------------------------------------

ATTACK_VERSION = "v19.1"

#: Ordered ATT&CK tactics. ``legacy`` records prior naming so older technique
#: records (e.g. "Defense Evasion") still resolve after the v19.1 split.
ATTACK_TACTICS: List[Dict[str, Any]] = [
    {"id": "TA0043", "name": "Reconnaissance", "phase": "pre-attack"},
    {"id": "TA0042", "name": "Resource Development", "phase": "pre-attack"},
    {"id": "TA0001", "name": "Initial Access", "phase": "intrusion"},
    {"id": "TA0002", "name": "Execution", "phase": "intrusion"},
    {"id": "TA0003", "name": "Persistence", "phase": "intrusion"},
    {"id": "TA0004", "name": "Privilege Escalation", "phase": "intrusion"},
    {"id": "TA0005", "name": "Stealth", "phase": "intrusion", "legacy": ["Defense Evasion"]},
    {"id": "TA0112", "name": "Defense Impairment", "phase": "intrusion",
     "legacy": ["Defense Evasion"], "note": "New in ATT&CK v19.1."},
    {"id": "TA0006", "name": "Credential Access", "phase": "intrusion"},
    {"id": "TA0007", "name": "Discovery", "phase": "intrusion"},
    {"id": "TA0008", "name": "Lateral Movement", "phase": "intrusion"},
    {"id": "TA0009", "name": "Collection", "phase": "intrusion"},
    {"id": "TA0011", "name": "Command and Control", "phase": "intrusion"},
    {"id": "TA0010", "name": "Exfiltration", "phase": "intrusion"},
    {"id": "TA0040", "name": "Impact", "phase": "post-intrusion"},
]

#: ATT&CK-v19.1 Stealth / Defense Impairment sub-scope, used for reporting.
STEALTH_AND_IMPAIRMENT: Dict[str, str] = {
    "Stealth": "Evasion of observation: obfuscation, masquerading, indicator removal, rootkits.",
    "Defense Impairment": "Disabling or degrading defenses: impair defenses, disable tools, "
                          "modify cloud/network security controls.",
}

# ---------------------------------------------------------------------------
# MITRE D3FEND v1.4.0 -- defensive countermeasures (representative subset)
# ---------------------------------------------------------------------------

D3FEND_VERSION = "v1.4.0"

D3FEND_COUNTERMEASURES: List[Dict[str, str]] = [
    {"id": "D3-NTA", "name": "Network Traffic Analysis",
     "counters": "Command and Control, Exfiltration"},
    {"id": "D3-NTF", "name": "Network Traffic Filtering",
     "counters": "Command and Control, Exfiltration, Lateral Movement"},
    {"id": "D3-DA", "name": "Dynamic Analysis",
     "counters": "Execution, Stealth"},
    {"id": "D3-FA", "name": "File Analysis",
     "counters": "Stealth, Resource Development"},
    {"id": "D3-PA", "name": "Process Analysis",
     "counters": "Execution, Privilege Escalation"},
    {"id": "D3-PMAD", "name": "Process Memory Analysis",
     "counters": "Stealth, Credential Access"},
    {"id": "D3-IPI", "name": "Inbound Payload Inspection",
     "counters": "Initial Access, Execution"},
    {"id": "D3-EAL", "name": "Executable Allowlisting",
     "counters": "Execution, Stealth"},
    {"id": "D3-CH", "name": "Credential Hardening",
     "counters": "Credential Access, Privilege Escalation"},
    {"id": "D3-MFA", "name": "Multi-factor Authentication",
     "counters": "Initial Access, Credential Access"},
    {"id": "D3-SU", "name": "Software Update",
     "counters": "Initial Access, Resource Development"},
    {"id": "D3-SICA", "name": "System Init Config Analysis",
     "counters": "Persistence, Defense Impairment"},
]

#: Technique-id prefix -> D3FEND countermeasure ids that best address it.
D3FEND_BY_TECHNIQUE: Dict[str, List[str]] = {
    "T1055": ["D3-PMAD", "D3-PA"],
    "T1003": ["D3-CH", "D3-MFA"],
    "T1059": ["D3-EAL", "D3-PA"],
    "T1071": ["D3-NTA", "D3-NTF"],
    "T1041": ["D3-NTA", "D3-NTF"],
    "T1105": ["D3-NTF", "D3-IPI"],
    "T1547": ["D3-SICA"],
    "T1562": ["D3-SICA", "D3-EAL"],
    "T1070": ["D3-NTA", "D3-FA"],
    "T1027": ["D3-FA", "D3-DA"],
    "T1486": ["D3-NTF"],
    "T1505": ["D3-IPI", "D3-FA"],
}

# ---------------------------------------------------------------------------
# MITRE ATLAS -- AI/ML adversarial threats (representative subset)
# ---------------------------------------------------------------------------

ATLAS_VERSION = "2026.07"
ATLAS_EXHAUSTIVE = False

ATLAS_TECHNIQUES: List[Dict[str, str]] = [
    {"id": "AML.T0051", "name": "LLM Prompt Injection", "asi_id": "ASI-01"},
    {"id": "AML.T0054", "name": "LLM Jailbreak", "asi_id": "ASI-01"},
    {"id": "AML.T0056", "name": "Extract LLM System Prompt", "asi_id": "ASI-03"},
    {"id": "AML.T0043", "name": "Craft Adversarial Data", "asi_id": "ASI-06"},
    {"id": "AML.T0047", "name": "ML-Enabled Product or Service", "asi_id": "ASI-07"},
    {"id": "AML.T0010", "name": "ML Supply Chain Compromise", "asi_id": "ASI-07"},
    {"id": "AML.T0048", "name": "External Harms", "asi_id": "ASI-09"},
    {"id": "AML.T0053", "name": "AI Agent Tool Invocation", "asi_id": "ASI-02"},
]

#: ASI threat class -> ATLAS techniques worth checking.
ATLAS_BY_ASI: Dict[str, List[str]] = {}
for _atlas in ATLAS_TECHNIQUES:
    ATLAS_BY_ASI.setdefault(_atlas["asi_id"], []).append(_atlas["id"])

# ---------------------------------------------------------------------------
# NIST CSF 2.0 and NIST AI RMF 1.0
# ---------------------------------------------------------------------------

CSF_VERSION = "2.0"

NIST_CSF_FUNCTIONS: List[Dict[str, Any]] = [
    {"id": "GV", "name": "Govern", "categories": 6,
     "categories_list": ["Organizational Context", "Risk Management Strategy",
                          "Roles, Responsibilities, and Authorities", "Policy",
                          "Oversight", "Cybersecurity Supply Chain Risk Management"]},
    {"id": "ID", "name": "Identify", "categories": 3,
     "categories_list": ["Asset Management", "Risk Assessment", "Improvement"]},
    {"id": "PR", "name": "Protect", "categories": 5,
     "categories_list": ["Identity Management, Authentication, and Access Control",
                          "Awareness and Training", "Data Security",
                          "Platform Security", "Technology Infrastructure Resilience"]},
    {"id": "DE", "name": "Detect", "categories": 2,
     "categories_list": ["Continuous Monitoring", "Adverse Event Analysis"]},
    {"id": "RS", "name": "Respond", "categories": 4,
     "categories_list": ["Incident Management", "Incident Analysis",
                          "Incident Response Reporting and Communication",
                          "Incident Mitigation"]},
    {"id": "RC", "name": "Recover", "categories": 2,
     "categories_list": ["Incident Recovery Plan Execution", "Incident Recovery Communication"]},
]

NIST_AI_RMF_VERSION = "1.0"

NIST_AI_RMF_FUNCTIONS: List[Dict[str, str]] = [
    {"id": "GOVERN", "name": "Govern", "focus": "Cultivate a risk culture and assign accountability."},
    {"id": "MAP", "name": "Map", "focus": "Frame context and identify AI risks for the use case."},
    {"id": "MEASURE", "name": "Measure", "focus": "Analyse, assess, and track identified risks."},
    {"id": "MANAGE", "name": "Manage", "focus": "Prioritise and act on risks; plan responses."},
]

# ---------------------------------------------------------------------------
# MITRE F3 (Fight Fraud Framework v1.1)
# ---------------------------------------------------------------------------

F3_VERSION = "v1.1"

#: Fraud-specific tactics. F3 is ATT&CK-compatible: reused behaviours keep
#: their T1XXX ids, while fraud-only tactics use F-ids (FA000X).
F3_TACTICS: List[Dict[str, str]] = [
    {"id": "FA0001", "name": "Positioning",
     "summary": "Post-access actions that prepare the fraud: synthetic-identity seeding, "
                "account warming, beneficiary setup, SIM-swap pre-positioning, session hijack."},
    {"id": "FA0002", "name": "Monetization",
     "summary": "Converting stolen assets into usable funds: money-mule layering, authorised "
                "push-payment fraud, crypto off-ramping, card cash-out, refund abuse."},
]

#: Fraud-specific technique ids referenced by F3 v1.1 (representative).
F3_TECHNIQUES: List[Dict[str, str]] = [
    {"id": "F1005.003", "name": "Add Beneficiary", "tactic": "Positioning"},
    {"id": "F1007", "name": "Adversary-in-the-Browser", "tactic": "Positioning"},
    {"id": "F1025.003", "name": "Wire Transfer", "tactic": "Monetization"},
]

# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

FRAMEWORKS: Dict[str, Dict[str, Any]] = {
    "mitre_attack": {"label": "MITRE ATT&CK", "version": ATTACK_VERSION},
    "mitre_d3fend": {"label": "MITRE D3FEND", "version": D3FEND_VERSION},
    "mitre_atlas": {"label": "MITRE ATLAS", "version": ATLAS_VERSION,
                    "exhaustive": ATLAS_EXHAUSTIVE},
    "nist_csf": {"label": "NIST CSF 2.0", "version": CSF_VERSION},
    "nist_ai_rmf": {"label": "NIST AI RMF", "version": NIST_AI_RMF_VERSION},
    "mitre_f3": {"label": "MITRE F3 (Fight Fraud)", "version": F3_VERSION},
}

_TACTIC_BY_NAME: Dict[str, Dict[str, Any]] = {}
for _tactic in ATTACK_TACTICS:
    _TACTIC_BY_NAME[_tactic["name"].lower()] = _tactic
    for _legacy in _tactic.get("legacy", []):
        _TACTIC_BY_NAME.setdefault(_legacy.lower(), _tactic)


def list_tactics() -> List[Dict[str, Any]]:
    """Return ATT&CK v19.1 tactics in kill-chain order."""
    return [dict(t) for t in ATTACK_TACTICS]


def list_frameworks() -> List[Dict[str, Any]]:
    """Return the framework registry as plain dictionaries."""
    return [{"key": k, **v} for k, v in FRAMEWORKS.items()]


def resolve_tactic(name: str) -> Optional[Dict[str, Any]]:
    """
    Resolve a tactic name (or tactic id) to its v19.1 record.

    Legacy names such as "Defense Evasion" resolve to their v19.1 successor
    (Stealth), keeping older technique records coherent.
    """
    if not name:
        return None
    needle = str(name).strip().lower()
    for tactic in ATTACK_TACTICS:
        if tactic["id"].lower() == needle:
            return dict(tactic)
    found = _TACTIC_BY_NAME.get(needle)
    return dict(found) if found else None


def d3fend_for_technique(technique_id: str) -> List[Dict[str, str]]:
    """Return D3FEND countermeasures recommended for a technique id."""
    base = str(technique_id).strip().upper().split(".")[0]
    ids = D3FEND_BY_TECHNIQUE.get(base, [])
    by_id = {c["id"]: c for c in D3FEND_COUNTERMEASURES}
    return [dict(by_id[cid]) for cid in ids if cid in by_id]


def atlas_for_asi(asi_id: str) -> List[Dict[str, str]]:
    """Return ATLAS techniques associated with an agentic threat class."""
    ids = set(ATLAS_BY_ASI.get(str(asi_id).strip().upper(), []))
    return [dict(t) for t in ATLAS_TECHNIQUES if t["id"] in ids]


def map_technique(technique_id: str) -> Dict[str, Any]:
    """Cross-map a technique id onto every framework it touches."""
    ident = str(technique_id).strip().upper()
    return {
        "technique_id": ident,
        "attack": {"framework": "MITRE ATT&CK", "version": ATTACK_VERSION,
                   "base_technique": ident.split(".")[0]},
        "d3fend": d3fend_for_technique(ident),
        "atlas": [dict(t) for t in ATLAS_TECHNIQUES
                  if t["id"] == ident or t["id"] == ident.split(".")[0]],
        "f3": [dict(t) for t in F3_TECHNIQUES if t["id"] == ident],
        "nist_csf": {"framework": "NIST CSF 2.0", "functions": [f["id"] for f in NIST_CSF_FUNCTIONS]},
        "nist_ai_rmf": {"framework": "NIST AI RMF 1.0",
                        "functions": [f["id"] for f in NIST_AI_RMF_FUNCTIONS]},
    }


# ---------------------------------------------------------------------------
# Detection coverage
# ---------------------------------------------------------------------------


def build_coverage_matrix(
    entries: Iterable[Dict[str, Any]],
    tactic_by_technique: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Build an ATT&CK coverage matrix from rules or findings.

    ``entries`` are dicts carrying at least ``technique_id``; an optional
    ``tactic`` field (or the ``tactic_by_technique`` map) assigns the tactic a
    technique belongs to. Techniques whose tactic is unknown are reported under
    ``Unmapped`` rather than silently attributed.
    """
    tactic_by_technique = {k.upper(): v for k, v in (tactic_by_technique or {}).items()}
    covered: Dict[str, set] = {}
    unmapped: set = set()
    total = 0

    for entry in entries:
        ident = str(entry.get("technique_id") or "").strip().upper()
        if not ident:
            continue
        total += 1
        tactic = entry.get("tactic") or tactic_by_technique.get(ident) \
            or tactic_by_technique.get(ident.split(".")[0])
        if tactic:
            covered.setdefault(str(tactic), set()).add(ident)
        else:
            unmapped.add(ident)

    matrix: List[Dict[str, Any]] = []
    for tactic in ATTACK_TACTICS:
        techniques = sorted(covered.get(tactic["name"], set()))
        matrix.append({
            "tactic_id": tactic["id"],
            "tactic": tactic["name"],
            "phase": tactic["phase"],
            "techniques_covered": techniques,
            "coverage_count": len(techniques),
            "covered": bool(techniques),
        })

    mapped_tactics = {t["name"] for t in ATTACK_TACTICS}
    for tactic_name, techniques in covered.items():
        if tactic_name not in mapped_tactics:
            matrix.append({
                "tactic_id": "",
                "tactic": tactic_name,
                "phase": "unclassified",
                "techniques_covered": sorted(techniques),
                "coverage_count": len(techniques),
                "covered": True,
            })

    total_covered = len({t for techniques in covered.values() for t in techniques})
    return {
        "framework": "MITRE ATT&CK",
        "version": ATTACK_VERSION,
        "rules_evaluated": total,
        "distinct_techniques_covered": total_covered,
        "tactics_with_coverage": sum(1 for row in matrix if row["covered"]),
        "tactics_total": len(ATTACK_TACTICS),
        "unmapped_techniques": sorted(unmapped),
        "gaps": [row["tactic"] for row in matrix if not row["covered"] and row["phase"] != "unclassified"],
        "matrix": matrix,
    }


def render_frameworks_resource() -> str:
    """Render the framework catalog as Markdown for the MCP resource."""
    lines = [
        "# Multi-Framework Security Catalog",
        "",
        "Data-only reference structures used to reason about defensive coverage",
        "across six frameworks. Lists marked *representative* are curated subsets,",
        "not the complete upstream catalogs.",
        "",
        "## MITRE ATT&CK " + ATTACK_VERSION + " -- tactics",
        "",
        "| ID | Tactic | Phase | Notes |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for tactic in ATTACK_TACTICS:
        note = tactic.get("note") or ("alias of former Defense Evasion" if tactic.get("legacy") else "")
        lines.append(f"| `{tactic['id']}` | {tactic['name']} | {tactic['phase']} | {note} |")

    lines += [
        "",
        "### v19.1 change: Defense Evasion split",
        "",
    ]
    for name, scope in STEALTH_AND_IMPAIRMENT.items():
        lines.append(f"- **{name}**: {scope}")

    lines += [
        "",
        "## MITRE D3FEND " + D3FEND_VERSION + " (representative)",
        "",
        "| ID | Countermeasure | Counters |",
        "| :--- | :--- | :--- |",
    ]
    for cm in D3FEND_COUNTERMEASURES:
        lines.append(f"| `{cm['id']}` | {cm['name']} | {cm['counters']} |")

    lines += [
        "",
        "## MITRE ATLAS " + ATLAS_VERSION + " (representative)",
        "",
        "| ID | Technique | Agentic class |",
        "| :--- | :--- | :--- |",
    ]
    for tech in ATLAS_TECHNIQUES:
        lines.append(f"| `{tech['id']}` | {tech['name']} | {tech.get('asi_id', '')} |")

    lines += [
        "",
        "## NIST CSF " + CSF_VERSION + " -- functions",
        "",
    ]
    for fn in NIST_CSF_FUNCTIONS:
        lines.append(f"- **{fn['id']} {fn['name']}** ({fn['categories']} categories): "
                     f"{', '.join(fn['categories_list'])}")

    lines += [
        "",
        "## NIST AI RMF " + NIST_AI_RMF_VERSION + " -- functions",
        "",
    ]
    for fn in NIST_AI_RMF_FUNCTIONS:
        lines.append(f"- **{fn['id']}** ({fn['name']}): {fn['focus']}")

    lines += [
        "",
        "## MITRE F3 (Fight Fraud) " + F3_VERSION + " -- fraud tactics",
        "",
    ]
    for tactic in F3_TACTICS:
        lines.append(f"- **{tactic['id']} {tactic['name']}**: {tactic['summary']}")
    lines += [
        "",
        "Fraud-specific techniques use F-ids; behaviours reused from ATT&CK keep their T-ids.",
    ]
    return "\n".join(lines)


__all__ = [
    "ATTACK_TACTICS",
    "ATTACK_VERSION",
    "ATLAS_TECHNIQUES",
    "CSF_VERSION",
    "D3FEND_COUNTERMEASURES",
    "D3FEND_VERSION",
    "F3_TACTICS",
    "F3_VERSION",
    "FRAMEWORKS",
    "NIST_AI_RMF_FUNCTIONS",
    "NIST_CSF_FUNCTIONS",
    "atlas_for_asi",
    "build_coverage_matrix",
    "d3fend_for_technique",
    "list_frameworks",
    "list_tactics",
    "map_technique",
    "render_frameworks_resource",
    "resolve_tactic",
]
