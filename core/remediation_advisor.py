"""
Offline Remediation Advisor.

Turns a dependency vulnerability into an actionable defensive advisory: likely
exposure, blast radius, remediation steps, and an urgency tier. Purely offline
and deterministic; no network lookups and no exploitation guidance.

Zero external dependencies (Python stdlib only).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


#: Curated advisory notes keyed by CVE, for the offline OSV entries we ship.
CURATED_ADVISORY: Dict[str, Dict[str, Any]] = {
    "CVE-2023-32681": {
        "exposure": "Proxy-Authorization header can leak to a malicious HTTPS proxy.",
        "vector": "Network",
        "remediation": [
            "Upgrade requests to the fixed release.",
            "If upgrade is blocked, avoid untrusted HTTPS proxies for authenticated requests.",
        ],
    },
    "CVE-2023-45803": {
        "exposure": "Request body may be forwarded on a cross-origin redirect.",
        "vector": "Network",
        "remediation": [
            "Upgrade urllib3 to the fixed release.",
            "Disable automatic redirects for requests carrying sensitive bodies.",
        ],
    },
}

#: Keyword -> remediation guidance used when a specific CVE has no curated note.
KEYWORD_ADVISORY: List[Dict[str, Any]] = [
    {
        "keywords": ["deseriali", "pickle", "yaml", "marshal"],
        "exposure": "Untrusted data may be deserialized, enabling code execution.",
        "remediation": ["Upgrade the package.", "Switch to a safe loader / strict schema validation."],
    },
    {
        "keywords": ["injection", "sql", "command", "template"],
        "exposure": "Untrusted input may reach an interpreter sink.",
        "remediation": ["Upgrade the package.", "Parameterize queries and validate inputs at boundaries."],
    },
    {
        "keywords": ["path", "traversal", "zip", "archive", "tar"],
        "exposure": "Archive or path handling may allow traversal outside the intended directory.",
        "remediation": ["Upgrade the package.", "Canonicalize and confine extracted paths to a base directory."],
    },
    {
        "keywords": ["ssrf", "redirect", "url", "proxy"],
        "exposure": "Outbound requests may be redirected to internal or metadata endpoints.",
        "remediation": ["Upgrade the package.", "Enforce an egress allowlist for outbound requests."],
    },
    {
        "keywords": ["dos", "denial", "resource", "regex", "catastrophic"],
        "exposure": "Malformed input may cause excessive resource consumption.",
        "remediation": ["Upgrade the package.", "Bound request sizes and add rate limiting."],
    },
    {
        "keywords": ["auth", "token", "session", "csrf", "jwt"],
        "exposure": "Authentication or session handling may be bypassable.",
        "remediation": ["Upgrade the package.", "Rotate affected secrets and re-verify auth flows."],
    },
]


def _urgency(severity: str, cvss_score: float) -> str:
    sev = (severity or "").lower()
    if sev == "critical" or cvss_score >= 9.0:
        return "immediate"
    if sev == "high" or cvss_score >= 7.0:
        return "urgent"
    if sev == "medium" or cvss_score >= 4.0:
        return "scheduled"
    return "monitor"


def advisory_for(
    cve_id: str = "",
    package: str = "",
    severity: str = "",
    cvss_score: float = 0.0,
    summary: str = "",
    fixed_in: str = "",
) -> Dict[str, Any]:
    """Build an offline remediation advisory for a dependency vulnerability."""
    curated = CURATED_ADVISORY.get(cve_id)
    haystack = f"{summary} {package}".lower()
    if curated:
        exposure = curated["exposure"]
        remediation = list(curated["remediation"])
    else:
        exposure = "Potential weakness in a third-party dependency."
        remediation = []
        for entry in KEYWORD_ADVISORY:
            if any(k in haystack for k in entry["keywords"]):
                exposure = entry["exposure"]
                remediation = list(entry["remediation"])
                break
    if not remediation:
        remediation = ["Upgrade the dependency to a maintained release."]
    if fixed_in:
        remediation.insert(0, f"Upgrade {package} to >= {fixed_in}.")
    return {
        "cve_id": cve_id,
        "package": package,
        "urgency": _urgency(severity, cvss_score),
        "exposure": exposure,
        "remediation": remediation,
        "blast_radius": "dependency-level: rebuild and redeploy after upgrade",
    }


def enrich_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach an advisory to each vulnerability finding dict (in place copy)."""
    enriched: List[Dict[str, Any]] = []
    for vuln in vulnerabilities:
        item = dict(vuln)
        item["advisory"] = advisory_for(
            cve_id=str(vuln.get("cve_id", "")),
            package=str(vuln.get("package_name", "")),
            severity=str(vuln.get("severity", "")),
            cvss_score=float(vuln.get("cvss_score") or 0.0),
            summary=str(vuln.get("summary", "")),
            fixed_in=str(vuln.get("fixed_in", "")),
        )
        enriched.append(item)
    return enriched
