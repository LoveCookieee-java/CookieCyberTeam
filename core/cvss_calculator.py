"""
FIRST.org CVSS v3.1 Specification Base Score & Vector String Calculator.
Zero-dependency, mathematically exact standard implementation.
"""

from __future__ import annotations
import math
from typing import Any, Dict, Optional, Set, Tuple


def cvss_roundup(val: float) -> float:
    """
    Standard FIRST CVSS v3.1 roundup function.
    Returns the smallest number to one decimal place that is >= input,
    avoiding IEEE-754 floating point imprecision.
    """
    int_round = int(round(val * 100000))
    if int_round % 10000 == 0:
        return int_round / 100000.0
    return (int(int_round / 10000) + 1) / 10.0


# CVSS v3.1 Metric Weight Constants
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}


# Standard default vectors for common vulnerabilities
CWE_DEFAULT_VECTORS: Dict[str, str] = {
    "CWE-78": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # OS Command Injection -> 9.8 Critical
    "CWE-89": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # SQL Injection -> 9.8 Critical
    "CWE-95": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # Code Injection / Eval -> 9.8 Critical
    "CWE-502": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Insecure Deserialization -> 9.8 Critical
    "CWE-798": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # Hardcoded Credentials -> 7.5 High
    "CWE-295": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # Improper Cert Validation -> 7.4 High
}


def get_severity(score: float) -> str:
    """Determine qualitative severity rating from CVSS Base Score."""
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    return "Critical"


VALID_METRICS: Dict[str, Set[str]] = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}


def parse_vector_string(vector_str: str) -> Dict[str, str]:
    """Parse CVSS:3.1 vector string into metric dictionary."""
    clean_vec = vector_str.strip()
    upper_vec = clean_vec.upper()
    if upper_vec.startswith("CVSS:3.1/"):
        clean_vec = clean_vec[9:]
    elif upper_vec.startswith("CVSS:3.0/"):
        clean_vec = clean_vec[9:]

    parts = clean_vec.split("/")
    metrics: Dict[str, str] = {}
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()

    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [m for m in required if m not in metrics]
    if missing:
        raise ValueError(f"Missing required CVSS v3.1 metrics in vector: {missing}")

    for k, v in metrics.items():
        if k in VALID_METRICS and v not in VALID_METRICS[k]:
            raise ValueError(f"Invalid metric value '{v}' for metric '{k}'. Allowed: {sorted(VALID_METRICS[k])}")

    return metrics


def calculate_cvss_score(vector_str: str) -> Dict[str, Any]:
    """
    Calculate CVSS v3.1 Base Score, Impact, Exploitability, and Severity.
    """
    metrics = parse_vector_string(vector_str)

    av = AV_WEIGHTS[metrics["AV"]]
    ac = AC_WEIGHTS[metrics["AC"]]
    scope = metrics["S"]
    pr = PR_WEIGHTS[scope][metrics["PR"]]
    ui = UI_WEIGHTS[metrics["UI"]]

    c = CIA_WEIGHTS[metrics["C"]]
    i = CIA_WEIGHTS[metrics["I"]]
    a = CIA_WEIGHTS[metrics["A"]]

    # ISS (Impact Sub-Score)
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    # Impact calculation based on Scope
    if scope == "U":
        impact = 6.42 * iss
    else:  # Scope Changed
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0.0:
        base_score = 0.0
    else:
        if scope == "U":
            raw_score = min(impact + exploitability, 10.0)
        else:
            raw_score = min(1.08 * (impact + exploitability), 10.0)
        base_score = cvss_roundup(raw_score)

    severity = get_severity(base_score)

    return {
        "vector_string": f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}",
        "base_score": base_score,
        "severity": severity,
        "impact": round(impact, 2),
        "exploitability": round(exploitability, 2),
        "metrics": metrics,
    }


def cvss_for_cwe(cwe_id: str, custom_overrides: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Get standardized CVSS v3.1 score for a given CWE ID."""
    base_vector = CWE_DEFAULT_VECTORS.get(cwe_id.upper(), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    if custom_overrides:
        metrics = parse_vector_string(base_vector)
        metrics.update(custom_overrides)
        vec_parts = [f"{k}:{v}" for k, v in metrics.items()]
        base_vector = f"CVSS:3.1/{'/'.join(vec_parts)}"
    return calculate_cvss_score(base_vector)
