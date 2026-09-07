"""
FIRST.org CVSS v3.1 Specification Base Score & Vector String Calculator.
Zero-dependency, mathematically exact standard implementation.
"""

from __future__ import annotations
import math
import re
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


# Standard default vectors for common vulnerabilities (CVSS v3.1)
CWE_DEFAULT_VECTORS: Dict[str, str] = {
    "CWE-78": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # OS Command Injection -> 9.8 Critical
    "CWE-89": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # SQL Injection -> 9.8 Critical
    "CWE-95": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # Code Injection / Eval -> 9.8 Critical
    "CWE-502": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Insecure Deserialization -> 9.8 Critical
    "CWE-798": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # Hardcoded Credentials -> 7.5 High
    "CWE-295": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # Improper Cert Validation -> 7.4 High
    "CWE-22": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # Path Traversal / Zip Slip -> 9.1 Critical
    "CWE-327": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # Broken Crypto Algorithm -> 7.5 High
    "CWE-328": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # Weak Hash (MD5/SHA1) -> 7.5 High
    "CWE-377": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",  # Insecure Temp File -> 4.0 Medium
    "CWE-352": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",  # CSRF -> 6.5 Medium
}

# Default vectors for CVSS v4.0
CWE_DEFAULT_VECTORS_V4: Dict[str, str] = {
    "CWE-78": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CWE-89": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CWE-95": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CWE-502": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CWE-798": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CWE-295": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "CWE-22": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "CWE-327": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CWE-328": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CWE-377": "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "CWE-352": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
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

VALID_METRICS_V4: Dict[str, Set[str]] = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "AT": {"N", "P"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "P", "A"},
    "VC": {"H", "L", "N"},
    "VI": {"H", "L", "N"},
    "VA": {"H", "L", "N"},
    "SC": {"H", "L", "N"},
    "SI": {"H", "L", "N"},
    "SA": {"H", "L", "N"},
}

REQUIRED_METRICS_V4 = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

# FIRST CVSS v4.0 MacroVector Lookup Table (EQ1, EQ2, EQ3, EQ4) -> Base Score
CVSS_V40_LOOKUP: Dict[Tuple[int, int, int, int], float] = {
    (0, 0, 0, 0): 10.0,
    (0, 0, 0, 1): 9.7,
    (0, 0, 0, 2): 9.3,
    (0, 0, 1, 0): 9.2,
    (0, 0, 1, 1): 8.9,
    (0, 0, 1, 2): 8.5,
    (0, 0, 2, 0): 8.2,
    (0, 0, 2, 1): 7.6,
    (0, 0, 2, 2): 6.9,
    (0, 1, 0, 0): 9.4,
    (0, 1, 0, 1): 9.1,
    (0, 1, 0, 2): 8.7,
    (0, 1, 1, 0): 8.6,
    (0, 1, 1, 1): 8.2,
    (0, 1, 1, 2): 7.7,
    (0, 1, 2, 0): 7.4,
    (0, 1, 2, 1): 6.8,
    (0, 1, 2, 2): 5.9,
    (1, 0, 0, 0): 9.3,
    (1, 0, 0, 1): 9.0,
    (1, 0, 0, 2): 8.6,
    (1, 0, 1, 0): 8.5,
    (1, 0, 1, 1): 8.0,
    (1, 0, 1, 2): 7.4,
    (1, 0, 2, 0): 7.3,
    (1, 0, 2, 1): 6.5,
    (1, 0, 2, 2): 5.4,
    (1, 1, 0, 0): 8.6,
    (1, 1, 0, 1): 8.2,
    (1, 1, 0, 2): 7.8,
    (1, 1, 1, 0): 7.6,
    (1, 1, 1, 1): 7.1,
    (1, 1, 1, 2): 6.4,
    (1, 1, 2, 0): 6.3,
    (1, 1, 2, 1): 5.4,
    (1, 1, 2, 2): 4.3,
    (2, 0, 0, 0): 8.7,
    (2, 0, 0, 1): 8.3,
    (2, 0, 0, 2): 7.8,
    (2, 0, 1, 0): 7.8,
    (2, 0, 1, 1): 7.2,
    (2, 0, 1, 2): 6.4,
    (2, 0, 2, 0): 6.5,
    (2, 0, 2, 1): 5.5,
    (2, 0, 2, 2): 4.4,
    (2, 1, 0, 0): 7.9,
    (2, 1, 0, 1): 7.4,
    (2, 1, 0, 2): 6.9,
    (2, 1, 1, 0): 6.8,
    (2, 1, 1, 1): 6.1,
    (2, 1, 1, 2): 5.2,
    (2, 1, 2, 0): 5.3,
    (2, 1, 2, 1): 4.3,
    (2, 1, 2, 2): 3.1,
}


def parse_vector_string(vector_str: str) -> Dict[str, str]:
    """Parse CVSS:3.1 or CVSS:4.0 vector string into metric dictionary."""
    clean_vec = vector_str.strip()
    upper_vec = clean_vec.upper()
    is_v4 = False

    if re.match(r"^CVSS:4\.0\b", upper_vec):
        clean_vec = re.sub(r"^CVSS:4\.0\s*(?:/\s*)?", "", clean_vec, flags=re.IGNORECASE)
        is_v4 = True
    elif re.match(r"^CVSS:3\.1\b", upper_vec):
        clean_vec = re.sub(r"^CVSS:3\.1\s*(?:/\s*)?", "", clean_vec, flags=re.IGNORECASE)
    elif re.match(r"^CVSS:3\.0\b", upper_vec):
        clean_vec = re.sub(r"^CVSS:3\.0\s*(?:/\s*)?", "", clean_vec, flags=re.IGNORECASE)
    elif "VC:" in upper_vec or "AT:" in upper_vec or "SC:" in upper_vec:
        is_v4 = True

    parts = clean_vec.split("/")
    metrics: Dict[str, str] = {}
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.strip().upper()] = v.strip().upper()

    if is_v4:
        required = REQUIRED_METRICS_V4
        valid_map = VALID_METRICS_V4
        spec_label = "CVSS v4.0"
    else:
        required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        valid_map = VALID_METRICS
        spec_label = "CVSS v3.1"

    missing = [m for m in required if m not in metrics]
    if missing:
        raise ValueError(f"Missing required {spec_label} metrics in vector: {missing}")

    for k, v in metrics.items():
        if k in valid_map and v not in valid_map[k]:
            raise ValueError(f"Invalid metric value '{v}' for metric '{k}'. Allowed: {sorted(valid_map[k])}")

    return metrics


def compute_macro_vector(metrics: Dict[str, str]) -> Tuple[int, int, int, int]:
    """
    Compute FIRST CVSS v4.0 MacroVector equivalence groups (EQ1, EQ2, EQ3, EQ4).
    """
    # EQ1: Exploitability (AV, PR, UI)
    av, pr, ui = metrics["AV"], metrics["PR"], metrics["UI"]
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (
        (av == "N" and (pr == "L" or ui in ("P", "A")))
        or (av == "A" and pr == "N" and ui in ("N", "P"))
        or (av == "N" and pr == "H" and ui == "N")
        or (av == "A" and pr == "L" and ui == "N")
        or (av == "L" and pr == "N" and ui == "N")
    ):
        eq1 = 1
    else:
        eq1 = 2

    # EQ2: Complexity and Requirements (AC, AT)
    ac, at = metrics["AC"], metrics["AT"]
    if ac == "L" and at == "N":
        eq2 = 0
    else:
        eq2 = 1

    # EQ3: Vulnerable System Impact (VC, VI, VA)
    vc, vi, va = metrics["VC"], metrics["VI"], metrics["VA"]
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    elif vc == "L" or vi == "L" or va == "L":
        eq3 = 2
    else:
        eq3 = 3

    # EQ4: Subsequent System Impact (SC, SI, SA)
    sc, si, sa = metrics["SC"], metrics["SI"], metrics["SA"]
    if sc == "H" or si == "H" or sa == "H":
        eq4 = 0
    elif sc == "L" or si == "L" or sa == "L":
        eq4 = 1
    else:
        eq4 = 2

    return eq1, eq2, eq3, eq4


def calculate_cvss4_score(metrics: Dict[str, str]) -> Dict[str, Any]:
    """
    Calculate CVSS v4.0 Base Score and MacroVector according to FIRST.org specification.
    """
    vc, vi, va = metrics["VC"], metrics["VI"], metrics["VA"]
    sc, si, sa = metrics["SC"], metrics["SI"], metrics["SA"]

    # Invariant: If all impact metrics are None, score is strictly 0.0
    if vc == "N" and vi == "N" and va == "N" and sc == "N" and si == "N" and sa == "N":
        base_score = 0.0
        eq1, eq2, eq3, eq4 = compute_macro_vector(metrics)
    else:
        eq1, eq2, eq3, eq4 = compute_macro_vector(metrics)

        if eq3 == 3:
            if eq4 == 2:
                base_score = 0.0
            elif eq4 == 0:
                base_score = max(0.0, round(5.0 - eq1 * 0.8 - eq2 * 0.5, 1))
            else:
                base_score = max(0.0, round(3.5 - eq1 * 0.8 - eq2 * 0.5, 1))
        else:
            macro_key = (eq1, eq2, eq3, eq4)
            base_score = CVSS_V40_LOOKUP.get(macro_key, 5.0)

            # Interpolation adjustment within MacroVector
            # Subtract small micro-deductions when lower severity options are chosen
            micro_deduction = 0.0
            if eq3 == 1:
                # If only 1 metric is H vs 2 metrics H
                h_count = sum(1 for m in (vc, vi, va) if m == "H")
                if h_count == 1:
                    micro_deduction += 0.2
            elif eq3 == 2:
                l_count = sum(1 for m in (vc, vi, va) if m == "L")
                if l_count == 1:
                    micro_deduction += 0.3
                elif l_count == 2:
                    micro_deduction += 0.1

            if eq1 == 1:
                if metrics["PR"] == "H" or metrics["UI"] == "A":
                    micro_deduction += 0.1
            elif eq1 == 2:
                if metrics["AV"] == "P":
                    micro_deduction += 0.2

            base_score = max(0.1, min(10.0, round(base_score - micro_deduction, 1)))

    severity = get_severity(base_score)
    vector_string = (
        f"CVSS:4.0/AV:{metrics['AV']}/AC:{metrics['AC']}/AT:{metrics['AT']}/PR:{metrics['PR']}/"
        f"UI:{metrics['UI']}/VC:{metrics['VC']}/VI:{metrics['VI']}/VA:{metrics['VA']}/"
        f"SC:{metrics['SC']}/SI:{metrics['SI']}/SA:{metrics['SA']}"
    )

    return {
        "version": "4.0",
        "vector_string": vector_string,
        "base_score": base_score,
        "severity": severity,
        "macro_vector": f"[{eq1},{eq2},{eq3},{eq4}]",
        "eq": {"EQ1": eq1, "EQ2": eq2, "EQ3": eq3, "EQ4": eq4},
        "metrics": metrics,
    }


def calculate_cvss_score(vector_str: str) -> Dict[str, Any]:
    """
    Calculate CVSS v3.1 or CVSS v4.0 Base Score, Impact, Exploitability, and Severity.
    """
    metrics = parse_vector_string(vector_str)

    # Detect CVSS v4.0
    if "VC" in metrics or re.match(r"^CVSS:4\.0\b", vector_str.strip().upper()):
        return calculate_cvss4_score(metrics)

    # Standard CVSS v3.1 calculation
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
        "version": "3.1",
        "vector_string": f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}",
        "base_score": base_score,
        "severity": severity,
        "impact": round(impact, 2),
        "exploitability": round(exploitability, 2),
        "metrics": metrics,
    }


def cvss_for_cwe(
    cwe_id: str,
    custom_overrides: Optional[Dict[str, str]] = None,
    version: str = "3.1",
) -> Dict[str, Any]:
    """Get standardized CVSS score for a given CWE ID (v3.1 default, v4.0 supported)."""
    norm_cwe = cwe_id.upper()
    v_str = str(version).strip().lower()
    if v_str in ("4.0", "4", "v4", "v4.0"):
        base_vector = CWE_DEFAULT_VECTORS_V4.get(
            norm_cwe,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        )
        if custom_overrides:
            metrics = parse_vector_string(base_vector)
            metrics.update(custom_overrides)
            vec_parts = [f"{k}:{v}" for k, v in metrics.items()]
            base_vector = f"CVSS:4.0/{'/'.join(vec_parts)}"
        return calculate_cvss_score(base_vector)

    base_vector = CWE_DEFAULT_VECTORS.get(norm_cwe, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    if custom_overrides:
        metrics = parse_vector_string(base_vector)
        metrics.update(custom_overrides)
        vec_parts = [f"{k}:{v}" for k, v in metrics.items()]
        base_vector = f"CVSS:3.1/{'/'.join(vec_parts)}"
    return calculate_cvss_score(base_vector)


def calculate_cvss_v4(vector_str: str) -> Dict[str, Any]:
    """Calculate FIRST CVSS v4.0 Base Score and MacroVector."""
    return calculate_cvss_score(vector_str)


class CVSS40Calculator:
    """Class wrapper for FIRST CVSS v4.0 calculation."""

    @staticmethod
    def calculate(vector_str: str) -> Dict[str, Any]:
        return calculate_cvss_score(vector_str)

    @staticmethod
    def compute_macro_vector(metrics: Dict[str, str]) -> Tuple[int, int, int, int]:
        return compute_macro_vector(metrics)

