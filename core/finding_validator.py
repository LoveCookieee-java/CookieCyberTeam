"""
Finding Validation Gate (7-Question Gate).

A deterministic, pure-stdlib triage layer inspired by bug-bounty finding
validation discipline: before a static-analysis finding is trusted, it must
survive seven falsifiable questions about reachability, taint provenance,
sanitization, context, novelty, exploitability, and scope.

This gate exists to suppress theoretical false positives (for example a
``Path.read_bytes()`` call on a local variable reported as CWE-22 at CVSS 9.1)
without weakening genuine detections. It never mutates a finding; it only
attaches a verdict (``submit`` / ``investigate`` / ``discard``), a confidence
score, and per-question answers.

Zero external dependencies (Python stdlib only).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Taint sources and sanitizers (defensive reference tables)
# ---------------------------------------------------------------------------

#: Conservative substrings that mark a value as potentially attacker-controlled.
TAINT_SOURCE_TOKENS: Tuple[str, ...] = (
    "request", "req.", "req_", "args", "argv", "kwargs", "input", "stdin",
    "environ", "getenv", "form", "query", "params", "body", "payload",
    "user", "untrusted", "external", "remote", "raw", "filename", "filepath",
    "url", "uri", "cmd", "command", "host", "header", "cookie", "session",
    "token", "json.loads", "get_data", "get_json", "get_param", "querystring",
)

#: Sanitizers grouped by the sink category they neutralise.
SQL_SANITIZER_TOKENS: Tuple[str, ...] = (
    "parameterized", "placeholders", "?", "executemany", "filter(", "filter_by(",
    "where(", "orm", "quote(", "escape(", "?", "%s", "named_param",
)
COMMAND_SANITIZER_TOKENS: Tuple[str, ...] = (
    "shlex.quote", "quote(", "shell=false", "allowlist", "whitelist",
    "subprocess.run([", "subprocess.call([", "popen([", "check_output([",
)
PATH_SANITIZER_TOKENS: Tuple[str, ...] = (
    "os.path.abspath", "os.path.normpath", "os.path.realpath", "os.path.basename",
    "path.resolve", "secure_filename", "sanitize", "safe_join", ".name",
    ".resolve()", "startswith(", "is_relative_to(", "allowed_", "allow_list",
)
EVAL_SANITIZER_TOKENS: Tuple[str, ...] = (
    "literal_eval", "safe_eval", "ast.literal_eval", "allowlist", "whitelist",
)
DESERIALIZE_SANITIZER_TOKENS: Tuple[str, ...] = (
    "safe_load", "safe_dump", "json.loads", "json.load", "yaml.safe_load",
    "defusedxml", "trusted", "signed", "hmac",
)
SSRF_SANITIZER_TOKENS: Tuple[str, ...] = (
    "allowlist", "whitelist", "argparse", "urlparse", "validate_url", "is_safe",
)

#: Map a CWE id to the sanitizer table that neutralises it.
SANITIZER_TABLE_BY_CWE: Dict[str, Tuple[str, ...]] = {
    "CWE-89": SQL_SANITIZER_TOKENS,
    "CWE-78": COMMAND_SANITIZER_TOKENS,
    "CWE-22": PATH_SANITIZER_TOKENS,
    "CWE-95": EVAL_SANITIZER_TOKENS,
    "CWE-502": DESERIALIZE_SANITIZER_TOKENS,
    "CWE-918": SSRF_SANITIZER_TOKENS,
    "CWE-943": SQL_SANITIZER_TOKENS,
}

#: File-name / path fragments that indicate non-production or out-of-scope code.
OUT_OF_SCOPE_TOKENS: Tuple[str, ...] = (
    "/vendor/", "/node_modules/", "/.git/", "/dist/", "/build/", "/__pycache__/",
    "/migrations/", "/generated/", "_pb2.py", ".min.js", "/third_party/",
    "/site-packages/", "/tests/fixtures/", "/examples/",
)


@dataclass
class GateQuestion:
    """A single falsifiable validation question and its deterministic answer."""

    id: str
    question: str
    answer: str  # "yes" | "no" | "unknown"
    weight: float
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "question": self.question,
            "answer": self.answer,
            "weight": self.weight,
            "detail": self.detail,
        }


@dataclass
class ValidationResult:
    """Outcome of applying the 7-Question Gate to one finding."""

    verdict: str  # "submit" | "investigate" | "discard"
    confidence: float  # 0.0 - 1.0
    score: float
    questions: List[GateQuestion] = field(default_factory=list)
    fingerprint: str = ""
    reason: str = ""
    #: Proof lifecycle: not-required | absent | partial | verified.
    proof_status: str = "not-required"
    repro_steps: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "score": round(self.score, 4),
            "fingerprint": self.fingerprint,
            "reason": self.reason,
            "proof_status": self.proof_status,
            "repro_steps": list(self.repro_steps),
            "evidence": list(self.evidence),
            "questions": [q.to_dict() for q in self.questions],
        }


def _as_dict(finding: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
    """Normalise a Finding object or dict into a plain dictionary."""
    if isinstance(finding, dict):
        return finding
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return {
        "cwe_id": getattr(finding, "cwe_id", ""),
        "title": getattr(finding, "title", ""),
        "description": getattr(finding, "description", ""),
        "file_path": getattr(finding, "file_path", ""),
        "line_number": getattr(finding, "line_number", 0),
        "severity": getattr(finding, "severity", ""),
        "cvss_score": getattr(finding, "cvss_score", 0.0),
        "code_snippet": getattr(finding, "code_snippet", ""),
    }


def fingerprint_finding(finding: Union[Dict[str, Any], Any]) -> str:
    """
    Build a stable, content-addressed fingerprint for deduplication.

    Two findings with the same sink, CWE, and normalised evidence collapse to
    the same fingerprint regardless of line drift.
    """
    import hashlib

    d = _as_dict(finding)
    snippet = (d.get("code_snippet") or "").strip()
    # Normalise whitespace so minor reformatting does not create duplicates.
    normalised = re.sub(r"\s+", " ", snippet)
    basis = "|".join(
        [
            str(d.get("cwe_id", "")),
            str(d.get("file_path", "")),
            normalised,
        ]
    )
    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()[:16]


def _contains_any(text: str, tokens: Sequence[str]) -> Optional[str]:
    """Return the first token found in text (case-insensitive) or None."""
    low = text.lower()
    for tok in tokens:
        if tok.lower() in low:
            return tok
    return None


def _snippet_window(code: str, line_number: int, radius: int = 12) -> str:
    """Return a window of source lines around a finding's line number."""
    if not code:
        return ""
    lines = code.splitlines()
    if not lines:
        return ""
    idx = max(0, min(len(lines) - 1, (line_number or 1) - 1))
    start = max(0, idx - radius)
    end = min(len(lines), idx + radius + 1)
    return "\n".join(lines[start:end])


def _collect_call_names(tree: ast.AST) -> List[str]:
    """Collect dotted call names (e.g. 'os.path.abspath') from an AST."""
    names: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            parts: List[str] = []
            while isinstance(func, ast.Attribute):
                parts.append(func.attr)
                func = func.value
            if isinstance(func, ast.Name):
                parts.append(func.id)
            if parts:
                names.append(".".join(reversed(parts)))
    return names


#: Minimum reproducible-evidence expectations before a finding is treated as
#: proven rather than asserted.
PROOF_STATUSES = ("not-required", "absent", "partial", "verified")


def build_repro_steps(finding: Union[Dict[str, Any], Any]) -> List[str]:
    """
    Derive deterministic, non-destructive replay steps for a finding.

    These describe how to *re-observe* the static flow, never how to exploit it,
    and are attached to every validation result so reports carry a reproduction
    spine even when no explicit proof was supplied.
    """
    d = _as_dict(finding)
    cwe = d.get("cwe_id") or "the weakness"
    return [
        f"1. Locate the reported sink at {d.get('file_path', '<unknown>')}:{d.get('line_number', 0)}.",
        f"2. Trace the data path from an attacker-controlled source into the sink ({cwe}); "
        "confirm no sanitizer or parameterisation intervenes.",
        "3. Record the minimal, non-destructive input that exercises the flow and capture the evidence.",
        "4. Re-run mcp_scan_vulnerabilities and mcp_validate_finding to confirm the finding is stable.",
    ]


def assess_proof(proof: Optional[Dict[str, Any]]) -> Tuple[str, List[str], List[str]]:
    """
    Classify supplied proof into (status, evidence, replay_steps).

    ``verified`` requires both replay steps and at least one piece of evidence;
    evidence alone or steps alone is ``partial``; nothing is ``absent``.
    """
    if not proof:
        return "absent", [], []
    evidence_raw = proof.get("evidence")
    if isinstance(evidence_raw, str):
        evidence = [evidence_raw] if evidence_raw.strip() else []
    elif isinstance(evidence_raw, (list, tuple)):
        evidence = [str(e) for e in evidence_raw if str(e).strip()]
    elif evidence_raw:
        evidence = [str(evidence_raw)]
    else:
        evidence = []

    steps_raw = proof.get("replay_steps") or proof.get("steps") or []
    if isinstance(steps_raw, str):
        steps = [steps_raw] if steps_raw.strip() else []
    else:
        steps = [str(s) for s in steps_raw if str(s).strip()]

    if steps and evidence:
        return "verified", evidence, steps
    if steps or evidence:
        return "partial", evidence, steps
    return "absent", [], []


class FindingValidator:
    """
    Applies the 7-Question Gate to static-analysis findings.

    The gate is intentionally conservative: it only discards a finding when a
    *positive* neutraliser is observed (a sanitizer on the path, a clearly
    out-of-scope file, or a syntactically-constant benchmark). Ambiguous cases
    are downgraded to ``investigate`` rather than silently dropped.
    """

    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = workspace_root

    # -- individual questions -------------------------------------------------

    def _q1_reachable(self, d: Dict[str, Any], code: str) -> GateQuestion:
        """Q1: Is the sink inside executable code that is plausibly invoked?"""
        if not code:
            return GateQuestion("q1_reachable", "Is the sink reachable?", "unknown", 0.5,
                                "No source context available.")
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return GateQuestion("q1_reachable", "Is the sink reachable?", "unknown", 0.5,
                                "Source did not parse cleanly.")
        functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if not functions:
            # Module-level code always executes on import.
            return GateQuestion("q1_reachable", "Is the sink reachable?", "yes", 0.5,
                                "Sink is at module scope; executes on import.")
        line = d.get("line_number") or 0
        enclosing = None
        for fn in functions:
            if fn.lineno <= line <= (getattr(fn, "end_lineno", fn.lineno) or fn.lineno):
                enclosing = fn
                break
        if enclosing is None:
            return GateQuestion("q1_reachable", "Is the sink reachable?", "yes", 0.5,
                                "Sink is at module/class scope.")
        module_names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        called = any(call.startswith(enclosing.name) for call in _collect_call_names(tree))
        if enclosing.name.startswith("__") or called or enclosing.name in module_names:
            return GateQuestion("q1_reachable", "Is the sink reachable?", "yes", 0.5,
                                f"Sink lives in function '{enclosing.name}', which is referenced.")
        return GateQuestion("q1_reachable", "Is the sink reachable?", "unknown", 0.5,
                            f"Function '{enclosing.name}' has no obvious caller in this module.")

    def _q2_tainted_source(self, d: Dict[str, Any], window: str) -> GateQuestion:
        """Q2: Does the data reaching the sink derive from an untrusted source?"""
        tok = _contains_any(window, TAINT_SOURCE_TOKENS)
        if tok:
            return GateQuestion("q2_tainted_source", "Is the source attacker-controlled?", "yes", 1.0,
                                f"Taint-like identifier '{tok}' present near the sink.")
        return GateQuestion("q2_tainted_source", "Is the source attacker-controlled?", "unknown", 1.0,
                            "No recognised attacker-controlled source observed near the sink.")

    def _q3_sanitized(self, d: Dict[str, Any], window: str) -> GateQuestion:
        """Q3: Is the tainted value neutralised by a sanitizer before the sink?"""
        cwe = str(d.get("cwe_id", ""))
        table = SANITIZER_TABLE_BY_CWE.get(cwe)
        if not table:
            return GateQuestion("q3_sanitized", "Is the flow sanitized?", "unknown", 1.0,
                                f"No sanitizer table for {cwe}.")
        tok = _contains_any(window, table)
        if tok:
            return GateQuestion("q3_sanitized", "Is the flow sanitized?", "yes", 1.0,
                                f"Neutralising construct '{tok}' observed on the path.")
        return GateQuestion("q3_sanitized", "Is the flow sanitized?", "unknown", 1.0,
                            "No recognised sanitizer on the taint path.")

    def _q4_context(self, d: Dict[str, Any], code: str) -> GateQuestion:
        """Q4: Is the finding in genuine production code (not a docstring/comment)?"""
        line = d.get("line_number") or 0
        lines = code.splitlines() if code else []
        if 0 < line <= len(lines):
            stripped = lines[line - 1].strip()
            if stripped.startswith("#") or stripped.startswith('"""') and stripped.endswith('"""'):
                return GateQuestion("q4_context", "Is this production code?", "no", 0.5,
                                    "Sink appears inside a comment or docstring.")
        return GateQuestion("q4_context", "Is this production code?", "yes", 0.5,
                            "Finding sits in executable source.")

    def _q5_novel(self, d: Dict[str, Any]) -> GateQuestion:
        """Q5: Was the finding introduced by the change under review?"""
        introduced = d.get("introduced")
        if introduced is True:
            return GateQuestion("q5_novel", "Is the issue newly introduced?", "yes", 0.5,
                                "Marked as newly introduced by delta scan.")
        if introduced is False:
            return GateQuestion("q5_novel", "Is the issue newly introduced?", "no", 0.5,
                                "Pre-existing finding, not introduced by this change.")
        return GateQuestion("q5_novel", "Is the issue newly introduced?", "unknown", 0.5,
                            "Novelty not asserted by the caller.")

    def _q6_exploitable(self, d: Dict[str, Any], window: str) -> GateQuestion:
        """Q6: Is there a plausible, non-theoretical exploit path?"""
        cwe = str(d.get("cwe_id", ""))
        # A sink invoked entirely with literals cannot be driven by input.
        literal_only = bool(re.search(r"\(\s*(['\"][^'\"]*['\"]|\d+)\s*\)", window))
        tok = _contains_any(window, TAINT_SOURCE_TOKENS)
        if tok:
            return GateQuestion("q6_exploitable", "Is there a plausible exploit path?", "yes", 1.0,
                                "Attacker-controlled value flows into the sink.")
        if literal_only:
            return GateQuestion("q6_exploitable", "Is there a plausible exploit path?", "no", 1.0,
                                "Sink is invoked with constant arguments only.")
        if cwe in ("CWE-798", "CWE-327", "CWE-328", "CWE-295"):
            # These are configuration/weakness findings; exploitability is indirect.
            return GateQuestion("q6_exploitable", "Is there a plausible exploit path?", "unknown", 0.5,
                                "Weakness is a hygiene issue rather than a direct sink.")
        return GateQuestion("q6_exploitable", "Is there a plausible exploit path?", "unknown", 1.0,
                            "No attacker-controlled value observed at the sink.")

    def _q7_in_scope(self, d: Dict[str, Any]) -> GateQuestion:
        """Q7: Is the file within the assessed scope?"""
        path = "/" + str(d.get("file_path", "")).replace("\\", "/").lstrip("/")
        for tok in OUT_OF_SCOPE_TOKENS:
            if tok in path:
                return GateQuestion("q7_in_scope", "Is the file in scope?", "no", 0.5,
                                    f"Path matches out-of-scope marker '{tok}'.")
        return GateQuestion("q7_in_scope", "Is the file in scope?", "yes", 0.5,
                            "Path is within the assessed source tree.")

    # -- aggregate ------------------------------------------------------------

    def validate(
        self,
        finding: Union[Dict[str, Any], Any],
        code: str = "",
        line_number: Optional[int] = None,
    ) -> ValidationResult:
        """Apply all seven questions and produce a verdict."""
        d = _as_dict(finding)
        if line_number is not None:
            d["line_number"] = line_number
        window = _snippet_window(code, d.get("line_number") or 1)
        questions = [
            self._q1_reachable(d, code),
            self._q2_tainted_source(d, window),
            self._q3_sanitized(d, window),
            self._q4_context(d, code),
            self._q5_novel(d),
            self._q6_exploitable(d, window),
            self._q7_in_scope(d),
        ]
        by_id = {q.id: q for q in questions}

        # Hard neutralisers: any one is sufficient to discard.
        if by_id["q7_in_scope"].answer == "no":
            return self._verdict("discard", 0.1, questions, "Out-of-scope file.")
        if by_id["q4_context"].answer == "no":
            return self._verdict("discard", 0.1, questions, "Finding is inside a comment/docstring.")
        if by_id["q3_sanitized"].answer == "yes":
            return self._verdict("discard", 0.15, questions,
                                 "A neutralising sanitizer/parameterisation is present on the flow.")

        # Scoring: positive evidence raises confidence.
        score = 0.0
        total = sum(q.weight for q in questions) or 1.0
        for q in questions:
            if q.answer == "yes":
                if q.id in ("q2_tainted_source", "q6_exploitable"):
                    score += q.weight
                elif q.id in ("q1_reachable", "q3_sanitized"):
                    score += 0.0
                else:
                    score += q.weight * 0.5
        score = round(score / total * 2.0, 4)  # normalise toward ~1.0 for strong findings

        if by_id["q2_tainted_source"].answer == "yes" and by_id["q6_exploitable"].answer == "yes":
            verdict = "submit"
            confidence = min(0.95, 0.6 + score * 0.3)
        elif by_id["q3_sanitized"].answer == "yes" or by_id["q6_exploitable"].answer == "no":
            verdict = "discard"
            confidence = 0.2
        else:
            verdict = "investigate"
            confidence = min(0.6, 0.3 + score * 0.2)
        return self._verdict(verdict, confidence, questions, "")

    def validate_with_proof(
        self,
        finding: Union[Dict[str, Any], Any],
        code: str = "",
        proof: Optional[Dict[str, Any]] = None,
        require_proof: bool = True,
        line_number: Optional[int] = None,
    ) -> ValidationResult:
        """
        Validate a finding and fold in reproducible evidence.

        With ``require_proof=True`` a finding cannot remain ``submit`` on
        assertion alone: unproven findings are downgraded to ``investigate`` and
        their confidence is capped, while verified findings gain a small boost.
        The base :meth:`validate` behaviour is untouched.
        """
        result = self.validate(finding, code=code, line_number=line_number)
        d = _as_dict(finding)
        if line_number is not None:
            d["line_number"] = line_number
        return self._apply_proof(result, d, proof, require_proof)

    def _apply_proof(
        self,
        result: ValidationResult,
        d: Dict[str, Any],
        proof: Optional[Dict[str, Any]],
        require_proof: bool,
    ) -> ValidationResult:
        status, evidence, steps = assess_proof(proof)
        result.proof_status = status if require_proof else ("not-required" if not proof else status)
        result.evidence = evidence
        result.repro_steps = steps or build_repro_steps(d)
        if not require_proof:
            return result
        if status == "verified":
            result.confidence = min(1.0, result.confidence + 0.05)
        elif result.verdict == "submit":
            result.verdict = "investigate"
            result.confidence = min(result.confidence, 0.55)
            result.reason = (result.reason + " Proof required but not verified.").strip()
        else:
            result.confidence = min(result.confidence, 0.4)
        return result

    def _verdict(
        self,
        verdict: str,
        confidence: float,
        questions: List[GateQuestion],
        reason: str,
    ) -> ValidationResult:
        return ValidationResult(
            verdict=verdict,
            confidence=max(0.0, min(1.0, confidence)),
            score=sum(q.weight for q in questions if q.answer == "yes"),
            questions=questions,
            reason=reason,
        )

    def validate_many(
        self,
        findings: Sequence[Union[Dict[str, Any], Any]],
        code_by_file: Optional[Dict[str, str]] = None,
        include_discarded: bool = False,
        proof_by_fingerprint: Optional[Dict[str, Dict[str, Any]]] = None,
        require_proof: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Validate a batch of findings, de-duplicating by fingerprint and attaching
        gate output. Discarded findings are excluded unless ``include_discarded``.

        ``proof_by_fingerprint`` optionally supplies reproducible evidence keyed
        by finding fingerprint; with ``require_proof`` an unproven finding can no
        longer remain ``submit``.
        """
        code_by_file = code_by_file or {}
        proof_map = proof_by_fingerprint or {}
        seen: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            d = _as_dict(f)
            code = code_by_file.get(d.get("file_path", ""), "")
            result = self.validate(d, code=code)
            fp = fingerprint_finding(d)
            result.fingerprint = fp
            result = self._apply_proof(result, d, proof_map.get(fp), require_proof)
            entry = dict(d)
            entry["validation"] = result.to_dict()
            entry["fingerprint"] = fp
            entry["validation_verdict"] = result.verdict
            entry["confidence"] = result.confidence
            if result.verdict == "discard" and not include_discarded:
                continue
            # De-duplicate identical fingerprints, keeping the higher confidence.
            if fp in seen:
                if entry["confidence"] > seen[fp]["confidence"]:
                    seen[fp] = entry
                continue
            seen[fp] = entry
        ordered = list(seen.values())
        ordered.sort(key=lambda e: e["confidence"], reverse=True)
        return ordered
