"""Unit tests for the 7-Question finding validation gate."""

import unittest

from core.finding_validator import (
    FindingValidator,
    assess_proof,
    build_repro_steps,
    fingerprint_finding,
)


SANITIZED = (
    "import os\n"
    "def read_config(user_path):\n"
    "    safe = os.path.abspath(user_path)\n"
    "    with open(safe) as fh:\n"
    "        return fh.read()\n"
)

RAW = (
    "import os\n"
    "def read_config(user_path):\n"
    "    return open(user_path).read()\n"
)

BASE = {
    "cwe_id": "CWE-22",
    "title": "Path Traversal",
    "file_path": "app.py",
    "line_number": 4,
    "severity": "Critical",
    "cvss_score": 9.1,
    "code_snippet": "open(safe)",
}


class TestFindingValidator(unittest.TestCase):

    def setUp(self):
        self.validator = FindingValidator()

    def test_sanitized_flow_is_suppressed(self):
        result = self.validator.validate(BASE, code=SANITIZED)
        self.assertEqual(result.verdict, "discard")
        self.assertLess(result.confidence, 0.5)

    def test_unsanitized_flow_is_retained(self):
        result = self.validator.validate(dict(BASE, line_number=3), code=RAW)
        self.assertIn(result.verdict, ("submit", "investigate"))

    def test_out_of_scope_file_is_suppressed(self):
        finding = dict(BASE, file_path="vendor/lib/app.py")
        result = self.validator.validate(finding, code=SANITIZED)
        self.assertEqual(result.verdict, "discard")

    def test_constant_only_sink_not_exploitable(self):
        code = (
            "import subprocess\n"
            "def run():\n"
            "    subprocess.run('ls')\n"
        )
        finding = dict(BASE, cwe_id="CWE-78", line_number=3, code_snippet="subprocess.run('ls')")
        result = self.validator.validate(finding, code=code)
        self.assertEqual(result.verdict, "discard")

    def test_validate_many_dedupes_and_orders(self):
        findings = [dict(BASE), dict(BASE), dict(BASE, file_path="other.py")]
        out = self.validator.validate_many(findings)
        # Two identical fingerprints collapse to one.
        self.assertEqual(len(out), 2)

    def test_fingerprint_is_stable(self):
        a = fingerprint_finding(BASE)
        b = fingerprint_finding(dict(BASE))
        self.assertEqual(a, b)
        self.assertNotEqual(a, fingerprint_finding(dict(BASE, file_path="x.py")))

    def test_validate_many_include_discarded(self):
        findings = [dict(BASE)]
        kept = self.validator.validate_many(findings, include_discarded=False)
        allf = self.validator.validate_many(findings, include_discarded=True)
        self.assertGreaterEqual(len(allf), len(kept))


class TestProofBackedValidation(unittest.TestCase):

    def setUp(self):
        self.validator = FindingValidator()
        self.finding = dict(BASE, line_number=3)

    def test_repro_steps_are_generated(self):
        steps = build_repro_steps(self.finding)
        self.assertEqual(len(steps), 4)
        self.assertIn("app.py", steps[0])
        self.assertIn("CWE-22", steps[1])

    def test_assess_proof_classification(self):
        self.assertEqual(assess_proof(None)[0], "absent")
        self.assertEqual(assess_proof({})[0], "absent")
        self.assertEqual(assess_proof({"replay_steps": ["s"]})[0], "partial")
        self.assertEqual(assess_proof({"evidence": "log line"})[0], "partial")
        status, evidence, steps = assess_proof(
            {"replay_steps": ["s1", "s2"], "evidence": ["e1"]}
        )
        self.assertEqual(status, "verified")
        self.assertEqual(evidence, ["e1"])
        self.assertEqual(steps, ["s1", "s2"])

    def test_unproven_finding_cannot_remain_submit(self):
        result = self.validator.validate_with_proof(
            self.finding, code=RAW, proof=None, require_proof=True
        )
        self.assertNotEqual(result.verdict, "submit")
        self.assertEqual(result.proof_status, "absent")
        self.assertTrue(result.repro_steps)
        self.assertLessEqual(result.confidence, 0.55)

    def test_verified_proof_is_recorded(self):
        result = self.validator.validate_with_proof(
            self.finding,
            code=RAW,
            proof={"replay_steps": ["observe sink"], "evidence": ["captured trace"]},
            require_proof=True,
        )
        self.assertEqual(result.proof_status, "verified")
        self.assertEqual(result.evidence, ["captured trace"])
        self.assertIn(result.verdict, ("submit", "investigate", "discard"))

    def test_proof_not_required_preserves_base_verdict(self):
        base = self.validator.validate(self.finding, code=RAW)
        relaxed = self.validator.validate_with_proof(
            self.finding, code=RAW, proof=None, require_proof=False
        )
        self.assertEqual(base.verdict, relaxed.verdict)
        self.assertEqual(relaxed.proof_status, "not-required")

    def test_validate_many_attaches_proof_status(self):
        findings = [dict(BASE, line_number=3)]
        baseline = self.validator.validate_many(findings)
        self.assertTrue(baseline[0]["validation"]["repro_steps"])

        fp = baseline[0]["fingerprint"]
        enforced = self.validator.validate_many(
            findings,
            proof_by_fingerprint={fp: {"replay_steps": ["x"], "evidence": ["y"]}},
            require_proof=True,
        )
        self.assertEqual(enforced[0]["validation"]["proof_status"], "verified")


if __name__ == "__main__":
    unittest.main()
