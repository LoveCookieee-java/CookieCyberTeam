"""Unit tests for report bundle building and export."""

import tempfile
import unittest
from pathlib import Path

from core.report_export import (
    build_bundle,
    export_bundle,
    render_bugcrowd_report,
    render_hackerone_report,
    render_markdown_report,
)


def _finding(cwe="CWE-89", path="app.py", sev="High", snippet="q", conf=0.8):
    return {
        "cwe_id": cwe,
        "title": "SQL Injection",
        "description": "Tainted input reaches a SQL sink.",
        "file_path": path,
        "line_number": 10,
        "severity": sev,
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "code_snippet": snippet,
        "remediation": "Parameterize the query.",
        "confidence": conf,
        "fingerprint": f"fp-{cwe}-{snippet}",
    }


class TestReportExport(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name) / "bundle"

    def tearDown(self):
        self.tmp.cleanup()

    def test_markdown_report(self):
        md = render_markdown_report("Title", [_finding()])
        self.assertIn("# Title", md)
        self.assertIn("CWE-89", md)

    def test_hackerone_and_bugcrowd_templates(self):
        h1 = render_hackerone_report(_finding())
        bc = render_bugcrowd_report(_finding())
        self.assertIn("Steps To Reproduce", h1)
        self.assertIn("Proof of Concept", bc)

    def test_build_bundle(self):
        bundle = build_bundle([_finding(), _finding(cwe="CWE-22", snippet="p")])
        self.assertTrue(bundle["success"])
        self.assertEqual(bundle["finding_count"], 2)
        self.assertIn("sarif", bundle)
        self.assertIn("markdown", bundle)
        self.assertTrue(bundle["reports"])

    def test_build_bundle_with_stix_inputs(self):
        bundle = build_bundle([_finding()], stix_inputs=[{
            "sha256": "a" * 64, "md5": "b" * 32, "imphash": "c" * 32,
            "fuzzy_hash": "3:abc:def", "family_matches": [], "techniques": [],
        }])
        self.assertTrue(bundle["stix_bundles"])
        self.assertTrue(bundle["maec_packages"])

    def test_export_bundle_writes_files(self):
        bundle = build_bundle([_finding()])
        result = export_bundle(bundle, self.dest)
        self.assertTrue(result["success"])
        self.assertTrue((self.dest / "report.md").is_file())
        self.assertTrue((self.dest / "findings.sarif").is_file())
        self.assertTrue((self.dest / "findings.json").is_file())
        self.assertTrue((self.dest / "submissions").is_dir())

    def test_export_bundle_neutralises_path_separators_in_cwe_id(self):
        """
        Submission filenames derive from finding fields that callers can supply.

        A separator-bearing cwe_id used to raise FileNotFoundError mid-export, after
        the top-level report files had already been written.
        """
        bundle = build_bundle([_finding(cwe="../nested/CWE-78")])
        result = export_bundle(bundle, self.dest)
        self.assertTrue(result["success"])

        written = sorted(p.name for p in (self.dest / "submissions").glob("*.md"))
        self.assertEqual(len(written), 2)
        for name in written:
            self.assertNotIn("/", name)
            self.assertNotIn("..", name)
        self.assertTrue(all(p.is_file() for p in (self.dest / "submissions").iterdir()))

    def test_export_bundle_handles_missing_cwe_id(self):
        bundle = build_bundle([_finding(cwe="")])
        result = export_bundle(bundle, self.dest)
        self.assertTrue(result["success"])
        self.assertTrue(any("finding" in p.name for p in (self.dest / "submissions").iterdir()))


if __name__ == "__main__":
    unittest.main()
