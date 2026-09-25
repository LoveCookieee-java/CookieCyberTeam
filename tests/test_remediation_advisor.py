"""Unit tests for the offline remediation advisor."""

import unittest

from core.remediation_advisor import advisory_for, enrich_vulnerabilities


class TestRemediationAdvisor(unittest.TestCase):

    def test_curated_cve_advisory(self):
        adv = advisory_for(
            cve_id="CVE-2023-32681",
            package="requests",
            severity="High",
            cvss_score=7.5,
            summary="Proxy-Authorization Header Leak",
            fixed_in="2.31.0",
        )
        self.assertEqual(adv["urgency"], "urgent")
        self.assertIn("proxy", adv["exposure"].lower())
        self.assertTrue(any("Upgrade requests" in r for r in adv["remediation"]))

    def test_keyword_fallback(self):
        adv = advisory_for(
            cve_id="CVE-0000-0000",
            package="somezip",
            severity="Medium",
            cvss_score=5.0,
            summary="Zip archive path traversal",
        )
        self.assertIn("traversal", adv["exposure"].lower())

    def test_urgency_tiers(self):
        self.assertEqual(advisory_for(severity="Critical", cvss_score=9.5)["urgency"], "immediate")
        self.assertEqual(advisory_for(severity="Low", cvss_score=2.0)["urgency"], "monitor")

    def test_enrich_vulnerabilities(self):
        enriched = enrich_vulnerabilities([{
            "package_name": "requests", "cve_id": "CVE-2023-32681",
            "severity": "High", "cvss_score": 7.5, "summary": "x", "fixed_in": "2.31.0",
        }])
        self.assertIn("advisory", enriched[0])


if __name__ == "__main__":
    unittest.main()
