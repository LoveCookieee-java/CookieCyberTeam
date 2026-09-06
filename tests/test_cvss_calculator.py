"""
Unit tests for FIRST.org CVSS v3.1 Calculator.
"""

import unittest
from core.cvss_calculator import (
    calculate_cvss_score,
    cvss_for_cwe,
    cvss_roundup,
    get_severity,
    parse_vector_string,
)


class TestCVSSCalculator(unittest.TestCase):

    def test_cvss_roundup_edge_cases(self):
        """Verify FIRST.org standard roundup behavior and floating precision."""
        self.assertEqual(cvss_roundup(4.02), 4.1)
        self.assertEqual(cvss_roundup(4.00), 4.0)
        self.assertEqual(cvss_roundup(0.0), 0.0)
        self.assertEqual(cvss_roundup(9.760377), 9.8)
        self.assertEqual(cvss_roundup(7.41), 7.5)

    def test_first_standard_critical_vector(self):
        """Test standard Network unauthenticated RCE/Critical vector (CVSS 9.8)."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        res = calculate_cvss_score(vec)
        self.assertEqual(res["base_score"], 9.8)
        self.assertEqual(res["severity"], "Critical")
        self.assertEqual(res["metrics"]["AV"], "N")
        self.assertEqual(res["metrics"]["S"], "U")

    def test_first_standard_scope_changed_vector(self):
        """Test Scope Changed (S:C) maximum critical vector (CVSS 10.0)."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        res = calculate_cvss_score(vec)
        self.assertEqual(res["base_score"], 10.0)
        self.assertEqual(res["severity"], "Critical")

    def test_first_medium_vector(self):
        """Test local low privilege vector (CVSS 5.3 Medium)."""
        vec = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        res = calculate_cvss_score(vec)
        self.assertEqual(res["base_score"], 5.3)
        self.assertEqual(res["severity"], "Medium")

    def test_zero_impact_vector(self):
        """Test vector where Confidentiality, Integrity, and Availability are None."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        res = calculate_cvss_score(vec)
        self.assertEqual(res["base_score"], 0.0)
        self.assertEqual(res["severity"], "None")

    def test_cvss_for_cwe_mapping(self):
        """Test standardized CWE mappings."""
        r_cwe78 = cvss_for_cwe("CWE-78")
        self.assertEqual(r_cwe78["base_score"], 9.8)
        self.assertEqual(r_cwe78["severity"], "Critical")

        r_cwe89 = cvss_for_cwe("CWE-89")
        self.assertEqual(r_cwe89["base_score"], 9.8)

        r_cwe798 = cvss_for_cwe("CWE-798")
        self.assertEqual(r_cwe798["base_score"], 7.5)
        self.assertEqual(r_cwe798["severity"], "High")

        r_cwe295 = cvss_for_cwe("CWE-295")
        self.assertEqual(r_cwe295["base_score"], 7.4)
        self.assertEqual(r_cwe295["severity"], "High")

    def test_invalid_vector_raises(self):
        """Missing required metric keys should raise ValueError."""
        with self.assertRaises(ValueError):
            parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N")

    def test_invalid_metric_value_raises(self):
        """Unrecognized metric values must raise ValueError."""
        with self.assertRaises(ValueError):
            parse_vector_string("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_case_insensitive_prefix_parsing(self):
        """Prefix and vector values should parse case-insensitively."""
        vec = "cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h"
        res = calculate_cvss_score(vec)
        self.assertEqual(res["base_score"], 9.8)


if __name__ == "__main__":
    unittest.main()
