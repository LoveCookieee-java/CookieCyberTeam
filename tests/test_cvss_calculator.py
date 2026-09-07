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

    def test_cvss_v40_max_critical_vector(self):
        """Test CVSS v4.0 maximum critical vector (10.0 Critical, EQ [0,0,0,0])."""
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        res = calculate_cvss_score(vec)
        self.assertEqual(res["version"], "4.0")
        self.assertEqual(res["base_score"], 10.0)
        self.assertEqual(res["severity"], "Critical")
        self.assertEqual(res["macro_vector"], "[0,0,0,0]")
        self.assertEqual(res["eq"]["EQ1"], 0)
        self.assertEqual(res["eq"]["EQ2"], 0)

    def test_cvss_v40_unauthenticated_rce_vector(self):
        """Test CVSS v4.0 network RCE vector with scope unchanged/subsequent none (9.3 Critical)."""
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        res = calculate_cvss_score(vec)
        self.assertEqual(res["version"], "4.0")
        self.assertEqual(res["base_score"], 9.3)
        self.assertEqual(res["severity"], "Critical")
        self.assertEqual(res["macro_vector"], "[0,0,0,2]")

    def test_cvss_v40_zero_impact_vector(self):
        """Test CVSS v4.0 vector with zero impact returns 0.0 None."""
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        res = calculate_cvss_score(vec)
        self.assertEqual(res["base_score"], 0.0)
        self.assertEqual(res["severity"], "None")

    def test_cvss_v40_validation_errors(self):
        """Verify CVSS v4.0 raises ValueError on missing metrics or invalid values."""
        # Missing AT and subsequent metrics
        with self.assertRaises(ValueError):
            parse_vector_string("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H")
        # Invalid UI value (X not in N, P, A)
        with self.assertRaises(ValueError):
            parse_vector_string("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:X/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")

    def test_new_cwe_default_vectors(self):
        """Verify default CVSS vectors for CWE-22, CWE-327, CWE-328, CWE-377, CWE-352."""
        r_cwe22 = cvss_for_cwe("CWE-22")
        self.assertEqual(r_cwe22["base_score"], 9.1)
        self.assertEqual(r_cwe22["severity"], "Critical")

        r_cwe327 = cvss_for_cwe("CWE-327")
        self.assertEqual(r_cwe327["base_score"], 7.5)
        self.assertEqual(r_cwe327["severity"], "High")

        r_cwe328 = cvss_for_cwe("CWE-328")
        self.assertEqual(r_cwe328["base_score"], 7.5)

        r_cwe377 = cvss_for_cwe("CWE-377")
        self.assertEqual(r_cwe377["base_score"], 4.0)
        self.assertEqual(r_cwe377["severity"], "Medium")

        r_cwe352 = cvss_for_cwe("CWE-352")
        self.assertEqual(r_cwe352["base_score"], 6.5)
        self.assertEqual(r_cwe352["severity"], "Medium")

        # Test CVSS v4.0 mode for CWE-78
        r_cwe78_v4 = cvss_for_cwe("CWE-78", version="4.0")
        self.assertEqual(r_cwe78_v4["version"], "4.0")
        self.assertEqual(r_cwe78_v4["base_score"], 9.3)


    def test_vector_whitespace_resilience(self):
        """Verify vector parser tolerates spaces around metrics and colons."""
        vec = " CVSS:3.1 / AV : N / AC : L / PR : N / UI : N / S : U / C : H / I : H / A : H "
        res = calculate_cvss_score(vec)
        self.assertEqual(res["base_score"], 9.8)

        vec_v4 = " CVSS:4.0 / AV : N / AC : L / AT : N / PR : N / UI : N / VC : H / VI : H / VA : H / SC : N / SI : N / SA : N "
        res_v4 = calculate_cvss_score(vec_v4)
        self.assertEqual(res_v4["base_score"], 9.3)

    def test_cvss_for_cwe_v4_custom_overrides(self):
        """Verify cvss_for_cwe with version='4.0' and custom overrides."""
        res = cvss_for_cwe("CWE-78", custom_overrides={"PR": "H"}, version="4.0")
        self.assertEqual(res["version"], "4.0")
        self.assertEqual(res["metrics"]["PR"], "H")
        self.assertLess(res["base_score"], 9.3)


    def test_cvss_for_cwe_version_string_variants(self):
        """Verify cvss_for_cwe accepts '4', 'v4', and 'v4.0' as valid CVSS v4.0 selectors."""
        for v in ("4", "v4", "v4.0", "4.0"):
            res = cvss_for_cwe("CWE-78", version=v)
            self.assertEqual(res["version"], "4.0", f"Failed for version='{v}'")
            self.assertEqual(res["base_score"], 9.3)


if __name__ == "__main__":
    unittest.main()
