"""Unit tests for the multi-framework security catalog."""

import unittest

from core.framework_catalog import (
    ATTACK_TACTICS,
    ATLAS_TECHNIQUES,
    D3FEND_COUNTERMEASURES,
    F3_TACTICS,
    atlas_for_asi,
    build_coverage_matrix,
    d3fend_for_technique,
    list_frameworks,
    list_tactics,
    map_technique,
    render_frameworks_resource,
    resolve_tactic,
)


class TestAttackTactics(unittest.TestCase):

    def test_tactic_count_and_order(self):
        tactics = list_tactics()
        self.assertGreaterEqual(len(tactics), 15)
        names = [t["name"] for t in tactics]
        self.assertEqual(names[0], "Reconnaissance")
        self.assertEqual(names[-1], "Impact")

    def test_v19_1_stealth_and_defense_impairment_split(self):
        names = {t["name"] for t in ATTACK_TACTICS}
        self.assertIn("Stealth", names)
        self.assertIn("Defense Impairment", names)
        self.assertNotIn("Defense Evasion", names)

    def test_legacy_defense_evasion_resolves_to_stealth(self):
        tactic = resolve_tactic("Defense Evasion")
        self.assertIsNotNone(tactic)
        self.assertEqual(tactic["name"], "Stealth")

    def test_resolve_by_id_and_unknown(self):
        self.assertEqual(resolve_tactic("TA0112")["name"], "Defense Impairment")
        self.assertIsNone(resolve_tactic("not-a-tactic"))


class TestCrossFrameworkMapping(unittest.TestCase):

    def test_d3fend_for_technique(self):
        counters = d3fend_for_technique("T1055")
        self.assertTrue(counters)
        self.assertTrue(all(c["id"].startswith("D3-") for c in counters))
        # Sub-techniques resolve to the base technique's countermeasures.
        self.assertEqual(d3fend_for_technique("T1055.002"), counters)

    def test_map_technique_returns_all_frameworks(self):
        mapping = map_technique("T1055")
        self.assertEqual(mapping["technique_id"], "T1055")
        self.assertTrue(mapping["d3fend"])
        self.assertIn("attack", mapping)
        self.assertIn("nist_csf", mapping)
        self.assertIn("nist_ai_rmf", mapping)
        self.assertIn("f3", mapping)

    def test_atlas_for_asi(self):
        atlas = atlas_for_asi("ASI-01")
        ids = {t["id"] for t in atlas}
        self.assertIn("AML.T0051", ids)

    def test_frameworks_registry(self):
        frameworks = list_frameworks()
        keys = {f["key"] for f in frameworks}
        self.assertEqual(
            keys,
            {"mitre_attack", "mitre_d3fend", "mitre_atlas", "nist_csf", "nist_ai_rmf", "mitre_f3"},
        )

    def test_reference_data_present(self):
        self.assertTrue(D3FEND_COUNTERMEASURES)
        self.assertTrue(ATLAS_TECHNIQUES)
        self.assertEqual({t["id"] for t in F3_TACTICS}, {"FA0001", "FA0002"})


class TestCoverageMatrix(unittest.TestCase):

    def test_matrix_reports_coverage_and_gaps(self):
        entries = [
            {"technique_id": "T1055", "tactic": "Stealth"},
            {"technique_id": "T1071", "tactic": "Command and Control"},
            {"technique_id": "T1071.001", "tactic": "Command and Control"},
            {"technique_id": "NOPE-1"},
        ]
        matrix = build_coverage_matrix(entries)
        self.assertEqual(matrix["distinct_techniques_covered"], 3)
        self.assertIn("NOPE-1", matrix["unmapped_techniques"])
        self.assertEqual(matrix["rules_evaluated"], 4)

        by_tactic = {row["tactic"]: row for row in matrix["matrix"]}
        self.assertEqual(by_tactic["Command and Control"]["coverage_count"], 2)
        self.assertTrue(by_tactic["Stealth"]["covered"])
        self.assertIn("Impact", matrix["gaps"])

    def test_tactic_lookup_map_used_when_tactic_missing(self):
        matrix = build_coverage_matrix(
            [{"technique_id": "T1082"}],
            tactic_by_technique={"T1082": "Discovery"},
        )
        by_tactic = {row["tactic"]: row for row in matrix["matrix"]}
        self.assertTrue(by_tactic["Discovery"]["covered"])

    def test_empty_entries(self):
        matrix = build_coverage_matrix([])
        self.assertEqual(matrix["distinct_techniques_covered"], 0)
        self.assertEqual(matrix["tactics_with_coverage"], 0)


class TestResourceRendering(unittest.TestCase):

    def test_render_contains_all_frameworks(self):
        text = render_frameworks_resource()
        for needle in ("ATT&CK", "D3FEND", "ATLAS", "NIST CSF", "NIST AI RMF", "F3"):
            self.assertIn(needle, text)
        self.assertIn("Defense Impairment", text)


if __name__ == "__main__":
    unittest.main()
