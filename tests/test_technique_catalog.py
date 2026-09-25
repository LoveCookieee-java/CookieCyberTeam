"""Unit tests for the ATT&CK technique signature catalog."""

import unittest

from core.technique_catalog import (
    TECHNIQUE_CATALOG,
    catalog_soc_rules,
    get_technique,
    list_techniques,
    search_techniques,
)
from core.soc_rules import SOCRuleEngine


class TestTechniqueCatalog(unittest.TestCase):

    def test_catalog_is_nonempty(self):
        self.assertGreater(len(TECHNIQUE_CATALOG), 10)

    def test_get_technique_exact_and_sub(self):
        info = get_technique("T1055.002")
        self.assertIsNotNone(info)
        self.assertIn("Injection", info["technique_name"])
        # Base technique resolves to a sub-technique entry.
        self.assertIsNotNone(get_technique("T1055"))

    def test_get_technique_missing(self):
        self.assertIsNone(get_technique("T9999"))

    def test_search_techniques_matches_api(self):
        hits = search_techniques("CreateRemoteThread VirtualAlloc WriteProcessMemory")
        ids = {h["technique_id"] for h in hits}
        self.assertIn("T1055.002", ids)

    def test_list_techniques_by_tactic(self):
        hits = list_techniques(tactic="Defense Evasion")
        self.assertTrue(all(h["tactic"] == "Defense Evasion" for h in hits))
        self.assertGreater(len(hits), 0)

    def test_catalog_soc_rules_register_and_fire(self):
        rules = catalog_soc_rules()
        self.assertGreater(len(rules), 10)
        engine = SOCRuleEngine(initial_rules=rules)
        alerts = engine.evaluate_text("rundll32.exe javascript:alert(1)")
        self.assertTrue(any(a["technique_id"].startswith("T1218") for a in alerts))


if __name__ == "__main__":
    unittest.main()
