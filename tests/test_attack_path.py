"""Unit tests for attack-path reasoning and the Pentesting Task Tree."""

import tempfile
import unittest
from pathlib import Path

from core.attack_path import KILL_CHAIN, PentestingTaskTree, reason


class TestAttackPath(unittest.TestCase):

    def test_reason_places_technique_on_chain(self):
        result = reason(["T1055", "T1082"])
        self.assertTrue(result["success"])
        self.assertGreaterEqual(result["kill_chain_index"], 0)
        self.assertIn(result["kill_chain_position"], KILL_CHAIN)

    def test_reason_suggests_next_steps(self):
        result = reason(["T1055"])
        self.assertTrue(result["likely_next_tactics"])
        self.assertIsInstance(result["candidate_next_techniques"], list)

    def test_reason_handles_empty(self):
        result = reason([])
        self.assertTrue(result["success"])
        self.assertEqual(result["observed_techniques"], [])

    def test_reason_accepts_dicts(self):
        result = reason([{"technique_id": "T1486"}])
        self.assertEqual(result["kill_chain_position"], "Impact")


class TestPentestingTaskTree(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ptt.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_add_and_next_actions(self):
        tree = PentestingTaskTree(goal="Respond to ransomware", path=self.path)
        task = tree.add_task("Collect triage artifacts", role="generation")
        self.assertEqual(task["role"], "generation")
        # The root is the first actionable node until it is started/completed.
        self.assertTrue(any(a["id"] == tree.root_id for a in tree.get_next_actions()))
        tree.update_status(tree.root_id, "active")
        self.assertTrue(any(a["id"] == task["id"] for a in tree.get_next_actions()))

    def test_invalid_role_raises(self):
        tree = PentestingTaskTree()
        with self.assertRaises(ValueError):
            tree.add_task("bad", role="invalid")

    def test_update_status_and_next_gating(self):
        tree = PentestingTaskTree(goal="g")
        parent = tree.add_task("parent", role="reasoning")
        child = tree.add_task("child", role="parsing", parent_id=parent["id"])
        # Child is not yet actionable (parent pending).
        self.assertFalse(any(a["id"] == child["id"] for a in tree.get_next_actions()))
        tree.update_status(parent["id"], "done")
        self.assertTrue(any(a["id"] == child["id"] for a in tree.get_next_actions()))

    def test_save_and_load_roundtrip(self):
        tree = PentestingTaskTree(goal="Investigate", path=self.path)
        tree.add_task("step one", role="reasoning")
        tree.save()
        loaded = PentestingTaskTree.load(self.path)
        self.assertEqual(loaded.goal, "Investigate")
        self.assertEqual(len(loaded.nodes), 2)


if __name__ == "__main__":
    unittest.main()
