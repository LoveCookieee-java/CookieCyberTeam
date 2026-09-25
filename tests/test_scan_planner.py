"""Unit tests for the adaptive scan planner."""

import tempfile
import unittest
from pathlib import Path

from core.dag_engine import DAGEngine
from core.scan_planner import ScanPlanner


class TestScanPlanner(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "app.py").write_text("import os\n" * 300, encoding="utf-8")
        (self.root / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
        (self.root / "sample.bin").write_bytes(b"MZ" + b"\x00" * 100)
        self.planner = ScanPlanner(workspace_root=self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_plan_contains_core_tasks(self):
        plan = self.planner.plan()
        kinds = {t["kind"] for t in plan["tasks"]}
        self.assertIn("recon", kinds)
        self.assertIn("sast", kinds)
        self.assertIn("deps", kinds)
        self.assertIn("binary", kinds)
        self.assertIn("aggregate", kinds)

    def test_aggregate_depends_on_leaves(self):
        plan = self.planner.plan()
        agg = next(t for t in plan["tasks"] if t["kind"] == "aggregate")
        self.assertTrue(len(agg["dependencies"]) >= 1)

    def test_seed_dag_creates_tasks(self):
        dag = DAGEngine(db_path=":memory:")
        result = self.planner.seed_dag(dag)
        self.assertEqual(result["total"], result["total"])
        self.assertGreater(result["total"], 3)
        summary = dag.get_dag_summary()
        self.assertEqual(summary["total_tasks"], result["total"])

    def test_max_files_bounds_sast_tasks(self):
        plan = self.planner.plan(max_files=1)
        sast = [t for t in plan["tasks"] if t["kind"] == "sast"]
        self.assertLessEqual(len(sast), 1)


if __name__ == "__main__":
    unittest.main()
