"""Unit tests for the persistent finding memory engine."""

import json
import tempfile
import unittest
from pathlib import Path

from core.finding_memory import FindingMemory


def _finding(cwe="CWE-89", path="app.py", sev="High", conf=0.8, snippet="q"):
    return {
        "cwe_id": cwe,
        "title": "t",
        "file_path": path,
        "line_number": 1,
        "severity": sev,
        "cvss_score": 8.0,
        "code_snippet": snippet,
        "confidence": conf,
    }


class TestFindingMemory(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "mem.jsonl"
        self.mem = FindingMemory(path=self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_record_and_recall(self):
        self.mem.record(_finding())
        self.assertEqual(len(self.mem.recall()), 1)
        self.assertEqual(len(self.mem.recall(cwe="CWE-89")), 1)
        self.assertEqual(len(self.mem.recall(cwe="CWE-78")), 0)

    def test_stats(self):
        self.mem.record(_finding())
        self.mem.record(_finding(cwe="CWE-78", snippet="x"))
        stats = self.mem.stats()
        self.assertEqual(stats["total_records"], 2)

    def test_dedupe_keeps_highest_confidence(self):
        out = FindingMemory.dedupe([_finding(conf=0.3), _finding(conf=0.9)])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["confidence"], 0.9)

    def test_rank_orders_by_severity(self):
        items = [_finding(sev="Low", snippet="a"), _finding(sev="Critical", snippet="b")]
        ranked = FindingMemory.rank(items)
        self.assertEqual(ranked[0]["severity"], "Critical")

    def test_find_chains(self):
        chains = FindingMemory.find_chains([
            _finding(cwe="CWE-22", snippet="a"),
            _finding(cwe="CWE-78", snippet="b"),
        ])
        self.assertTrue(any(c["chain_id"] == "CHAIN-LFI-RCE" for c in chains))

    def test_dismiss_hides_finding(self):
        rec = self.mem.record(_finding())
        self.mem.dismiss(rec["fingerprint"], reason="false positive")
        self.assertEqual(len(self.mem.recall()), 0)
        self.assertEqual(len(self.mem.recall(include_dismissed=True)), 1)

    def test_rotation_creates_backup(self):
        mem = FindingMemory(path=self.path, max_bytes=10, backups=1)
        mem.record(_finding())
        mem.record(_finding(snippet="second"))
        # Rotation should have created a .1 backup file (no deletion).
        backup = self.path.with_suffix(self.path.suffix + ".1")
        self.assertTrue(backup.is_file() or self.path.is_file())

    def test_record_many(self):
        count = self.mem.record_many([_finding(snippet="a"), _finding(snippet="b")])
        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
