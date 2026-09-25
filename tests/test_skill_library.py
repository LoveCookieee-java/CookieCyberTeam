"""Unit tests for the Agent Skills (SKILL.md) knowledge library."""

import tempfile
import unittest
from pathlib import Path

from core.skill_library import (
    DOMAIN_TAXONOMY,
    SKILL_NAME_RE,
    SkillLibrary,
    parse_frontmatter,
    parse_skill_file,
    parse_skill_text,
    split_frontmatter,
    validate_skill,
)


VALID_SKILL = """---
name: analyzing-network-traffic-of-malware
description: Analyzes network traffic of malware. Use when investigating C2 beaconing.
license: Apache-2.0
compatibility: Designed for Claude Code
allowed-tools: Bash(tcpdump:*) Read
metadata:
  author: example-org
  version: "1.0"
  domain: dfir
mitre_attack:
  - T1071
  - T1071.001
nist_csf: [DE.CM, DE.AE]
mitre_atlas: AML.T0047
mitre_d3fend: D3-NTA
---

# Analyzing Network Traffic

Step one.
Step two.
"""


class TestFrontmatterParsing(unittest.TestCase):

    def test_split_frontmatter_ok(self):
        frontmatter, body, error = split_frontmatter(VALID_SKILL)
        self.assertEqual(error, "")
        self.assertIn("name:", frontmatter)
        self.assertIn("Analyzing Network Traffic", body)

    def test_split_frontmatter_missing(self):
        frontmatter, _body, error = split_frontmatter("# No frontmatter here\n")
        self.assertIsNone(frontmatter)
        self.assertIn("missing", error)

    def test_split_frontmatter_unterminated(self):
        frontmatter, _body, error = split_frontmatter("---\nname: x\n")
        self.assertIsNone(frontmatter)
        self.assertIn("unterminated", error)

    def test_parse_frontmatter_nested_and_inline(self):
        frontmatter, _body, _err = split_frontmatter(VALID_SKILL)
        data = parse_frontmatter(frontmatter)
        self.assertEqual(data["name"], "analyzing-network-traffic-of-malware")
        self.assertEqual(data["metadata"]["version"], "1.0")
        self.assertEqual(data["mitre_attack"], ["T1071", "T1071.001"])
        self.assertEqual(data["nist_csf"], ["DE.CM", "DE.AE"])

    def test_parse_frontmatter_block_scalar(self):
        data = parse_frontmatter("description: >\n  First part.\n  Second part.\n")
        self.assertEqual(data["description"], "First part. Second part.")


class TestSkillRecord(unittest.TestCase):

    def test_parse_skill_text_success(self):
        record = parse_skill_text(
            VALID_SKILL,
            path="x/SKILL.md",
            directory_name="analyzing-network-traffic-of-malware",
        )
        self.assertEqual(record.issues, [])
        self.assertEqual(record.license, "Apache-2.0")
        self.assertEqual(record.domain, "dfir")
        self.assertIn("Bash(tcpdump:*)", record.allowed_tools)
        self.assertIn("MITRE ATT&CK", record.frameworks)
        self.assertIn("T1071", record.frameworks["MITRE ATT&CK"])
        self.assertIn("NIST CSF 2.0", record.frameworks)
        self.assertGreater(record.body_lines, 0)

    def test_parse_skill_text_missing_frontmatter_is_invalid(self):
        record = parse_skill_text("no frontmatter", path="bad/SKILL.md")
        self.assertTrue(record.issues)

    def test_name_must_match_directory(self):
        record = parse_skill_text(VALID_SKILL, path="y/SKILL.md", directory_name="other-name")
        self.assertTrue(any("parent directory" in issue for issue in record.issues))

    def test_validate_skill_rules(self):
        self.assertEqual(validate_skill("good-name", "A description.", "good-name"), [])
        self.assertTrue(any("lowercase" in i for i in validate_skill("Bad_Name", "d", "")))
        self.assertTrue(any("missing required 'description'" in i for i in validate_skill("n", "")))
        self.assertTrue(any("hyphens" in i for i in validate_skill("bad--name", "d")))
        self.assertTrue(any("64" in i for i in validate_skill("x" * 65, "d")))

    def test_name_regex(self):
        self.assertTrue(SKILL_NAME_RE.match("log-analysis"))
        self.assertIsNone(SKILL_NAME_RE.match("-leading"))
        self.assertIsNone(SKILL_NAME_RE.match("trailing-"))

    def test_domain_taxonomy_nonempty(self):
        self.assertGreater(len(DOMAIN_TAXONOMY), 20)
        self.assertIn("dfir", DOMAIN_TAXONOMY)


class TestSkillLibrary(unittest.TestCase):

    def _write_tree(self, root: Path):
        first = root / "analyzing-network-traffic-of-malware"
        first.mkdir(parents=True)
        (first / "SKILL.md").write_text(VALID_SKILL, encoding="utf-8")

        second = root / "detecting-business-email-compromise"
        second.mkdir(parents=True)
        (second / "SKILL.md").write_text(
            "---\n"
            "name: detecting-business-email-compromise\n"
            "description: Detects business email compromise. Use when triaging account takeover.\n"
            "metadata:\n"
            "  domain: threat-hunting\n"
            "mitre_attack: T1566\n"
            "---\n"
            "# Body\n",
            encoding="utf-8",
        )

        invalid = root / "broken"
        invalid.mkdir(parents=True)
        (invalid / "SKILL.md").write_text("no frontmatter at all\n", encoding="utf-8")

    def test_load_from_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_tree(root)
            library = SkillLibrary.load(root)
            stats = library.stats()
            self.assertEqual(stats["total_skills"], 3)
            self.assertEqual(stats["valid_skills"], 2)
            self.assertEqual(stats["invalid_skills"], 1)
            self.assertIn("dfir", stats["domains"])
            self.assertIn("MITRE ATT&CK", stats["framework_counts"])

    def test_load_missing_root_degrades(self):
        library = SkillLibrary.load(Path("definitely-not-here-12345"))
        self.assertEqual(library.stats()["total_skills"], 0)

    def test_search_by_query_and_framework(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_tree(root)
            library = SkillLibrary.load(root)

            hits = library.search(query="network traffic")
            self.assertTrue(hits)
            self.assertEqual(hits[0]["name"], "analyzing-network-traffic-of-malware")

            fw_hits = library.search(framework="MITRE ATT&CK")
            self.assertEqual(len(fw_hits), 2)

            dom_hits = library.search(domain="threat-hunting")
            self.assertEqual(len(dom_hits), 1)

    def test_search_ranks_name_match_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_tree(root)
            library = SkillLibrary.load(root)
            hits = library.search(query="business email", top_k=5)
            self.assertEqual(hits[0]["name"], "detecting-business-email-compromise")

    def test_from_dicts_roundtrip(self):
        library = SkillLibrary.from_dicts([
            {
                "name": "sample-skill",
                "description": "A sample skill for testing.",
                "domain": "dfir",
                "frameworks": {"MITRE ATT&CK": ["T1055"]},
            }
        ])
        self.assertEqual(library.stats()["total_skills"], 1)
        self.assertEqual(library.list_domains(), ["dfir"])

    def test_parse_skill_file_missing_file(self):
        record = parse_skill_file(Path("nope") / "SKILL.md")
        self.assertTrue(record.issues)


if __name__ == "__main__":
    unittest.main()
