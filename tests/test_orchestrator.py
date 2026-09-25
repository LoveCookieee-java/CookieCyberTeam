"""Unit tests for the meta-orchestrator (coordinating MCP)."""

import tempfile
import unittest
from pathlib import Path

from core.orchestrator import Orchestrator


def make_dispatcher(scan_findings=None, techniques=None):
    calls = []

    def call(tool, args):
        calls.append((tool, args))
        if tool == "mcp_scan_vulnerabilities":
            findings = scan_findings if scan_findings is not None else [
                {"cwe_id": "CWE-89", "severity": "High", "cvss_score": 8.0, "file_path": "a.py", "code_snippet": "q"},
                {"cwe_id": "CWE-78", "severity": "High", "cvss_score": 9.0, "file_path": "a.py", "code_snippet": "c"},
            ]
            return {"success": True, "total_findings": len(findings), "overall_severity": "High",
                    "max_cvss_score": 9.0, "findings": findings}
        if tool == "mcp_validate_finding":
            return {"success": True, "total": 1, "suppressed": 1, "by_verdict": {"submit": 1},
                    "findings": [{"cwe_id": "CWE-89", "validation_verdict": "submit"}]}
        if tool == "mcp_recall_findings":
            return {"success": True, "count": 1, "chains": [{"title": "Chain", "impact": "High"}]}
        if tool == "mcp_triage_binary":
            return {"success": True, "header": {"format": "PE"}, "risk_assessment": {"severity": "High"},
                    "evidence_chain": ["x"], "soc_alerts": [{"technique_id": "T1055"}],
                    "malware_intel": {"techniques": techniques if techniques is not None else [{"technique_id": "T1055.002"}],
                                      "family_matches": [{"family": "Emotet"}], "imphash": "abc"}}
        if tool == "mcp_attack_path":
            return {"success": True, "kill_chain_position": "Defense Evasion",
                    "likely_next_tactics": ["Credential Access"], "priority_detections": ["Watch T1003"]}
        if tool == "mcp_plan_scan":
            return {"success": True, "total_tasks": 5, "kind_counts": {"sast": 3}}
        if tool == "mcp_export_bundle":
            return {"success": True, "finding_count": 1, "chain_count": 1}
        if tool == "mcp_audit_dependencies":
            return {"success": True, "total_dependencies_checked": 3, "vulnerability_count": 1, "urgent_count": 1}
        if tool in ("mcp_generate_containment_rule", "mcp_quarantine_artifact", "mcp_terminate_process"):
            return {"success": True}
        return {"success": True}

    return call, calls


class TestOrchestrator(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "a.py").write_text("import os\n", encoding="utf-8")
        (self.root / "sample.bin").write_bytes(b"MZ" + b"\x00" * 10)
        (self.root / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
        self.orch = Orchestrator(workspace_root=self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_classify_targets(self):
        self.assertEqual(self.orch.classify_target(str(self.root))["kind"], "repo")
        self.assertEqual(self.orch.classify_target(str(self.root / "sample.bin"))["kind"], "binary")
        self.assertEqual(self.orch.classify_target(str(self.root / "requirements.txt"))["kind"], "dependency")
        self.assertEqual(self.orch.classify_target(str(self.root / "a.py"))["kind"], "source")
        self.assertEqual(self.orch.classify_target(None)["kind"], "workspace")

    def test_auto_intent_resolution(self):
        self.assertEqual(self.orch.resolve_intent("auto", "binary", {}), "triage_binary")
        self.assertEqual(self.orch.resolve_intent("auto", "dependency", {}), "dependency_audit")
        self.assertEqual(self.orch.resolve_intent("auto", "repo", {}), "audit_repo")
        self.assertEqual(self.orch.resolve_intent("auto", "workspace", {"code_content": "x"}), "review_code")

    def test_audit_repo_threads_findings(self):
        call, _ = make_dispatcher()
        result = self.orch.run("audit_repo", target=str(self.root), call=call)
        ok = {s["id"]: s for s in result["steps"]}
        self.assertEqual(ok["s_scan"]["status"], "ok")
        self.assertEqual(ok["s_validate"]["status"], "ok")
        self.assertEqual(ok["s_chains"]["status"], "ok")
        self.assertEqual(result["report"]["findings_kept"], 1)
        self.assertEqual(result["report"]["findings_suppressed"], 1)
        self.assertTrue(any("Chain" in str(c) for c in result["report"].get("attack_chains", [])))

    def test_triage_binary_chains_into_attack_path(self):
        call, _ = make_dispatcher()
        result = self.orch.run("triage_binary", target=str(self.root / "sample.bin"), call=call)
        ok = {s["id"]: s for s in result["steps"]}
        self.assertEqual(ok["s_triage"]["status"], "ok")
        self.assertEqual(ok["s_path"]["status"], "ok")
        self.assertEqual(result["report"]["kill_chain_position"], "Defense Evasion")
        self.assertIn("Emotet", result["report"]["families"])

    def test_dependency_audit(self):
        call, _ = make_dispatcher()
        result = self.orch.run("dependency_audit", target=str(self.root / "requirements.txt"), call=call)
        self.assertEqual(result["report"]["dependency_vulnerabilities"], 1)
        self.assertEqual(result["report"]["dependency_urgent"], 1)

    def test_condition_skips_validate_when_no_findings(self):
        call, _ = make_dispatcher(scan_findings=[])
        result = self.orch.run("audit_repo", target=str(self.root), call=call)
        ok = {s["id"]: s for s in result["steps"]}
        self.assertEqual(ok["s_validate"]["status"], "skipped")

    def test_write_steps_withheld_by_default(self):
        call, _ = make_dispatcher()
        result = self.orch.run("incident_response", target=str(self.root / "sample.bin"), call=call)
        ok = {s["id"]: s for s in result["steps"]}
        self.assertEqual(ok["s_quarantine"]["status"], "proposed")
        self.assertGreaterEqual(result["proposed_write_count"], 1)

    def test_write_steps_execute_when_allowed(self):
        call, _ = make_dispatcher()
        result = self.orch.run("incident_response", target=str(self.root / "sample.bin"),
                               call=call, allow_write=True)
        ok = {s["id"]: s for s in result["steps"]}
        self.assertEqual(ok["s_quarantine"]["status"], "ok")

    def test_containment_rule_planned(self):
        call, calls = make_dispatcher()
        result = self.orch.run("incident_response", target=str(self.root / "sample.bin"),
                               call=call, options={"containment_target": "198.51.100.7"})
        tools_called = [t for t, _ in calls]
        self.assertIn("mcp_generate_containment_rule", tools_called)

    def test_requires_dispatcher(self):
        with self.assertRaises(ValueError):
            self.orch.run("audit_repo", target=str(self.root))


class TestAgentSurfaceIntents(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.orch = Orchestrator(workspace_root=self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_skill_audit_plan(self):
        plan = self.orch.plan(intent="skill_audit", target=str(self.root))
        self.assertEqual(plan["intent"], "skill_audit")
        tools = [s["tool"] for s in plan["steps"]]
        self.assertIn("mcp_import_skills", tools)
        self.assertIn("mcp_audit_agent_skills", tools)

    def test_agentic_audit_plan(self):
        plan = self.orch.plan(intent="agentic_audit", target=str(self.root))
        tools = [s["tool"] for s in plan["steps"]]
        self.assertIn("mcp_audit_agent_skills", tools)
        self.assertIn("mcp_detection_coverage", tools)

    def test_agentic_audit_runs_end_to_end(self):
        def call(tool, args):
            if tool == "mcp_audit_agent_skills":
                return {"success": True, "artifacts_scanned": 2, "total_findings": 1,
                        "max_severity": "High", "by_asi": {"ASI-02": 1},
                        "findings": [{"id": "ASI02-TOOL-01", "severity": "High"}]}
            if tool == "mcp_detection_coverage":
                return {"success": True, "distinct_techniques_covered": 31,
                        "tactics_with_coverage": 8}
            return {"success": True}

        result = self.orch.run(intent="agentic_audit", target=str(self.root), call=call)
        self.assertTrue(result["success"])
        self.assertGreaterEqual(result["executed_count"], 2)
        self.assertGreaterEqual(result["report"].get("findings_raw", 0), 1)

    def test_skill_audit_feeds_bundle(self):
        calls = []

        def call(tool, args):
            calls.append(tool)
            if tool == "mcp_import_skills":
                return {"success": True, "available": True, "total_skills": 3, "domains": ["dfir"]}
            if tool == "mcp_audit_agent_skills":
                return {"success": True, "artifacts_scanned": 3, "total_findings": 2,
                        "max_severity": "High", "findings": [{"id": "A"}, {"id": "B"}]}
            if tool == "mcp_export_bundle":
                return {"success": True, "finding_count": 2, "chain_count": 0}
            return {"success": True}

        result = self.orch.run(intent="skill_audit", target=str(self.root), call=call)
        self.assertIn("mcp_import_skills", calls)
        self.assertIn("mcp_audit_agent_skills", calls)
        self.assertIn("mcp_export_bundle", calls)
        self.assertGreaterEqual(result["report"].get("findings_raw", 0), 2)


if __name__ == "__main__":
    unittest.main()
