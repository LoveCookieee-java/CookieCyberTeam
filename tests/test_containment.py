"""
Unit tests for Active Containment Primitives (core/containment.py).
Tests artifact quarantine vault, payload XOR obfuscation, tamper-evident manifest,
firewall rule generation (Windows, Linux, DNS), and safe process tree termination.
"""

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from core.containment import (
    generate_firewall_rule,
    quarantine_file,
    restore_quarantined_file,
    terminate_suspicious_process,
    XOR_KEY,
)


class TestContainment(unittest.TestCase):

    def test_quarantine_file_basic(self):
        """Verify suspicious file is atomically moved to vault with manifest entry."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            sample = ws / "malicious_dropper.exe"
            original_content = b"MZ\x90\x00\x03\x00\x00\x00TEST_DROPPER_CONTENT_HEX"
            sample.write_bytes(original_content)

            expected_sha = hashlib.sha256(original_content).hexdigest()
            expected_md5 = hashlib.md5(original_content).hexdigest()

            res = quarantine_file(file_path=sample, workspace_root=ws)
            self.assertTrue(res["success"])
            self.assertIn("quarantine_id", res)
            self.assertEqual(res["sha256"], expected_sha)
            self.assertEqual(res["md5"], expected_md5)
            self.assertEqual(res["file_size"], len(original_content))

            # Original sample must no longer exist at original path (moved)
            self.assertFalse(sample.exists())

            # Quarantined file must exist in vault
            quar_path = Path(res["quarantine_path"])
            self.assertTrue(quar_path.is_file())
            self.assertTrue(quar_path.name.endswith(".quarantine.enc"))

            # Manifest must be created and valid JSON
            manifest_file = Path(res["manifest_path"])
            self.assertTrue(manifest_file.is_file())
            manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
            self.assertIn(res["quarantine_id"], manifest_data["items"])
            item = manifest_data["items"][res["quarantine_id"]]
            self.assertEqual(item["sha256"], expected_sha)
            self.assertEqual(item["status"], "quarantined")

    def test_quarantine_file_obfuscation_and_restore(self):
        """Verify payload is XOR-obfuscated in vault and can be restored intact."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            sample = ws / "trojan_payload.bin"
            original_data = b"PE\x00\x00CRITICAL_MALWARE_BYTE_SEQUENCE\xff\xfe\x01\x02"
            sample.write_bytes(original_data)

            res = quarantine_file(file_path=sample, workspace_root=ws)
            self.assertTrue(res["success"])

            # Verify on-disk bytes in vault are XOR-scrambled
            enc_path = Path(res["quarantine_path"])
            if os.name != "nt":
                try:
                    os.chmod(enc_path, stat.S_IRUSR)
                except Exception:
                    pass
            enc_bytes = enc_path.read_bytes()
            self.assertNotEqual(enc_bytes, original_data)
            expected_enc = bytes([b ^ XOR_KEY for b in original_data])
            self.assertEqual(enc_bytes, expected_enc)

            # Test restoration
            restore_dest = ws / "restored_sample.bin"
            rest_res = restore_quarantined_file(
                quarantine_id=res["quarantine_id"],
                workspace_root=ws,
                destination_path=restore_dest,
            )
            self.assertTrue(rest_res["success"])
            self.assertTrue(restore_dest.is_file())
            self.assertEqual(restore_dest.read_bytes(), original_data)
            self.assertEqual(rest_res["sha256"], hashlib.sha256(original_data).hexdigest())

    def test_quarantine_file_path_traversal_rejection(self):
        """Verify path traversal or escaping workspace boundaries is rejected."""
        with tempfile.TemporaryDirectory() as ws_dir, tempfile.TemporaryDirectory() as external_dir:
            ws = Path(ws_dir)
            external_file = Path(external_dir) / "system_file.txt"
            external_file.write_text("critical external file", encoding="utf-8")

            # Traversal targeting external path
            res = quarantine_file(file_path=external_file, workspace_root=ws)
            self.assertFalse(res["success"])
            self.assertIn("traversal", res["error"].lower())
            self.assertTrue(external_file.exists())  # Must not touch external file

    def test_quarantine_file_sensitive_path_rejection(self):
        """Verify attempts to quarantine sensitive git or env paths are strictly rejected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            git_file = ws / ".git" / "config"
            git_file.parent.mkdir(parents=True, exist_ok=True)
            git_file.write_text("[core]\n\trepositoryformatversion = 0\n", encoding="utf-8")

            res = quarantine_file(file_path=git_file, workspace_root=ws)
            self.assertFalse(res["success"])
            self.assertIn("forbidden", res["error"].lower())

            env_file = ws / ".env"
            env_file.write_text("API_KEY=secret", encoding="utf-8")
            res_env = quarantine_file(file_path=env_file, workspace_root=ws)
            self.assertFalse(res_env["success"])

    def test_quarantine_nonexistent_file(self):
        """Verify non-existent file reports structured failure without unhandled exception."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            res = quarantine_file(file_path=ws / "does_not_exist.bin", workspace_root=ws)
            self.assertFalse(res["success"])
            self.assertIn("not found", res["error"].lower())

    def test_generate_firewall_rule_ip_block(self):
        """Verify host firewall rules generated for IPv4 block."""
        res = generate_firewall_rule(target="198.51.100.42", rule_type="block")
        self.assertTrue(res["success"])
        self.assertEqual(res["target"], "198.51.100.42")
        self.assertEqual(res["rule_type"], "block")

        # Windows netsh
        self.assertIn("netsh advfirewall firewall add rule", res["windows_netsh"])
        self.assertIn("action=block", res["windows_netsh"])
        self.assertIn("remoteip=198.51.100.42", res["windows_netsh"])

        # Linux iptables
        self.assertIn("iptables -A OUTPUT -d 198.51.100.42 -j DROP", res["linux_iptables"])
        self.assertIn("iptables -A INPUT -s 198.51.100.42 -j DROP", res["linux_iptables"])

        # Linux UFW
        self.assertIn("ufw deny from 198.51.100.42", res["linux_ufw"])
        self.assertIn("ufw deny out to 198.51.100.42", res["linux_ufw"])

        # DNS Sinkhole
        self.assertEqual(res["dns_sinkhole"], "0.0.0.0 198.51.100.42")

    def test_generate_firewall_rule_with_port(self):
        """Verify host firewall rules with port filtering."""
        res = generate_firewall_rule(target="evil-c2.attacker.test", rule_type="block", port=4444)
        self.assertTrue(res["success"])
        self.assertIn("remoteport=4444", res["windows_netsh"])
        self.assertIn("--dport 4444", res["linux_iptables"])
        self.assertIn("port 4444", res["linux_ufw"])

    def test_generate_firewall_rule_allow_rule(self):
        """Verify firewall rules generation for allow action."""
        res = generate_firewall_rule(target="10.0.0.1", rule_type="allow", port=80)
        self.assertTrue(res["success"])
        self.assertIn("action=allow", res["windows_netsh"])
        self.assertIn("ACCEPT", res["linux_iptables"])
        self.assertIn("ufw allow", res["linux_ufw"])

    def test_generate_firewall_rule_rejection_of_dangerous_input(self):
        """Verify shell injection metacharacters and invalid ports are rejected."""
        bad_targets = [
            "10.0.0.1; rm -rf /",
            "evil.com | echo pwned",
            "$(cat /etc/passwd)",
            "10.0.0.1 && dir",
            "target with spaces",
        ]
        for bt in bad_targets:
            res = generate_firewall_rule(target=bt)
            self.assertFalse(res["success"])
            self.assertIn("metacharacters", res["error"].lower())

        # Bad ports
        self.assertFalse(generate_firewall_rule("10.0.0.1", port=0)["success"])
        self.assertFalse(generate_firewall_rule("10.0.0.1", port=70000)["success"])

    def test_terminate_suspicious_process_protection_invariants(self):
        """Verify process termination rejects PID 0, PID 4, and current agent PID."""
        # System PID 0
        res_0 = terminate_suspicious_process(pid=0)
        self.assertFalse(res_0["success"])
        self.assertIn("critical", res_0["error"].lower())

        # System PID 4 (Windows System)
        res_4 = terminate_suspicious_process(pid=4)
        self.assertFalse(res_4["success"])
        self.assertIn("critical", res_4["error"].lower())

        # Current agent process
        res_self = terminate_suspicious_process(pid=os.getpid())
        self.assertFalse(res_self["success"])
        self.assertIn("self", res_self["error"].lower())

        # Non-existent PID
        res_none = terminate_suspicious_process(pid=9999999)
        self.assertFalse(res_none["success"])
        self.assertIn("not found", res_none["error"].lower())

    def test_restore_quarantined_file_path_traversal_rejection(self):
        """Verify restore cannot escape workspace or overwrite arbitrary external files."""
        with tempfile.TemporaryDirectory() as ws_dir, tempfile.TemporaryDirectory() as ext_dir:
            ws = Path(ws_dir)
            sample = ws / "dropper.exe"
            sample.write_bytes(b"MALWARE_TEST_BYTES")

            res = quarantine_file(file_path=sample, workspace_root=ws)
            self.assertTrue(res["success"])

            # Attempt restore to external path
            external_dest = Path(ext_dir) / "pwned.exe"
            rest_res = restore_quarantined_file(
                quarantine_id=res["quarantine_id"],
                workspace_root=ws,
                destination_path=external_dest,
            )
            self.assertFalse(rest_res["success"])
            self.assertIn("forbidden", rest_res["error"].lower())
            self.assertFalse(external_dest.exists())

    def test_quarantine_already_quarantined_or_manifest_rejection(self):
        """Verify attempts to quarantine vault contents or manifest itself are rejected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            sample = ws / "sample.exe"
            sample.write_bytes(b"DATA")
            res = quarantine_file(file_path=sample, workspace_root=ws)
            self.assertTrue(res["success"])

            # Attempt to quarantine the manifest
            manifest = Path(res["manifest_path"])
            q_man = quarantine_file(file_path=manifest, workspace_root=ws)
            self.assertFalse(q_man["success"])

            # Attempt to quarantine an already quarantined file inside .quarantine
            enc_file = Path(res["quarantine_path"])
            q_enc = quarantine_file(file_path=enc_file, workspace_root=ws)
            self.assertFalse(q_enc["success"])

    def test_generate_firewall_rule_bidirectional_port(self):
        """Verify firewall rules with port block both inbound and outbound."""
        res = generate_firewall_rule(target="198.51.100.5", rule_type="block", port=8080)
        self.assertTrue(res["success"])
        self.assertIn("--dport 8080", res["linux_iptables"])
        self.assertIn("--sport 8080", res["linux_iptables"])
        self.assertIn("out to 198.51.100.5 port 8080", res["linux_ufw"])
        self.assertIn("from 198.51.100.5 port 8080", res["linux_ufw"])

    def test_restore_quarantined_file_with_quarantine_dir_and_default_ws(self):
        """Verify restore_quarantined_file executes properly when workspace_root is not explicitly provided."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            sample = ws / "test_file.bin"
            sample.write_bytes(b"HELLO_RESTORATION")
            vault = ws / ".custom_vault"
            q_res = quarantine_file(file_path=sample, quarantine_dir=vault, workspace_root=ws)
            self.assertTrue(q_res["success"])

            # Call restore passing quarantine_dir without workspace_root
            dest = ws / "restored_test.bin"
            rest_res = restore_quarantined_file(
                quarantine_id=q_res["quarantine_id"],
                quarantine_dir=vault,
                destination_path=dest,
            )
            self.assertTrue(rest_res["success"])
            self.assertTrue(dest.is_file())
            self.assertEqual(dest.read_bytes(), b"HELLO_RESTORATION")

    def test_restore_quarantined_file_relocated_vault(self):
        """Verify restore succeeds even if quarantine vault directory was moved and manifest paths are outdated."""
        with tempfile.TemporaryDirectory() as tmp_dir1, tempfile.TemporaryDirectory() as tmp_dir2:
            ws1 = Path(tmp_dir1)
            sample = ws1 / "payload.bin"
            sample.write_bytes(b"RELOCATED_TEST_BYTES")
            vault1 = ws1 / ".quarantine"
            q_res = quarantine_file(file_path=sample, quarantine_dir=vault1, workspace_root=ws1)
            self.assertTrue(q_res["success"])

            # Move vault files to new location
            ws2 = Path(tmp_dir2)
            vault2 = ws2 / ".quarantine_relocated"
            vault2.mkdir(parents=True, exist_ok=True)
            for f in vault1.iterdir():
                if os.name != "nt":
                    try:
                        os.chmod(f, stat.S_IRUSR)
                    except Exception:
                        pass
                (vault2 / f.name).write_bytes(f.read_bytes())

            dest2 = ws2 / "restored_from_relocated.bin"
            rest_res = restore_quarantined_file(
                quarantine_id=q_res["quarantine_id"],
                quarantine_dir=vault2,
                destination_path=dest2,
                workspace_root=ws2,
            )
            self.assertTrue(rest_res["success"])
            self.assertEqual(dest2.read_bytes(), b"RELOCATED_TEST_BYTES")


if __name__ == "__main__":
    unittest.main()
