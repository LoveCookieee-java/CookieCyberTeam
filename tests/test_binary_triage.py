"""
Unit tests for Air-Gapped Static Binary Triage & Reverse Engineering Engine.
"""

import os
import struct
import tempfile
import unittest
from pathlib import Path
from core.binary_triage import (
    BinaryTriageEngine,
    calculate_entropy,
    calculate_block_entropy,
    extract_ioc_strings,
    parse_magic_header,
)


class TestBinaryTriage(unittest.TestCase):

    def setUp(self):
        self.engine = BinaryTriageEngine()

    def test_shannon_entropy_calculation(self):
        """Uniform byte sequences have 0 entropy; diverse sequences approach 8.0."""
        # 0 entropy: identical bytes
        all_zeros = b"\x00" * 2048
        self.assertEqual(calculate_entropy(all_zeros), 0.0)

        # High entropy: all 256 byte values uniformly distributed
        diverse = bytes(range(256)) * 8
        h = calculate_entropy(diverse)
        self.assertAlmostEqual(h, 8.0, delta=0.05)

    def test_block_entropy_detects_packing(self):
        """1KB block entropy flags packed or encrypted regions when peak >= 7.3."""
        normal_data = b"def calculate_total(): return 42\n" * 100
        block_res = calculate_block_entropy(normal_data)
        self.assertFalse(block_res["is_packed"])

        # Create pseudo-random high entropy block
        high_entropy_block = os.urandom(2048)
        packed_res = calculate_block_entropy(high_entropy_block)
        self.assertTrue(packed_res["is_packed"])
        self.assertGreaterEqual(packed_res["peak_entropy"], 7.3)

    def test_magic_header_detection(self):
        """Verify static recognition of PE, ELF, ZIP, and DEX formats."""
        # 1. PE Header
        pe_mock = bytearray(b"MZ" + (b"\x00" * 0x3A))
        pe_mock.extend(struct.pack("<I", 0x80))  # e_lfanew = 0x80
        pe_mock.extend(b"\x00" * (0x80 - len(pe_mock)))
        pe_mock.extend(b"PE\x00\x00")  # Signature
        pe_mock.extend(struct.pack("<H", 0x8664))  # AMD64
        pe_mock.extend(b"\x00" * 16)
        pe_mock.extend(struct.pack("<H", 0x0002))  # Executable
        pe_mock.extend(struct.pack("<H", 0x20b))   # PE32+
        pe_res = parse_magic_header(bytes(pe_mock))
        self.assertEqual(pe_res["format"], "PE")
        self.assertTrue(pe_res["is_valid_pe"])
        self.assertIn("AMD64", pe_res["architecture"])

        # 2. Linux ELF
        elf_mock = bytearray(b"\x7fELF")
        elf_mock.append(2)  # 64-bit
        elf_mock.append(1)  # Little endian
        elf_mock.extend(b"\x00" * 10)
        elf_mock.extend(struct.pack("<H", 2))  # Executable
        elf_mock.extend(struct.pack("<H", 0x3E))  # x86_64
        elf_res = parse_magic_header(bytes(elf_mock))
        self.assertEqual(elf_res["format"], "ELF")
        self.assertEqual(elf_res["class"], "64-bit")
        self.assertEqual(elf_res["architecture"], "x86_64")

        # 3. Android DEX
        dex_mock = b"dex\n035\x00" + b"\x00" * 50
        dex_res = parse_magic_header(dex_mock)
        self.assertEqual(dex_res["format"], "DEX")

        # 4. ZIP Archive
        zip_mock = b"PK\x03\x04" + b"\x00" * 50
        zip_res = parse_magic_header(zip_mock)
        self.assertEqual(zip_res["format"], "ZIP")

    def test_safe_string_ioc_extraction(self):
        """Verify extraction of URLs, IPs, Registry keys, and suspicious RAT APIs."""
        raw_payload = (
            b"Error loading module. Contact 198.51.100.24 for support.\x00"
            b"C2 Server: https://command-control-node.net/beacon\x00"
            b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\PersistAgent\x00"
            b"calling CreateRemoteThread and VirtualAlloc to inject\x00"
        )
        ioc = extract_ioc_strings(raw_payload)

        self.assertIn("198.51.100.24", ioc["ips_detected"])
        self.assertTrue(any("command-control-node.net" in u for u in ioc["urls_detected"]))
        self.assertTrue(any("PersistAgent" in r for r in ioc["registry_keys_detected"]))
        self.assertTrue(any("CreateRemoteThread" in a or "VirtualAlloc" in a for a in ioc["suspicious_apis_detected"]))

    def test_full_triage_file(self):
        """End-to-end file triage producing evidence chain and CVSS risk evaluation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_file = Path(tmp_dir) / "suspicious_agent.exe"
            # Build mock binary with PE signature and embedded C2 URL
            data = (
                b"MZ" + (b"\x00" * 0x3A) + struct.pack("<I", 0x40) +
                b"PE\x00\x00\x4c\x01\x00\x00" +
                (b"\x00" * 100) +
                b"https://evil-rat.internal/payload.bin\x00" +
                b"cmd.exe /c powershell downloadstring\x00"
            )
            sample_file.write_bytes(data)

            res = self.engine.triage_file(sample_file)
            self.assertTrue(res["success"])
            self.assertEqual(res["header"]["format"], "PE")
            self.assertIn("sha256", res["hashes"])
            self.assertIn("md5", res["hashes"])
            self.assertGreaterEqual(len(res["evidence_chain"]), 3)
            self.assertIn(res["risk_assessment"]["severity"], ("Medium", "High", "Critical"))


    def test_ipv4_zero_octets_and_version_rejection(self):
        """Verify IPs with 0 octets (10.0.0.1, 127.0.0.1, 192.168.0.1) are detected, while versions like 1.2.3.4.5 are ignored."""
        payload = (
            b"Internal listener at 10.0.0.1:8080 and loopback 127.0.0.1.\x00"
            b"Gateway is 192.168.0.1, external is 198.51.100.24.\x00"
            b"Version string v1.2.3.4.5 must not be matched as an IP.\x00"
            b"Invalid octet 999.999.999.999 must not be matched.\x00"
        )
        ioc = extract_ioc_strings(payload)
        self.assertIn("10.0.0.1", ioc["ips_detected"])
        self.assertIn("127.0.0.1", ioc["ips_detected"])
        self.assertIn("192.168.0.1", ioc["ips_detected"])
        self.assertIn("198.51.100.24", ioc["ips_detected"])
        self.assertNotIn("999.999.999.999", ioc["ips_detected"])
        self.assertNotIn("1.2.3.4", ioc["ips_detected"])

    def test_persistence_registry_ioc_elevates_risk(self):
        """Verify persistence registry keys are added to evidence chain and elevate risk from Low."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_file = Path(tmp_dir) / "persistence_agent.exe"
            data = (
                b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\PersistService\x00"
                b"Clean utility binary without any network or injection calls.\x00"
            )
            sample_file.write_bytes(data)

            res = self.engine.triage_file(sample_file)
            self.assertTrue(res["success"])
            self.assertEqual(res["risk_assessment"]["severity"], "Medium")
            self.assertTrue(any("Persistence registry keys" in r for r in res["risk_assessment"]["reasons"]))
            self.assertTrue(any("[IOC PERSISTENCE]" in line for line in res["evidence_chain"]))

    def test_pe_parsing_corrupted_header_resilience(self):
        """Verify corrupted or adversarial e_lfanew pointers do not crash triage."""
        # 1. Negative or overlapping pe_offset (less than 0x40)
        bad_pe_1 = b"MZ" + (b"\x00" * 0x3A) + struct.pack("<I", 0x10) + (b"\x00" * 100)
        res_1 = parse_magic_header(bad_pe_1)
        self.assertFalse(res_1["is_valid_pe"])

        # 2. Out of bounds pe_offset pointing past EOF
        bad_pe_2 = b"MZ" + (b"\x00" * 0x3A) + struct.pack("<I", 0xFFFFFF00) + (b"\x00" * 100)
        res_2 = parse_magic_header(bad_pe_2)
        self.assertFalse(res_2["is_valid_pe"])


if __name__ == "__main__":
    unittest.main()
