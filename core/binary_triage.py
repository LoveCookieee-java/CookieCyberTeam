"""
Air-Gapped Binary Triage & Malware / Reverse Engineering Static Inspector.
Enforces the Zero-Execution Policy: static binary dissection only. Never executes binaries.
Extracts magic headers (PE/ELF/ZIP/DEX), computes 1KB block Shannon entropy,
extracts safe string IOCs (IP, URL, Registry, RAT APIs), and builds an evidence chain.
"""

from __future__ import annotations
import hashlib
import math
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy (0.0 - 8.0 bits per byte)."""
    if not data:
        return 0.0
    length = len(data)
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_block_entropy(data: bytes, block_size: int = 1024) -> Dict[str, Any]:
    """Calculate Shannon entropy over consecutive 1KB blocks to identify packed/encrypted regions."""
    if block_size <= 0:
        block_size = 1024
    if not data:
        return {"block_count": 0, "peak_entropy": 0.0, "mean_entropy": 0.0, "is_packed": False, "high_entropy_blocks": []}

    entropies: List[float] = []
    high_entropy_blocks: List[Dict[str, Any]] = []

    for idx, offset in enumerate(range(0, len(data), block_size)):
        block = data[offset:offset + block_size]
        h = calculate_entropy(block)
        entropies.append(h)
        if h >= 7.2:
            high_entropy_blocks.append({
                "block_index": idx,
                "offset_hex": hex(offset),
                "entropy": h,
            })

    peak_h = max(entropies) if entropies else 0.0
    mean_h = sum(entropies) / len(entropies) if entropies else 0.0
    # Flag as packed if peak entropy >= 7.2 or > 30% of blocks exceed 7.0
    packed_ratio = sum(1 for e in entropies if e >= 7.0) / len(entropies) if entropies else 0.0
    is_packed = peak_h >= 7.3 or packed_ratio >= 0.35

    return {
        "block_count": len(entropies),
        "peak_entropy": round(peak_h, 4),
        "mean_entropy": round(mean_h, 4),
        "high_entropy_block_count": len(high_entropy_blocks),
        "packed_ratio": round(packed_ratio, 4),
        "is_packed": is_packed,
        "sample_high_entropy_blocks": high_entropy_blocks[:10],
    }


def parse_magic_header(data: bytes) -> Dict[str, Any]:
    """Parse static binary file format and architecture without dynamic execution."""
    if not data:
        return {"format": "Empty", "description": "Empty file (0 bytes)"}

    # 1. Windows PE (Portable Executable)
    if data.startswith(b"MZ"):
        pe_info: Dict[str, Any] = {
            "format": "PE",
            "os": "Windows",
            "description": "Windows Portable Executable (MZ Header)",
            "is_valid_pe": False,
        }
        if len(data) >= 0x40:
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            if 0x40 <= pe_offset <= len(data) - 24 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                pe_info["is_valid_pe"] = True
                pe_info["pe_header_offset"] = hex(pe_offset)
                machine = struct.unpack("<H", data[pe_offset + 4:pe_offset + 6])[0]
                characteristics = struct.unpack("<H", data[pe_offset + 22:pe_offset + 24])[0]
                size_of_opt = struct.unpack("<H", data[pe_offset + 20:pe_offset + 22])[0]
                
                machine_map = {
                    0x014c: "i386 (32-bit x86)",
                    0x8664: "AMD64 (64-bit x86_64)",
                    0xaa64: "ARM64 (little endian)",
                }
                pe_info["architecture"] = machine_map.get(machine, f"Unknown ({hex(machine)})")
                pe_info["is_dll"] = bool(characteristics & 0x2000)
                pe_info["is_executable"] = bool(characteristics & 0x0002)

                # Optional Header Magic (only valid when size_of_opt >= 2)
                opt_offset = pe_offset + 24
                if size_of_opt >= 2 and opt_offset + 2 <= len(data):
                    opt_magic = struct.unpack("<H", data[opt_offset:opt_offset + 2])[0]
                    pe_info["pe_type"] = "PE32+" if opt_magic == 0x20b else ("PE32" if opt_magic == 0x10b else "Unknown")
        return pe_info

    # 2. Linux ELF
    if data.startswith(b"\x7fELF"):
        elf_info: Dict[str, Any] = {
            "format": "ELF",
            "os": "Linux",
            "description": "Linux Executable and Linkable Format",
        }
        if len(data) >= 20:
            ei_class = data[4]
            ei_data = data[5]
            elf_info["class"] = "64-bit" if ei_class == 2 else ("32-bit" if ei_class == 1 else "Unknown")
            elf_info["endian"] = "Little Endian" if ei_data == 1 else ("Big Endian" if ei_data == 2 else "Unknown")
            e_type = struct.unpack("<H" if ei_data == 1 else ">H", data[16:18])[0]
            e_machine = struct.unpack("<H" if ei_data == 1 else ">H", data[18:20])[0]

            type_map = {1: "Relocatable", 2: "Executable", 3: "Shared Object (SO)", 4: "Core Dump"}
            machine_map = {0x03: "x86", 0x3E: "x86_64", 0x28: "ARM", 0xB7: "AArch64", 0x08: "MIPS"}
            elf_info["elf_type"] = type_map.get(e_type, f"Unknown ({e_type})")
            elf_info["architecture"] = machine_map.get(e_machine, f"Unknown ({hex(e_machine)})")
        return elf_info

    # 3. Android DEX
    if data.startswith(b"dex\n"):
        return {
            "format": "DEX",
            "os": "Android",
            "description": f"Android Dalvik Executable (Version {data[4:7].decode('ascii', 'replace')})",
        }

    # 4. ZIP / JAR / APK
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        desc = "ZIP Archive"
        if b"AndroidManifest.xml" in data[:4096]:
            desc = "Android APK Package"
        elif b"META-INF" in data[:4096]:
            desc = "Java Archive (JAR/WAR)"
        return {"format": "ZIP", "os": "Cross-Platform", "description": desc}

    # 5. Java Class Bytecode
    if data.startswith(b"\xca\xfe\xba\xbe"):
        return {"format": "JAVA_CLASS", "os": "JVM", "description": "Compiled Java Class Bytecode (CAFEBABE)"}

    # 6. Mach-O
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return {"format": "Mach-O", "os": "macOS/iOS", "description": "Apple Mach-O Binary"}

    # 7. Shell Script
    if data.startswith(b"#!"):
        first_line = data.split(b"\n", 1)[0].decode("ascii", "replace")
        return {"format": "SCRIPT", "os": "Unix", "description": f"Executable Script Shebang: {first_line}"}

    # 8. PDF
    if data.startswith(b"%PDF-"):
        return {"format": "PDF", "os": "Document", "description": "Adobe PDF Document"}

    return {"format": "RAW_BINARY", "os": "Unknown", "description": "Unknown binary or data format"}


SUSPICIOUS_API_PATTERNS = [
    re.compile(rb"cmd\.exe", re.IGNORECASE),
    re.compile(rb"powershell(?:\.exe)?", re.IGNORECASE),
    re.compile(rb"downloadstring", re.IGNORECASE),
    re.compile(rb"virtualalloc", re.IGNORECASE),
    re.compile(rb"createremotethread", re.IGNORECASE),
    re.compile(rb"writeprocessmemory", re.IGNORECASE),
    re.compile(rb"setwindowshook", re.IGNORECASE),
    re.compile(rb"getkeystate|getasynckeystate", re.IGNORECASE),
    re.compile(rb"regopenkey|regsetvalue", re.IGNORECASE),
    re.compile(rb"wscript\.shell", re.IGNORECASE),
    re.compile(rb"certutil(?:\.exe)?\s+-urlcache", re.IGNORECASE),
    re.compile(rb"mimikatz|sekurlsa", re.IGNORECASE),
    re.compile(rb"beacon|meterpreter|reverse_tcp", re.IGNORECASE),
]

IPV4_PATTERN = re.compile(
    r"(?<![0-9])(?<![0-9]\.)(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?![0-9])(?!\.[0-9])"
)
URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9_\-\.]+(:[0-9]+)?(/[^\s\"\'<>]*)?")
REGISTRY_PATTERN = re.compile(r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|Software\\Microsoft\\Windows\\CurrentVersion)\\[^\s\"\'<>]{4,}")


def extract_ioc_strings(data: bytes, max_strings: int = 150) -> Dict[str, Any]:
    """Extract printable strings and identify potential Indicators of Compromise (IOCs)."""
    # Extract ASCII strings (min len 4)
    ascii_strings = re.findall(rb"[\x20-\x7e]{4,}", data)
    decoded_strings: List[str] = [s.decode("ascii", "replace") for s in ascii_strings[:1000]]

    # Also extract UTF-16LE strings
    wide_strings = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data)
    for ws in wide_strings[:500]:
        try:
            decoded_strings.append(ws.decode("utf-16le", "replace"))
        except Exception:
            pass

    # Extract specific IOC categories
    urls: List[str] = []
    ips: List[str] = []
    registry_keys: List[str] = []
    suspicious_apis: List[str] = []

    for s in decoded_strings:
        # URLs
        for m in URL_PATTERN.finditer(s):
            u = m.group(0)
            if u not in urls:
                urls.append(u)
        # IPs
        for m in IPV4_PATTERN.finditer(s):
            ip = m.group(0)
            # Filter standard private / loopback noise if desired, keep visible for blue team triage
            if ip not in ips:
                ips.append(ip)
        # Registry
        for m in REGISTRY_PATTERN.finditer(s):
            r = m.group(0)
            if r not in registry_keys:
                registry_keys.append(r)

    # Suspicious API keywords in raw bytes
    for pat in SUSPICIOUS_API_PATTERNS:
        matches = pat.findall(data)
        if matches:
            decoded_match = matches[0].decode("ascii", "replace")
            if decoded_match not in suspicious_apis:
                suspicious_apis.append(decoded_match)

    return {
        "total_extracted_strings": len(decoded_strings),
        "suspicious_apis_detected": suspicious_apis[:20],
        "urls_detected": urls[:20],
        "ips_detected": ips[:20],
        "registry_keys_detected": registry_keys[:20],
        "sample_strings": decoded_strings[:max_strings],
    }


class BinaryTriageEngine:
    """
    Air-Gapped Binary Triage Engine.
    Executes zero-execution static inspection of binary artifacts.
    """

    def triage_file(self, file_path: str | Path, max_bytes: int = 15 * 1024 * 1024) -> Dict[str, Any]:
        """Triage an artifact statically and build a cryptographically rooted evidence chain."""
        p = Path(file_path).resolve()
        if not p.is_file():
            return {"success": False, "error": f"File not found: {p}"}

        try:
            file_size = p.stat().st_size
            # Read artifact safely
            with p.open("rb") as f:
                data = f.read(max_bytes)

            sha256 = hashlib.sha256(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()

            # Global & block entropy
            global_entropy = calculate_entropy(data)
            block_entropy = calculate_block_entropy(data, block_size=1024)

            # Header / format dissection
            header_info = parse_magic_header(data)

            # IOC String extraction
            ioc_info = extract_ioc_strings(data)

            # Build Evidence-Finding Path
            # SHA-256 -> Magic/Offset -> Identified Feature/IOC -> Risk Evaluation
            evidence_chain: List[str] = [
                f"Artifact SHA-256: {sha256}",
                f"Header Inspection: {header_info.get('format')} ({header_info.get('description')})",
                f"Global Entropy: {global_entropy} / 8.0 (Peak 1KB Block: {block_entropy['peak_entropy']})",
            ]
            if block_entropy["is_packed"]:
                evidence_chain.append(
                    f"[CONFIRMED PACKING]: Peak entropy {block_entropy['peak_entropy']} indicates packed/encrypted sections."
                )
            if ioc_info["suspicious_apis_detected"]:
                evidence_chain.append(
                    f"[CONFIRMED SUSPICIOUS APIS]: {', '.join(ioc_info['suspicious_apis_detected'][:5])}"
                )
            if ioc_info["urls_detected"]:
                evidence_chain.append(f"[IOC URLS]: {', '.join(ioc_info['urls_detected'][:3])}")
            if ioc_info["ips_detected"]:
                evidence_chain.append(f"[IOC IPS]: {', '.join(ioc_info['ips_detected'][:3])}")
            if ioc_info["registry_keys_detected"]:
                evidence_chain.append(f"[IOC PERSISTENCE]: {', '.join(ioc_info['registry_keys_detected'][:3])}")

            # Overall Risk Assessment
            risk = "Low"
            reasons = []
            if block_entropy["is_packed"]:
                risk = "High"
                reasons.append("High entropy packing detected")
            if ioc_info["suspicious_apis_detected"]:
                if any(api.lower() in ("createremotethread", "writeprocessmemory", "virtualalloc", "beacon", "meterpreter") for api in ioc_info["suspicious_apis_detected"]):
                    risk = "Critical"
                    reasons.append("Process injection or RAT C2 payload indicators found")
                elif risk != "Critical":
                    risk = "High"
                    reasons.append("Suspicious system execution APIs detected")
            if ioc_info["urls_detected"] or ioc_info["ips_detected"]:
                if risk == "Low":
                    risk = "Medium"
                reasons.append("External network indicators embedded in binary")
            if ioc_info["registry_keys_detected"]:
                if risk == "Low":
                    risk = "Medium"
                reasons.append("Persistence registry keys detected in binary")

            return {
                "success": True,
                "file_path": str(p),
                "file_size_bytes": file_size,
                "truncated": file_size > max_bytes,
                "hashes": {
                    "sha256": sha256,
                    "md5": md5,
                },
                "header": header_info,
                "entropy": {
                    "global": global_entropy,
                    "block_analysis": block_entropy,
                },
                "iocs": {
                    "suspicious_apis": ioc_info["suspicious_apis_detected"],
                    "urls": ioc_info["urls_detected"],
                    "ips": ioc_info["ips_detected"],
                    "registry_keys": ioc_info["registry_keys_detected"],
                },
                "risk_assessment": {
                    "severity": risk,
                    "reasons": reasons if reasons else ["Clean static profile"],
                },
                "evidence_chain": evidence_chain,
            }
        except Exception as exc:
            return {"success": False, "error": f"Triage failed: {str(exc)}"}
