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

from core.malware_intel import enrich_triage


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
            "sections": [],
            "has_wx_sections": False,
            "wx_sections": [],
            "section_anomalies": [],
        }
        if len(data) >= 0x40:
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            if 0x40 <= pe_offset <= len(data) - 24 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                pe_info["is_valid_pe"] = True
                pe_info["pe_header_offset"] = hex(pe_offset)
                machine = struct.unpack("<H", data[pe_offset + 4:pe_offset + 6])[0]
                num_sections = struct.unpack("<H", data[pe_offset + 6:pe_offset + 8])[0]
                characteristics = struct.unpack("<H", data[pe_offset + 22:pe_offset + 24])[0]
                size_of_opt = struct.unpack("<H", data[pe_offset + 20:pe_offset + 22])[0]
                
                machine_map = {
                    0x014c: "i386 (32-bit x86)",
                    0x8664: "AMD64 (64-bit x86_64)",
                    0xaa64: "ARM64 (little endian)",
                }
                pe_info["architecture"] = machine_map.get(machine, f"Unknown ({hex(machine)})")
                pe_info["number_of_sections"] = num_sections
                pe_info["is_dll"] = bool(characteristics & 0x2000)
                pe_info["is_executable"] = bool(characteristics & 0x0002)

                # Optional Header Magic (only valid when size_of_opt >= 2)
                opt_offset = pe_offset + 24
                if size_of_opt >= 2 and opt_offset + 2 <= len(data):
                    opt_magic = struct.unpack("<H", data[opt_offset:opt_offset + 2])[0]
                    pe_info["pe_type"] = "PE32+" if opt_magic == 0x20b else ("PE32" if opt_magic == 0x10b else "Unknown")

                # Section Table Parsing
                sec_table_offset = opt_offset + size_of_opt
                sections: List[Dict[str, Any]] = []
                wx_sections: List[str] = []
                anomalies: List[str] = []

                IMAGE_SCN_MEM_EXECUTE = 0x20000000
                IMAGE_SCN_MEM_WRITE = 0x80000000

                if sec_table_offset > len(data):
                    anomalies.append(f"Malformed PE: Section table offset ({hex(sec_table_offset)}) exceeds file size ({hex(len(data))})")
                else:
                    for i in range(num_sections):
                        sec_start = sec_table_offset + (i * 40)
                        if sec_start + 40 > len(data):
                            anomalies.append(
                                f"Truncated section table: header specifies {num_sections} sections, but file only contains data for {len(sections)}"
                            )
                            break
                        sec_header = data[sec_start:sec_start + 40]
                        sec_name_raw = sec_header[:8]
                        sec_name = sec_name_raw.split(b"\x00", 1)[0].decode("ascii", "replace").strip()
                        if not sec_name or not sec_name.isprintable():
                            sec_name = f"unnamed_{i}" if not sec_name else sec_name
                            anomalies.append(f"Section at index {i} has empty or non-printable name")
                        vsize = struct.unpack("<I", sec_header[8:12])[0]
                        vaddr = struct.unpack("<I", sec_header[12:16])[0]
                        raw_size = struct.unpack("<I", sec_header[16:20])[0]
                        raw_ptr = struct.unpack("<I", sec_header[20:24])[0]
                        sec_chars = struct.unpack("<I", sec_header[36:40])[0]

                        is_executable = bool(sec_chars & IMAGE_SCN_MEM_EXECUTE)
                        is_writable = bool(sec_chars & IMAGE_SCN_MEM_WRITE)
                        is_wx = is_executable and is_writable

                        if is_wx:
                            wx_sections.append(sec_name)
                            anomalies.append(f"Section '{sec_name}' has W^X violation (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)")

                        if "UPX" in sec_name.upper():
                            anomalies.append(f"UPX packed section detected: '{sec_name}'")

                        # Size anomaly: VirtualSize significantly larger than RawSize
                        if raw_size == 0 and vsize > 0:
                            anomalies.append(f"Section '{sec_name}' has 0 raw bytes but non-zero virtual size {vsize} (decompression buffer)")
                        elif raw_size > 0 and vsize > 3 * raw_size:
                            anomalies.append(f"Section '{sec_name}' virtual size ({vsize}) > 3x raw size ({raw_size})")

                        # Out of bounds check
                        if raw_size > 0 and raw_ptr + raw_size > len(data):
                            anomalies.append(f"Section '{sec_name}' raw data ({hex(raw_ptr)}..{hex(raw_ptr + raw_size)}) extends beyond file boundary ({hex(len(data))})")

                        # Entropy calculation for section raw data
                        sec_entropy = 0.0
                        if raw_size > 0 and raw_ptr < len(data):
                            avail_data = data[raw_ptr:min(len(data), raw_ptr + raw_size)]
                            sec_entropy = calculate_entropy(avail_data)

                        sections.append({
                            "name": sec_name,
                            "virtual_size": vsize,
                            "virtual_address": hex(vaddr),
                            "raw_data_size": raw_size,
                            "raw_data_pointer": hex(raw_ptr),
                            "characteristics": hex(sec_chars),
                            "is_executable": is_executable,
                            "is_writable": is_writable,
                            "is_wx": is_wx,
                            "entropy": sec_entropy,
                        })

                pe_info["sections"] = sections
                pe_info["has_wx_sections"] = bool(wx_sections)
                pe_info["wx_sections"] = wx_sections
                pe_info["section_anomalies"] = anomalies
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

    # 5. Java Class Bytecode vs Mach-O Universal FAT Binary
    if data.startswith(b"\xca\xfe\xba\xbf"):
        nfat_arch = struct.unpack(">I", data[4:8])[0] if len(data) >= 8 else 0
        return {
            "format": "Mach-O",
            "os": "macOS/iOS",
            "description": f"Apple Mach-O Universal FAT 64-bit Binary ({nfat_arch} architectures)",
            "fat_arch_count": nfat_arch,
        }

    if data.startswith(b"\xca\xfe\xba\xbe"):
        if len(data) >= 8:
            minor, major = struct.unpack(">HH", data[4:8])
            nfat_arch = struct.unpack(">I", data[4:8])[0]
            if 45 <= major <= 75:
                return {
                    "format": "JAVA_CLASS",
                    "os": "JVM",
                    "description": f"Compiled Java Class Bytecode (major {major}, minor {minor})",
                    "major_version": major,
                    "minor_version": minor,
                }
            if 1 <= nfat_arch <= 32:
                return {
                    "format": "Mach-O",
                    "os": "macOS/iOS",
                    "description": f"Apple Mach-O Universal FAT Binary ({nfat_arch} architectures)",
                    "fat_arch_count": nfat_arch,
                }
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
    """Extract printable strings with exact hex offsets and identify potential Indicators of Compromise (IOCs)."""
    string_entries: List[Tuple[str, int, str]] = []  # (text, offset, encoding)

    # 1. Extract ASCII strings (min len 4) with offsets
    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        s_text = m.group(0).decode("ascii", "replace")
        string_entries.append((s_text, m.start(), "ascii"))

    # 2. Extract UTF-16LE strings (min len 4 wide chars = 8 bytes) with offsets
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data):
        try:
            s_text = m.group(0).decode("utf-16le", "replace")
            string_entries.append((s_text, m.start(), "utf-16le"))
        except Exception:
            pass

    decoded_strings: List[str] = [entry[0] for entry in string_entries]

    # Extract specific IOC categories with exact hex offsets
    urls: List[str] = []
    ips: List[str] = []
    registry_keys: List[str] = []
    suspicious_apis: List[str] = []
    detailed_iocs: List[Dict[str, Any]] = []

    for text, offset, encoding in string_entries:
        # URLs
        for m in URL_PATTERN.finditer(text):
            u = m.group(0)
            u_offset = offset + (m.start() if encoding == "ascii" else m.start() * 2)
            if u not in urls:
                urls.append(u)
                detailed_iocs.append({
                    "type": "url",
                    "value": u,
                    "offset": u_offset,
                    "offset_hex": f"0x{u_offset:08x}",
                })
        # IPs
        for m in IPV4_PATTERN.finditer(text):
            ip = m.group(0)
            ip_offset = offset + (m.start() if encoding == "ascii" else m.start() * 2)
            if ip not in ips:
                ips.append(ip)
                detailed_iocs.append({
                    "type": "ip",
                    "value": ip,
                    "offset": ip_offset,
                    "offset_hex": f"0x{ip_offset:08x}",
                })
        # Registry
        for m in REGISTRY_PATTERN.finditer(text):
            r = m.group(0)
            r_offset = offset + (m.start() if encoding == "ascii" else m.start() * 2)
            if r not in registry_keys:
                registry_keys.append(r)
                detailed_iocs.append({
                    "type": "registry",
                    "value": r,
                    "offset": r_offset,
                    "offset_hex": f"0x{r_offset:08x}",
                })

    # Suspicious API keywords: match raw bytes (ASCII) with offsets
    for pat in SUSPICIOUS_API_PATTERNS:
        for m in pat.finditer(data):
            val = m.group(0).decode("ascii", "replace")
            api_offset = m.start()
            if val not in suspicious_apis:
                suspicious_apis.append(val)
                detailed_iocs.append({
                    "type": "api",
                    "value": val,
                    "offset": api_offset,
                    "offset_hex": f"0x{api_offset:08x}",
                })

    # Match suspicious API patterns against decoded UTF-16LE strings as well
    for text, offset, encoding in string_entries:
        if encoding == "utf-16le":
            for pat in SUSPICIOUS_API_PATTERNS:
                pat_str = pat.pattern.decode("ascii", "replace")
                m = re.search(pat_str, text, re.IGNORECASE)
                if m:
                    val = m.group(0)
                    api_offset = offset + (m.start() * 2)
                    if val not in suspicious_apis:
                        suspicious_apis.append(val)
                        detailed_iocs.append({
                            "type": "api",
                            "value": val,
                            "offset": api_offset,
                            "offset_hex": f"0x{api_offset:08x}",
                        })

    return {
        "total_extracted_strings": len(decoded_strings),
        "suspicious_apis_detected": suspicious_apis[:20],
        "urls_detected": urls[:20],
        "ips_detected": ips[:20],
        "registry_keys_detected": registry_keys[:20],
        "detailed_iocs": detailed_iocs,
        "sample_strings": decoded_strings[:max_strings],
    }


# ---------------------------------------------------------------------------
# Deep static analysis (still zero-execution)
# ---------------------------------------------------------------------------

#: PE data-directory index -> label (only the entries with defensive value).
PE_DIRECTORY_LABELS: Dict[int, str] = {
    0: "Export Table",
    1: "Import Table",
    2: "Resource Table",
    3: "Exception Table",
    4: "Certificate Table (Authenticode)",
    5: "Base Relocation Table",
    6: "Debug Directory",
    9: "TLS Table (callbacks)",
    10: "Load Configuration",
    12: "IAT",
    13: "Delay Import Descriptor",
    14: "CLR Runtime Header (.NET)",
}

#: Implant / tooling markers expressed as defensive detection signatures.
#: Data-only: every entry maps an artifact string to the ATT&CK technique it
#: is consistent with. No offensive capability is represented here.
IMPLANT_SIGNATURE_RULES: List[Dict[str, str]] = [
    {"name": "Reflective loader stub", "pattern": r"reflectiveload",
     "technique_id": "T1620", "tactic": "Stealth",
     "description": "In-memory PE loader stub marker (fileless module loading)."},
    {"name": "C2 submit endpoint", "pattern": r"(?:submit|gate|panel)\.php\b",
     "technique_id": "T1071.001", "tactic": "Command and Control",
     "description": "HTTP beacon callback endpoint pattern."},
    {"name": "Directory/domain discovery tooling", "pattern": r"(?:sharphound|bloodhound|adfind)",
     "technique_id": "T1087", "tactic": "Discovery",
     "description": "Active Directory enumeration tooling marker."},
    {"name": "Remote access utility", "pattern": r"(?:anydesk|teamviewer|screenconnect|atera)",
     "technique_id": "T1219", "tactic": "Command and Control",
     "description": "Commercial remote-monitoring tool used for hands-on access."},
    {"name": "Tunnelling/proxy utility", "pattern": r"(?:ngrok|chisel|socat|frpc?\b)",
     "technique_id": "T1572", "tactic": "Command and Control",
     "description": "Protocol tunnelling or reverse-proxy utility marker."},
    {"name": "Cloud sync exfiltration tooling", "pattern": r"(?:rclone|mega\.nz|anonfiles|transfer\.sh)",
     "technique_id": "T1567", "tactic": "Exfiltration",
     "description": "Exfiltration to a cloud storage service."},
    {"name": "Anonymising network client", "pattern": r"(?:tor\b|\.onion\b|snowflake\b)",
     "technique_id": "T1090.003", "tactic": "Command and Control",
     "description": "Anonymising proxy or Tor hidden-service usage."},
    {"name": "Credential-harvest toolkit", "pattern": r"(?:lazagne|pypykatz|secretsdump)",
     "technique_id": "T1003", "tactic": "Credential Access",
     "description": "Credential harvesting toolkit marker."},
    {"name": "Lateral movement framework", "pattern": r"(?:crackmapexec|impacket|psexec)",
     "technique_id": "T1021", "tactic": "Lateral Movement",
     "description": "Remote-service lateral movement framework marker."},
    {"name": "Script-host invocation", "pattern": r"mshta(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?",
     "technique_id": "T1218", "tactic": "Stealth",
     "description": "Signed script-host binary proxy execution marker."},
]


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        return 0
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, offset)[0]


def analyze_pe_deep(data: bytes, pe_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Extract deeper PE structure signals without ever executing the artifact.

    Adds overlay (appended payload) detection, data-directory presence, an
    entry-point-to-section mapping, and entry-point section anomalies on top of
    the header dissection already performed by ``parse_magic_header``.
    """
    result: Dict[str, Any] = {
        "available": False,
        "overlay": {"present": False, "size": 0, "entropy": 0.0, "offset_hex": "0x0"},
        "directories": {},
        "entry_point": {},
        "anomalies": [],
    }
    if not data or len(data) < 0x40 or not data.startswith(b"MZ"):
        return result

    pe_offset = _u32(data, 0x3C)
    if not (0x40 <= pe_offset <= len(data) - 24) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return result
    result["available"] = True

    opt_offset = pe_offset + 24
    optional_magic = _u16(data, opt_offset)
    is_pe32_plus = optional_magic == 0x20B
    directories_offset = opt_offset + (112 if is_pe32_plus else 96)

    directories: Dict[str, Dict[str, Any]] = {}
    if directories_offset + 8 <= len(data):
        for index, label in PE_DIRECTORY_LABELS.items():
            rva = _u32(data, directories_offset + index * 8)
            size = _u32(data, directories_offset + index * 8 + 4)
            if rva or size:
                directories[label] = {"rva": hex(rva), "size": size}
                # TLS callbacks and a missing Authenticode signature are notable.
                if index == 9:
                    result["anomalies"].append(
                        "TLS callback directory present (code executes before the entry point)"
                    )
                if index == 4 and size == 0:
                    result["anomalies"].append("No Authenticode certificate table (binary is unsigned)")
    else:
        result["anomalies"].append("PE data directory table is truncated or malformed")
    result["directories"] = directories

    # Overlay: any bytes after the end of the last mapped section.
    raw_end = 0
    for section in (pe_info or {}).get("sections", []) or []:
        try:
            ptr = int(section.get("raw_data_pointer", "0x0"), 16)
            size = int(section.get("raw_data_size", 0) or 0)
        except (TypeError, ValueError):
            continue
        raw_end = max(raw_end, ptr + size)
    if raw_end and 0 < raw_end < len(data):
        overlay = data[raw_end:]
        h = calculate_entropy(overlay)
        result["overlay"] = {
            "present": True,
            "size": len(overlay),
            "entropy": h,
            "offset_hex": f"0x{raw_end:08x}",
        }
        if len(overlay) >= 512 and h >= 6.5:
            result["anomalies"].append(
                f"High-entropy overlay of {len(overlay)} bytes at {hex(raw_end)} "
                "(appended or compressed payload)"
            )

    # Entry point -> section mapping.
    entry_rva = _u32(data, opt_offset + 16)
    ep_section = None
    for section in (pe_info or {}).get("sections", []) or []:
        try:
            vaddr = int(section.get("virtual_address", "0x0"), 16)
        except (TypeError, ValueError):
            continue
        vsize = int(section.get("virtual_size", 0) or 0)
        if vaddr <= entry_rva < vaddr + max(vsize, 1):
            ep_section = section
            break
    result["entry_point"] = {
        "rva": hex(entry_rva),
        "section": (ep_section or {}).get("name", "unmapped"),
    }
    if ep_section is not None:
        if ep_section.get("is_writable"):
            result["anomalies"].append(
                f"Entry point resolves into writable section '{ep_section.get('name')}'"
            )
        if float(ep_section.get("entropy", 0.0) or 0.0) >= 7.2:
            result["anomalies"].append(
                f"Entry-point section '{ep_section.get('name')}' has high entropy "
                f"({ep_section.get('entropy')}), suggesting packing"
            )
    return result


def detect_implant_signatures(data: bytes, max_hits: int = 20) -> List[Dict[str, Any]]:
    """Match implant/tooling markers against raw bytes and map them to ATT&CK."""
    hits: List[Dict[str, Any]] = []
    for rule in IMPLANT_SIGNATURE_RULES:
        try:
            regex = re.compile(rule["pattern"].encode("ascii"), re.IGNORECASE)
        except re.error:
            continue
        match = regex.search(data)
        if match:
            hits.append({
                "name": rule["name"],
                "marker": match.group(0).decode("ascii", "replace"),
                "offset_hex": f"0x{match.start():08x}",
                "technique_id": rule["technique_id"],
                "tactic": rule["tactic"],
                "description": rule["description"],
            })
        if len(hits) >= max_hits:
            break
    return hits


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
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5(usedforsecurity=False)  # Forensic IOC checksum (non-cryptographic)
            analysis_chunks: List[bytes] = []
            bytes_read_for_analysis = 0

            # Stream in 64KB chunks to hash entire file correctly while capping analysis buffer
            with p.open("rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
                    if bytes_read_for_analysis < max_bytes:
                        take = min(len(chunk), max_bytes - bytes_read_for_analysis)
                        analysis_chunks.append(chunk[:take])
                        bytes_read_for_analysis += take

            data = b"".join(analysis_chunks)
            sha256 = sha256_hash.hexdigest()
            md5 = md5_hash.hexdigest()

            # Global & block entropy
            global_entropy = calculate_entropy(data)
            block_entropy = calculate_block_entropy(data, block_size=1024)

            # Header / format dissection
            header_info = parse_magic_header(data)
            pe_deep = analyze_pe_deep(data, header_info) if header_info.get("format") == "PE" else {}
            implants = detect_implant_signatures(data)

            # IOC String extraction
            ioc_info = extract_ioc_strings(data)

            # Build Evidence-Finding Path:
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
            if header_info.get("has_wx_sections"):
                evidence_chain.append(
                    f"[CONFIRMED W^X VIOLATION]: Section(s) {', '.join(header_info.get('wx_sections', []))} have simultaneous Write + Execute permissions."
                )
            for anomaly in header_info.get("section_anomalies", []):
                evidence_chain.append(f"[PE SECTION ANOMALY]: {anomaly}")

            # Record IOCs with exact hex offsets:
            for item in ioc_info.get("detailed_iocs", []):
                ioc_t = item["type"]
                ioc_hex = item["offset_hex"]
                ioc_val = item["value"]
                if ioc_t == "api":
                    evidence_chain.append(f"[CONFIRMED SUSPICIOUS APIS] @ {ioc_hex}: {ioc_val}")
                elif ioc_t == "url":
                    evidence_chain.append(f"[IOC URLS] @ {ioc_hex}: {ioc_val}")
                elif ioc_t == "ip":
                    evidence_chain.append(f"[IOC IPS] @ {ioc_hex}: {ioc_val}")
                elif ioc_t == "registry":
                    evidence_chain.append(f"[IOC PERSISTENCE] @ {ioc_hex}: {ioc_val}")

            # Also maintain summary tags if detailed_iocs had none (for backward compatibility)
            if not any("[CONFIRMED SUSPICIOUS APIS]" in x for x in evidence_chain) and ioc_info["suspicious_apis_detected"]:
                evidence_chain.append(f"[CONFIRMED SUSPICIOUS APIS]: {', '.join(ioc_info['suspicious_apis_detected'][:5])}")
            if not any("[IOC URLS]" in x for x in evidence_chain) and ioc_info["urls_detected"]:
                evidence_chain.append(f"[IOC URLS]: {', '.join(ioc_info['urls_detected'][:3])}")
            if not any("[IOC IPS]" in x for x in evidence_chain) and ioc_info["ips_detected"]:
                evidence_chain.append(f"[IOC IPS]: {', '.join(ioc_info['ips_detected'][:3])}")
            if not any("[IOC PERSISTENCE]" in x for x in evidence_chain) and ioc_info["registry_keys_detected"]:
                evidence_chain.append(f"[IOC PERSISTENCE]: {', '.join(ioc_info['registry_keys_detected'][:3])}")

            # Overall Risk Assessment
            risk = "Low"
            reasons = []
            if block_entropy["is_packed"]:
                risk = "High"
                reasons.append("High entropy packing detected")
            if header_info.get("has_wx_sections"):
                risk = "High"
                reasons.append("W^X violation: Section with simultaneous Write + Execute permissions detected")
            if header_info.get("section_anomalies"):
                if risk == "Low":
                    risk = "Medium"
                reasons.append(f"PE section anomalies: {', '.join(header_info.get('section_anomalies', [])[:2])}")
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

            # Deep PE structure signals (overlay, directories, entry point).
            if pe_deep.get("overlay", {}).get("present"):
                ov = pe_deep["overlay"]
                evidence_chain.append(
                    f"[OVERLAY] {ov['size']} bytes appended at {ov['offset_hex']} (entropy {ov['entropy']})"
                )
                if risk == "Low":
                    risk = "Medium"
                reasons.append("Appended overlay data present beyond the last section")
            for anomaly in pe_deep.get("anomalies", []):
                evidence_chain.append(f"[PE DEEP ANOMALY]: {anomaly}")
            if pe_deep.get("entry_point", {}).get("section"):
                evidence_chain.append(
                    f"[ENTRY POINT] {pe_deep['entry_point']['rva']} in section "
                    f"'{pe_deep['entry_point']['section']}'"
                )
            for imp in implants:
                evidence_chain.append(
                    f"[IMPLANT MARKER] {imp['technique_id']} {imp['name']} "
                    f"@ {imp['offset_hex']}: {imp['marker']}"
                )
            if implants:
                if risk in ("Low", "Medium"):
                    risk = "High"
                reasons.append(
                    f"Implant/tooling markers matched: {', '.join(i['name'] for i in implants[:3])}"
                )

            # Malware intelligence enrichment: imphash, fuzzy hash, family match,
            # and ATT&CK technique inference. Never executes the artifact.
            ioc_summary_text = " ".join(
                ioc_info["urls_detected"] + ioc_info["ips_detected"]
                + ioc_info["registry_keys_detected"] + ioc_info["suspicious_apis_detected"]
                + ioc_info["sample_strings"][:50]
            )
            intel = enrich_triage(sha256=sha256, md5=md5, data=data, ioc_summary_text=ioc_summary_text)
            if intel.get("imphash"):
                evidence_chain.append(f"[IMPHASH] {intel['imphash']} (import-hash cluster key)")
            if intel.get("fuzzy_hash"):
                evidence_chain.append(f"[FUZZY HASH] {intel['fuzzy_hash']}")
            for fam in intel.get("family_matches", [])[:3]:
                evidence_chain.append(
                    f"[FAMILY MATCH] {fam['family']} (score {fam['match_score']}, "
                    f"markers: {', '.join(fam['matched_markers'][:4])})"
                )
            for tech in intel.get("techniques", [])[:5]:
                evidence_chain.append(
                    f"[ATT&CK] {tech['technique_id']} {tech['technique_name']} ({tech['tactic']})"
                )
            if intel.get("family_matches") and risk == "Low":
                risk = "Medium"
                reasons.append("Signature matches a catalogued malware family")

            return {
                "success": True,
                "file_path": str(p),
                "file_size_bytes": file_size,
                "truncated": file_size > max_bytes,
                "hashes": {
                    "sha256": sha256,
                    "md5": md5,
                },
                "malware_intel": intel,
                "pe_deep_analysis": pe_deep,
                "implant_signatures": implants,
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
                    "detailed_iocs": ioc_info["detailed_iocs"],
                },
                "risk_assessment": {
                    "severity": risk,
                    "reasons": reasons if reasons else ["Clean static profile"],
                },
                "evidence_chain": evidence_chain,
            }
        except Exception as exc:
            return {"success": False, "error": f"Triage failed: {str(exc)}"}
