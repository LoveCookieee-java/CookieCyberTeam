"""
ATT&CK Technique Signature Catalog.

A curated, data-only catalog of offensive technique primitives expressed as
*defensive* detection signatures. Each entry maps an observed implementation
pattern (API call sequences, command-line markers, artifact strings) to a MITRE
ATT&CK technique and tactic, plus a severity and remediation note.

The catalog contains no offensive code and executes nothing. It powers the
dynamic SOC rule engine and the binary triage engine by reporting which
techniques a sample or log line is consistent with.

Zero external dependencies (Python stdlib only).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from core.soc_rules import SOCRule


@dataclass
class TechniqueSignature:
    """A single ATT&CK technique expressed as detection primitives."""

    technique_id: str
    technique_name: str
    tactic: str
    severity: str
    description: str
    api_signatures: List[str] = field(default_factory=list)
    command_markers: List[str] = field(default_factory=list)
    artifact_markers: List[str] = field(default_factory=list)
    match_logic: str = "any"
    remediation: str = ""
    source: str = "curated"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def patterns(self) -> List[str]:
        """All regex patterns that trigger this technique."""
        return list(self.api_signatures) + list(self.command_markers) + list(self.artifact_markers)


# ---------------------------------------------------------------------------
# Catalog data (defensive signatures only)
# ---------------------------------------------------------------------------

TECHNIQUE_CATALOG: List[TechniqueSignature] = [
    TechniqueSignature(
        technique_id="T1055.002",
        technique_name="Process Injection: Portable Executable Injection",
        tactic="Defense Evasion",
        severity="Critical",
        description="Maps/allocates executable memory in a remote process and starts a thread in it.",
        api_signatures=[r"virtualalloc",
                        r"virtualprotect",
                        r"writeprocessmemory",
                        r"createremotethread"],
        match_logic="all",
        remediation="Enable Credential Guard / LSA protection and monitor cross-process thread creation.",
        source="Rust-for-Malware-Development primitives",
    ),
    TechniqueSignature(
        technique_id="T1055.012",
        technique_name="Process Injection: Process Hollowing",
        tactic="Defense Evasion",
        severity="Critical",
        description="Creates a suspended process, unmaps its image, and replaces it with a payload.",
        api_signatures=[r"createprocess[^;]*suspend",
                        r"ntunmapviewofsection",
                        r"zwunmapviewofsection",
                        r"setthreadcontext",
                        r"resumethread"],
        match_logic="any",
        remediation="Alert on CreateProcess with CREATE_SUSPENDED combined with section unmapping.",
        source="Rust-for-Malware-Development primitives",
    ),
    TechniqueSignature(
        technique_id="T1055.004",
        technique_name="Process Injection: Asynchronous Procedure Call",
        tactic="Defense Evasion",
        severity="Critical",
        description="Queues an APC to a remote thread to execute the payload.",
        api_signatures=[r"ntqueueapcthread", r"queueuserapc"],
        remediation="Monitor QueueUserAPC from unexpected processes and enable Sysmon Event ID 8.",
        source="Rust-for-Malware-Development primitives",
    ),
    TechniqueSignature(
        technique_id="T1620",
        technique_name="Reflective Code Loading",
        tactic="Defense Evasion",
        severity="Critical",
        description="Loads a PE/DLL directly from memory without touching disk or the loader.",
        api_signatures=[r"reflectiveload", r"manualmap", r"loadlibrarya?\(\)\s*;?\s*//",
                        r"llvm\.memory\.", r"__attribute__\(\(constructor\)\)"],
        artifact_markers=[r"reflectiveloader", r"manualmap"],
        remediation="Detect unsigned in-memory modules; enable module load auditing (Sysmon ID 7).",
        source="Rust-for-Malware-Development primitives",
    ),
    TechniqueSignature(
        technique_id="T1497",
        technique_name="Virtualization/Sandbox Evasion",
        tactic="Defense Evasion",
        severity="Medium",
        description="Probes for analysis environments: VMs, debuggers, sandboxes, hosted artifacts.",
        api_signatures=[r"isdebuggerpresent", r"checkremotedebuggerpresent",
                        r"cpuid", r"getsystemfirmwaretable", r"queryperformancecounter"],
        artifact_markers=[r"vmware", r"virtualbox", r"vbox", r"qemu", r"sandbox",
                          r"wine_get_version", r"\d+\.\d+\.\d+\.\d+"],
        match_logic="any",
        remediation="Instrument timing checks and enumerate analysis-tool artifacts during detonation.",
        source="Rust-for-Malware-Development primitives",
    ),
    TechniqueSignature(
        technique_id="T1140",
        technique_name="Deobfuscate/Decode Files or Information",
        tactic="Defense Evasion",
        severity="High",
        description="Decodes embedded payloads at runtime (XOR loops, base64, RC4, AES blobs).",
        api_signatures=[r"xor\s*key", r"base64_decode", r"from_base64",
                        r"aes[-_]?(256|128)?decrypt", r"rc4", r"cryptdecrypt"],
        match_logic="any",
        remediation="Scan for high-entropy embedded blobs and XOR-key decryption routines.",
        source="Rust-for-Malware-Development primitives",
    ),
    TechniqueSignature(
        technique_id="T1218",
        technique_name="System Binary Proxy Execution (LOLBins)",
        tactic="Defense Evasion",
        severity="High",
        description="Abuses signed system binaries to proxy execution of untrusted content.",
        command_markers=[r"rundll32(?:\.exe)?\s+[^\r\n]*\.dll\s*,\s*\w+",
                         r"regsvr32(?:\.exe)?\s+[^\r\n]*/i:http",
                         r"mshta(?:\.exe)?\s+https?://",
                         r"installutil(?:\.exe)?\s+",
                         r"msbuild(?:\.exe)?\s+.*\.(?:xml|proj)",
                         r"wmic(?:\.exe)?\s+process\s+call\s+create"],
        match_logic="any",
        remediation="Constrain LOLBin execution with AppLocker/WDAC and monitor parent-child lineage.",
        source="Mindmap: execution methodology",
    ),
    TechniqueSignature(
        technique_id="T1218.011",
        technique_name="System Binary Proxy Execution: Rundll32",
        tactic="Defense Evasion",
        severity="High",
        description="Executes a DLL export (often JavaScript/VBScript) via rundll32.exe.",
        command_markers=[r"rundll32(?:\.exe)?\s+\w+\.dll\s*,\s*\w+",
                         r"rundll32(?:\.exe)?\s+javascript:",
                         r"rundll32(?:\.exe)?\s+[^\r\n]*\.(?:dll|ocx)\s*,[^\s]+"],
        remediation="Block unsigned DLL export invocation and inspect rundll32 command lines.",
        source="Mindmap: execution methodology",
    ),
    TechniqueSignature(
        technique_id="T1569.002",
        technique_name="System Services: Service Execution",
        tactic="Execution",
        severity="High",
        description="Creates or modifies a Windows service to execute a payload with SYSTEM rights.",
        command_markers=[r"sc(?:\.exe)?\s+create\s+", r"sc(?:\.exe)?\s+config\s+",
                         r"new-service", r"createprocessasuser\s*\(",
                         r"\.installexe\(\)", r"createservice[wa]?"],
        match_logic="any",
        remediation="Alert on service creation from non-standard parents; restrict service privileges.",
        source="Rust-for-Malware-Development primitives",
    ),
    TechniqueSignature(
        technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
        tactic="Persistence",
        severity="High",
        description="Registers persistence or execution through the Windows Task Scheduler.",
        command_markers=[r"schtasks(?:\.exe)?\s+/create",
                         r"register-scheduledtask",
                         r"/sc\s+(?:once|minute|hourly|daily|onlogon)"],
        match_logic="any",
        remediation="Monitor Task Scheduler operational logs (Event ID 106/4698) for new tasks.",
        source="Mindmap: persistence methodology",
    ),
    TechniqueSignature(
        technique_id="T1047",
        technique_name="Windows Management Instrumentation",
        tactic="Execution",
        severity="Medium",
        description="Uses WMI for execution, discovery, or persistence.",
        command_markers=[r"wmic(?:\.exe)?\s+", r"invoke-wmimethod", r"getobject\(\s*[\"']winmgmts"],
        remediation="Restrict WMI usage and monitor process creation with wmic.exe parents.",
        source="Mindmap: execution methodology",
    ),
    TechniqueSignature(
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        tactic="Command and Control",
        severity="High",
        description="Transfers an additional tool or payload onto the host (certutil, bitsadmin, curl).",
        command_markers=[r"certutil(?:\.exe)?\s+[^\r\n]*-urlcache",
                         r"certutil(?:\.exe)?\s+[^\r\n]*-decode",
                         r"bitsadmin(?:\.exe)?\s+/transfer",
                         r"start-bitstransfer",
                         r"curl(?:\.exe)?\s+[^\r\n]*\s+-o\s+",
                         r"wget\s+[^\r\n]*\s+-o\s+",
                         r"invoke-webrequest"],
        match_logic="any",
        remediation="Block outbound tool transfer via firewall/DNS and monitor LOLBin download patterns.",
        source="Mindmap: C2 methodology",
    ),
    TechniqueSignature(
        technique_id="T1082",
        technique_name="System Information Discovery",
        tactic="Discovery",
        severity="Low",
        description="Enumerates host/system information prior to staging.",
        command_markers=[r"\bsysteminfo\b", r"\bhostname\b", r"\bwhoami\b",
                         r"getsysteminfo\s*\(", r"uname\s+-\w+"],
        match_logic="any",
        remediation="Baseline discovery commands and alert on bursts from a single parent.",
        source="Mindmap: discovery methodology",
    ),
    TechniqueSignature(
        technique_id="T1083",
        technique_name="File and Directory Discovery",
        tactic="Discovery",
        severity="Low",
        description="Enumerates the filesystem looking for targets or staging locations.",
        command_markers=[r"findfirstfile[wa]?", r"findnextfile[wa]?",
                         r"os\.walk\s*\(", r"\bdir\s+/s\b", r"\bls\s+-r\b"],
        match_logic="any",
        remediation="Monitor rapid recursive directory enumeration against sensitive paths.",
        source="Mindmap: discovery methodology",
    ),
    TechniqueSignature(
        technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        severity="High",
        description="Encodes or encrypts content to evade signature detection.",
        artifact_markers=[r"-[Ee]nc(?:odedcommand)?\b", r"FromBase64String",
                          r"chr\(\d+\)\s*\+", r"eval\(\s*base64",
                          r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}"],
        match_logic="any",
        remediation="Decode and inspect encoded blobs; enable script block logging.",
        source="Mindmap: evasion methodology",
    ),
    TechniqueSignature(
        technique_id="T1571",
        technique_name="Non-Standard Port",
        tactic="Command and Control",
        severity="Medium",
        description="Communicates over a port not typically associated with the protocol.",
        artifact_markers=[r"https?://[a-zA-Z0-9_.\-]+:(?:4444|1337|8081|9001|31337)\b",
                          r"reverse_tcp", r"meterpreter", r"beacon"],
        match_logic="any",
        remediation="Sinkhole non-standard egress ports and inspect beacon jitter in PCAP.",
        source="Mindmap: C2 methodology",
    ),
    TechniqueSignature(
        technique_id="T1036",
        technique_name="Masquerading",
        tactic="Defense Evasion",
        severity="Medium",
        description="Names or modifies artifacts to appear legitimate or trusted.",
        artifact_markers=[r"svchost32", r"lsasss", r"explorer\.exe\s+\"",
                          r"microsoft\s+corporation\s+-\s+", r"\.pdf\.exe\b",
                          r"\.docx\.scr\b"],
        match_logic="any",
        remediation="Verify digital signatures and flag near-miss process/file names.",
        source="Mindmap: evasion methodology",
    ),
    TechniqueSignature(
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        severity="High",
        description="Beacons over HTTP(S) using embedded URLs or user agents.",
        artifact_markers=[r"User-Agent:\s*(?:python|curl|powershell)",
                          r"https?://[a-zA-Z0-9_.\-]+/(?:gate|panel|beacon|api/v\d)",
                          r"cookie:\s*[A-Za-z0-9+/=]{20,}"],
        match_logic="any",
        remediation="Inspect anomalous user agents and periodic HTTP(S) beaconing.",
        source="Mindmap: C2 methodology",
    ),
]


#: Additional curated signatures. Kept separate from the original block so the
#: base catalog data stays untouched while the surface grows.
TECHNIQUE_CATALOG.extend([
    TechniqueSignature(
        technique_id="T1059.004",
        technique_name="Command and Scripting Interpreter: Unix Shell",
        tactic="Execution",
        severity="Medium",
        description="Executes commands through a Unix shell interpreter.",
        command_markers=[r"/bin/(?:ba|z|da)?sh\b", r"\bsh\s+-c\b", r"\bbash\s+-c\b",
                         r"\bzsh\s+-c\b"],
        match_logic="any",
        remediation="Constrain shell execution with least privilege and command allow-lists.",
        source="curated",
    ),
    TechniqueSignature(
        technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        tactic="Command and Control",
        severity="High",
        description="Uses DNS queries (including TXT and DoH) to carry command or exfiltration data.",
        artifact_markers=[r"\b(?:dns|doh)\s*(?:tunnel|exfil)",
                          r"https?://[^/\s]+/dns-query",
                          r"\bnslookup\b[^\r\n]*\btxt\b"],
        match_logic="any",
        remediation="Inspect long or high-entropy DNS labels and block unauthorised resolvers.",
        source="curated",
    ),
    TechniqueSignature(
        technique_id="T1021",
        technique_name="Remote Services",
        tactic="Lateral Movement",
        severity="High",
        description="Logs on to a remote service to move laterally (SMB, WMI, WinRM, SSH).",
        command_markers=[r"net\s+use\s+\\\\", r"psexec", r"crackmapexec", r"impacket",
                         r"\bwinrs\b", r"wmic(?:\.exe)?\s[^\r\n]*/node:",
                         r"ssh\s+-o\s+StrictHostKeyChecking"],
        match_logic="any",
        remediation="Segment remote administration paths and require bastion-mediated access.",
        source="curated",
    ),
    TechniqueSignature(
        technique_id="T1567",
        technique_name="Exfiltration Over Web Service",
        tactic="Exfiltration",
        severity="High",
        description="Moves collected data to an external web or cloud service.",
        artifact_markers=[r"rclone\s+copy", r"mega\.nz", r"anonfiles", r"transfer\.sh",
                          r"api\.telegram\.org/bot", r"discord(?:app)?\.com/api/webhooks",
                          r"pastebin\.com/raw"],
        match_logic="any",
        remediation="Allow-list egress destinations and alert on bulk uploads to storage services.",
        source="curated",
    ),
    TechniqueSignature(
        technique_id="T1090.003",
        technique_name="Proxy: Multi-hop Proxy",
        tactic="Command and Control",
        severity="Medium",
        description="Chains proxies or anonymity networks to conceal command-and-control traffic.",
        artifact_markers=[r"\.onion\b", r"\btor(?:\.exe)?\b", r"\bngrok\b", r"\bchisel\b",
                          r"\bsocat\b", r"\bcloudflared\b"],
        match_logic="any",
        remediation="Block anonymity networks and unauthorised tunnelling endpoints at the perimeter.",
        source="curated",
    ),
    TechniqueSignature(
        technique_id="T1219",
        technique_name="Remote Access Software",
        tactic="Command and Control",
        severity="Medium",
        description="Uses commercial remote-monitoring and management software for interactive access.",
        artifact_markers=[r"anydesk", r"teamviewer", r"screenconnect", r"atera", r"logmein"],
        match_logic="any",
        remediation="Maintain an approved remote-access allow-list and flag unapproved agents.",
        source="curated",
    ),
    TechniqueSignature(
        technique_id="T1572",
        technique_name="Protocol Tunneling",
        tactic="Command and Control",
        severity="Medium",
        description="Tunnels traffic inside an allowed protocol to bypass network controls.",
        artifact_markers=[r"\bsocat\b", r"\bstunnel\b", r"\biodine\b", r"\bdns2tcp\b",
                          r"ssh\s+-[LRD]\b"],
        match_logic="any",
        remediation="Inspect tunnelled sessions and restrict port-forwarding on egress gateways.",
        source="curated",
    ),
    TechniqueSignature(
        technique_id="T1087",
        technique_name="Account Discovery",
        tactic="Discovery",
        severity="Low",
        description="Enumerates local or domain accounts to enable later access.",
        command_markers=[r"\bnet\s+user\b", r"\bnet\s+group\b", r"\bdsquery\b",
                         r"sharphound", r"bloodhound", r"adfind", r"\bwhoami\s+/all\b"],
        match_logic="any",
        remediation="Baseline directory-enumeration tools and alert on bursts from one principal.",
        source="curated",
    ),
    TechniqueSignature(
        technique_id="T1112",
        technique_name="Modify Registry",
        tactic="Stealth",
        severity="Medium",
        description="Modifies the Windows Registry to persist, evade, or weaken a control.",
        command_markers=[r"reg(?:\.exe)?\s+add\b", r"reg(?:\.exe)?\s+import\b",
                         r"Set-ItemProperty[^\r\n]*HKLM", r"New-ItemProperty[^\r\n]*HKCU",
                         r"regedit(?:\.exe)?\s[^\r\n]*/s\b"],
        match_logic="any",
        remediation="Monitor registry writes to autorun and security-policy keys (Sysmon 12/13).",
        source="curated",
    ),
    TechniqueSignature(
        technique_id="F1007",
        technique_name="Adversary-in-the-Browser",
        tactic="Positioning",
        severity="High",
        description="Manipulates a live banking/browser session to prepare account fraud (MITRE F3).",
        artifact_markers=[r"add\s+beneficiary", r"payee\s+setup", r"session\s+cookie\s+replay",
                          r"browser\s+extension[^\r\n]*inject"],
        match_logic="any",
        remediation="Bind sessions to device, re-authenticate for beneficiary changes, alert on session replay.",
        source="MITRE F3 v1.1",
    ),
    TechniqueSignature(
        technique_id="F1025.003",
        technique_name="Wire Transfer",
        tactic="Monetization",
        severity="High",
        description="Moves fraudulently obtained funds out of the victim account (MITRE F3).",
        artifact_markers=[r"wire\s+transfer", r"\brtgs\b", r"swift\s+messag", r"interbank\s+transfer"],
        match_logic="any",
        remediation="Apply velocity limits and out-of-band call-back verification on new payees.",
        source="MITRE F3 v1.1",
    ),
])

#: ATT&CK v19.1 moved several behaviours under the new Defense Impairment tactic.
#: Overrides are kept separate so the original signature data stays stable.
TACTIC_OVERRIDES_V19_1: Dict[str, str] = {
    "T1562": "Defense Impairment",
    "T1562.001": "Defense Impairment",
    "T1562.004": "Defense Impairment",
}


def tactic_index() -> Dict[str, str]:
    """Return a {technique_id: tactic} index applying v19.1 tactic overrides."""
    index: Dict[str, str] = {}
    for sig in TECHNIQUE_CATALOG:
        ident = sig.technique_id.upper()
        index[ident] = TACTIC_OVERRIDES_V19_1.get(ident, sig.tactic)
        base = ident.split(".")[0]
        index.setdefault(base, TACTIC_OVERRIDES_V19_1.get(base, sig.tactic))
    return index


def get_technique(technique_id: str) -> Optional[Dict[str, Any]]:
    """Look up a technique by id (e.g. 'T1055.002' or 'T1055')."""
    ident = technique_id.strip().upper()
    for sig in TECHNIQUE_CATALOG:
        if sig.technique_id.upper() == ident:
            return sig.to_dict()
    # Allow base-technique match to a sub-technique.
    for sig in TECHNIQUE_CATALOG:
        if sig.technique_id.upper().startswith(ident + "."):
            return sig.to_dict()
    return None


def list_techniques(tactic: Optional[str] = None) -> List[Dict[str, Any]]:
    """List catalog techniques, optionally filtered by tactic."""
    if tactic:
        t = tactic.strip().lower()
        return [s.to_dict() for s in TECHNIQUE_CATALOG if s.tactic.lower() == t]
    return [s.to_dict() for s in TECHNIQUE_CATALOG]


def search_techniques(text: str) -> List[Dict[str, Any]]:
    """Return techniques whose signatures match the supplied text."""
    import re

    hits: List[Dict[str, Any]] = []
    if not text:
        return hits
    for sig in TECHNIQUE_CATALOG:
        matched = [p for p in sig.patterns() if re.search(p, text, re.IGNORECASE)]
        if matched:
            d = sig.to_dict()
            d["matched_signatures"] = matched
            hits.append(d)
    return hits


def catalog_soc_rules() -> List[SOCRule]:
    """Adapt the catalog into SOCRule objects for the dynamic rule engine."""
    rules: List[SOCRule] = []
    for sig in TECHNIQUE_CATALOG:
        rules.append(
            SOCRule(
                id=f"SOC-{sig.technique_id.replace('.', '-')}-CAT",
                name=sig.technique_name,
                technique_id=sig.technique_id,
                technique_name=sig.technique_name,
                severity=sig.severity,
                description=sig.description,
                patterns=sig.patterns(),
                match_logic=sig.match_logic,
                containment_playbook=[
                    f"1. Isolate the host and preserve volatile evidence for {sig.technique_id}.",
                    "2. Terminate the offending process tree after snapshotting memory.",
                ],
                remediation_playbook=[
                    f"1. {sig.remediation}" if sig.remediation else
                    "1. Apply least-privilege hardening relevant to this technique.",
                ],
            )
        )
    return rules
