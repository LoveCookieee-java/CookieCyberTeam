"""
Pure-Python Dynamic SOC Detection Rule Engine & Playbook Dispatcher.
Features:
- MITRE ATT&CK Technique Mapping (T1055, T1059, T1003, T1071, T1547.001, T1562.001, T1070.001, T1486, T1505.003, T1027)
- Regex pattern matching with 'any' / 'all' evaluation logic
- Zero external dependencies (Python stdlib: re, dataclasses, typing)
- Automated Incident Containment & Remediation Playbooks
- Seamless integration with Binary Triage Engine and MCP Server
"""

from __future__ import annotations
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class SOCRule:
    """Detection rule structure representing a SOC analytic."""
    id: str
    name: str
    technique_id: str
    technique_name: str
    severity: str  # 'Critical', 'High', 'Medium', 'Low'
    description: str
    patterns: List[str]
    match_logic: str = "any"  # 'any' or 'all'
    containment_playbook: List[str] = field(default_factory=list)
    remediation_playbook: List[str] = field(default_factory=list)

    def __init__(
        self,
        id: Optional[str] = None,
        name: Optional[str] = None,
        technique_id: str = "",
        technique_name: str = "",
        severity: str = "Medium",
        description: str = "",
        patterns: Optional[List[str]] = None,
        match_logic: str = "any",
        containment_playbook: Optional[List[str]] = None,
        remediation_playbook: Optional[List[str]] = None,
        rule_id: Optional[str] = None,
        title: Optional[str] = None,
    ):
        self.id = id or rule_id or "SOC-CUSTOM"
        self.name = name or title or "Custom SOC Rule"
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.severity = severity
        self.description = description
        self.patterns = patterns or []
        self.match_logic = match_logic
        self.containment_playbook = containment_playbook or []
        self.remediation_playbook = remediation_playbook or []

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["rule_id"] = self.id
        d["title"] = self.name
        return d


DEFAULT_SOC_RULES: List[SOCRule] = [
    SOCRule(
        id="SOC-T1055-01",
        name="Process Injection & Remote Memory Allocation",
        technique_id="T1055",
        technique_name="Process Injection",
        severity="Critical",
        description="Detects suspicious API calls commonly used for process injection, shellcode delivery, and memory manipulation.",
        patterns=[
            r"createremotethread",
            r"writeprocessmemory",
            r"virtualalloc",
            r"ntqueueapcthread",
            r"setwindowshook",
        ],
        match_logic="any",
        containment_playbook=[
            "1. Immediately isolate the affected endpoint from the corporate network.",
            "2. Forcefully terminate the offending process tree and dump process memory for forensic analysis.",
            "3. Inspect virtual memory allocations for PAGE_EXECUTE_READWRITE (W^X violation) sections.",
        ],
        remediation_playbook=[
            "1. Re-image the compromised host from a clean, verified golden image.",
            "2. Revoke and rotate all host credentials, Kerberos tickets, and cached API tokens.",
            "3. Submit dumped shellcode payload to Blue Team sandbox for static extraction.",
        ],
    ),
    SOCRule(
        id="SOC-T1059-01",
        name="PowerShell Download Cradle & Encoded Execution",
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        severity="High",
        description="Detects PowerShell invoking web download cradles or executing encoded commands to bypass defenses.",
        patterns=[
            r"powershell(?:\.exe)?",
            r"downloadstring|downloadfile|invoke-expression|\biex\b|-enc\s+|-nop\b|bypass",
        ],
        match_logic="all",
        containment_playbook=[
            "1. Block outbound internet access for powershell.exe on endpoint and boundary firewalls.",
            "2. Query PowerShell ScriptBlock logging (Event ID 4104) and transcription logs for the full command line.",
        ],
        remediation_playbook=[
            "1. Deploy AppLocker or Windows Defender Application Control (WDAC) enforcing ConstrainedLanguage Mode.",
            "2. Audit Group Policy Objects (GPOs) to restrict unmanaged script execution.",
        ],
    ),
    SOCRule(
        id="SOC-T1003-01",
        name="OS Credential Dumping & LSASS Access",
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        severity="Critical",
        description="Detects known credential harvesting tools, LSASS memory access, and password extraction strings.",
        patterns=[
            r"mimikatz",
            r"sekurlsa",
            r"lsass\.exe",
            r"samlib\.dll",
            r"wdigest\.dll",
        ],
        match_logic="any",
        containment_playbook=[
            "1. Immediately isolate the workstation or Domain Controller to prevent lateral movement.",
            "2. Terminate any unauthorized processes accessing LSASS handles.",
        ],
        remediation_playbook=[
            "1. Execute enterprise-wide KRBTGT password reset and reset credentials for exposed domain accounts.",
            "2. Enable Windows Credential Guard and LSA Protection (RunAsPPL).",
            "3. Disable WDigest credential caching in the Windows Registry.",
        ],
    ),
    SOCRule(
        id="SOC-T1071-01",
        name="Command and Control Application Layer Protocol Beaconing",
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        severity="High",
        description="Detects Indicators of Compromise pointing to external C2 frameworks, reverse TCP handlers, or beacon endpoints.",
        patterns=[
            r"beacon|meterpreter|reverse_tcp",
            r"https?://[a-zA-Z0-9_\-\.]+(?::[0-9]+)?/[^\s\"\'<>]+",
        ],
        match_logic="any",
        containment_playbook=[
            "1. Blacklist identified C2 IP addresses and domain names at the edge firewall and DNS sinkhole.",
            "2. Terminate all active network sockets associated with the suspicious process.",
        ],
        remediation_playbook=[
            "1. Inspect network perimeter PCAP traffic for data exfiltration during the active beacon window.",
            "2. Update network IDS/IPS detection signatures across all corporate sensor gateways.",
        ],
    ),
    SOCRule(
        id="SOC-T1547-01",
        name="Autostart Execution via Registry Run Keys",
        technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
        severity="Medium",
        description="Detects binary persistence mechanisms installed in CurrentVersion\\Run or RunOnce Registry hives.",
        patterns=[
            r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|Software\\Microsoft\\Windows\\CurrentVersion)\\Run[^\s\"\'<>]*",
        ],
        match_logic="any",
        containment_playbook=[
            "1. Remove or quarantine the unauthorized Run key entry from the Windows Registry.",
            "2. Quarantine the persistence binary payload referenced by the registry entry.",
        ],
        remediation_playbook=[
            "1. Perform an enterprise autoruns audit across all endpoints using Sysinternals Autoruns.",
            "2. Enable Sysmon Event ID 12/13 to monitor registry key creation and tampering.",
        ],
    ),
    SOCRule(
        id="SOC-T1562-01",
        name="Impair Defenses: AMSI & Antivirus Tampering",
        technique_id="T1562.001",
        technique_name="Impair Defenses: Disable or Modify Tools",
        severity="Critical",
        description="Detects tampering with antivirus real-time monitoring, AMSI buffer patching, ETW logging disabling, or minifilter driver unloading.",
        patterns=[
            r"Set-MpPreference\s+-(?:DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableScriptScanning)",
            r"AmsiScanBuffer",
            r"EtwEventWrite",
            r"fltmc(?:\.exe)?\s+unload",
        ],
        match_logic="any",
        containment_playbook=[
            "1. Isolate the compromised host immediately from the corporate network.",
            "2. Re-enable Windows Defender realtime monitoring and re-verify tamper protection via GPO.",
            "3. Terminate the offending process and examine memory for AMSI/ETW hooks.",
        ],
        remediation_playbook=[
            "1. Enforce Windows Defender Tamper Protection and RunAsPPL on LSA.",
            "2. Deploy WDAC (Windows Defender Application Control) policy to block unsigned filter drivers.",
        ],
    ),
    SOCRule(
        id="SOC-T1070-01",
        name="Indicator Removal: Event Log Clearing & History Deletion",
        technique_id="T1070.001",
        technique_name="Indicator Removal: Clear Windows Event Logs",
        severity="High",
        description="Detects clearing of Windows Event Logs or shell command history to hinder incident response and forensic analysis.",
        patterns=[
            r"wevtutil(?:\.exe)?\s+(?:cl|clear-log)",
            r"Clear-EventLog",
            r"history\s+-c",
            r"(?:rm|unlink|shred|truncate)\s+(?:-[a-zA-Z0-9_\-]+\s+)*.*\.bash_history",
            r">\s*~?/?\.bash_history",
        ],
        match_logic="any",
        containment_playbook=[
            "1. Check central SIEM / forwarder (Splunk, Elastic, Sentinel) for shipped copies of deleted logs.",
            "2. Take an immediate memory snapshot of the endpoint to preserve volatile command history.",
        ],
        remediation_playbook=[
            "1. Configure read-only remote log streaming to an isolated syslog/SIEM server.",
            "2. Restrict local administrator permissions to prevent unlogged wevtutil invocations.",
        ],
    ),
    SOCRule(
        id="SOC-T1486-01",
        name="Data Encrypted for Impact: Ransomware & Shadow Copy Deletion",
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        severity="Critical",
        description="Detects catastrophic ransomware behaviors including Volume Shadow Copy deletion, backup catalog destruction, and boot recovery tampering.",
        patterns=[
            r"vssadmin(?:\.exe)?\s+delete\s+shadows",
            r"wbadmin(?:\.exe)?\s+delete\s+catalog",
            r"wmic(?:\.exe)?\s+shadowcopy\s+delete",
            r"bcdedit(?:\.exe)?\s+/set[^\n\r]*ignoreallfailures",
        ],
        match_logic="any",
        containment_playbook=[
            "1. Sever all network connections immediately to halt ransomware propagation and encryption.",
            "2. Freeze host state (virtual machine snapshot) for forensic analysis and key recovery.",
        ],
        remediation_playbook=[
            "1. Restore systems from offline, immutable, or air-gapped backups.",
            "2. Rotate all active domain credentials and verify storage integrity.",
        ],
    ),
    SOCRule(
        id="SOC-T1505-01",
        name="Server Software Component: Web Shell Signatures & Backdoors",
        technique_id="T1505.003",
        technique_name="Server Software Component: Web Shell",
        severity="Critical",
        description="Detects classic and dynamic web shells across PHP, JSP, and ASP (b374k, c99, r57, eval base64, runtime exec).",
        patterns=[
            r"\bb374k\b",
            r"\bc99(?:shell)?\b",
            r"\br57(?:shell)?\b",
            r"eval\s*\(\s*base64_decode\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)",
            r"Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter",
            r"(?:execute|eval)\s*\(\s*Request(?:\.Item)?\s*[\(\[]",
            r"Server\.CreateObject\s*\(\s*[\"\'](?:WScript\.Shell|Shell\.Application)[\"\']\s*\)",
        ],
        match_logic="any",
        containment_playbook=[
            "1. Move the web shell file into the quarantine vault using mcp_quarantine_artifact.",
            "2. Terminate the web server worker process handling the active connection.",
            "3. Revoke active web application sessions and tokens.",
        ],
        remediation_playbook=[
            "1. Audit web root directories for unauthorized or newly created files.",
            "2. Enforce read-only filesystem permissions for web server document root.",
            "3. Deploy Web Application Firewall (WAF) to inspect upload payloads.",
        ],
    ),
    SOCRule(
        id="SOC-T1027-01",
        name="Obfuscated Files or Information: Certutil Remote Download & Decode",
        technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        severity="High",
        description="Detects abuse of Windows built-in certutil utility for decoding obfuscated base64 payloads or downloading remote binaries.",
        patterns=[
            r"certutil(?:\.exe)?\s+(?:-[a-zA-Z0-9_\-]+\s+)*-(?:decode|decodehex)",
            r"certutil(?:\.exe)?\s+(?:-[a-zA-Z0-9_\-]+\s+)*-urlcache(?:\s+-[a-zA-Z0-9_\-]+)*\s+-split",
            r"certutil(?:\.exe)?\s+(?:-[a-zA-Z0-9_\-]+\s+)*-split(?:\s+-[a-zA-Z0-9_\-]+)*\s+-urlcache",
        ],
        match_logic="any",
        containment_playbook=[
            "1. Terminate running certutil.exe processes via terminate_suspicious_process.",
            "2. Quarantine the decoded payload or downloaded binary file.",
        ],
        remediation_playbook=[
            "1. Restrict certutil network outbound access using host firewall rules.",
            "2. Configure AppLocker or WDAC to disallow arbitrary certutil invocations by standard users.",
        ],
    ),
]


class SOCRuleEngine:
    """
    Pure-Python Dynamic SOC Detection Rule Engine.
    Evaluates raw strings, code snippets, or Binary Triage outputs against MITRE ATT&CK rules.
    """

    def __init__(self, initial_rules: Optional[List[SOCRule]] = None):
        self._rules: Dict[str, SOCRule] = {}
        for r in (initial_rules or DEFAULT_SOC_RULES):
            self.register_rule(r)

    def register_rule(self, rule: SOCRule) -> None:
        """Register or update a detection rule."""
        self._rules[rule.id] = rule

    def list_rules(self) -> List[Dict[str, Any]]:
        """List all active detection rules."""
        return [r.to_dict() for r in self._rules.values()]

    def get_playbook(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Retrieve containment and remediation playbook for a given MITRE ATT&CK Technique ID or Rule ID."""
        ident_lower = identifier.lower().strip()
        for rule in self._rules.values():
            if (
                rule.technique_id.lower() == ident_lower
                or rule.id.lower() == ident_lower
                or f"soc-{rule.technique_id.lower()}" == ident_lower
                or f"pb-{rule.technique_id.lower()}" == ident_lower
            ):
                return {
                    "playbook_id": f"PB-{rule.technique_id}",
                    "rule_id": rule.id,
                    "technique_id": rule.technique_id,
                    "technique_name": rule.technique_name,
                    "severity": rule.severity,
                    "containment": rule.containment_playbook,
                    "remediation": rule.remediation_playbook,
                    "containment_playbook": rule.containment_playbook,
                    "remediation_playbook": rule.remediation_playbook,
                }
        return None

    def evaluate_text(self, text: str, source_label: str = "general") -> List[Dict[str, Any]]:
        """
        Evaluate a block of text or disassembly against all registered SOC rules.
        Returns a list of triggered alerts with matched evidence and playbooks.
        """
        if not text:
            return []

        alerts: List[Dict[str, Any]] = []

        for rule in self._rules.values():
            matched_patterns: List[str] = []
            pattern_matches: Dict[str, List[str]] = {}

            for pat_str in rule.patterns:
                pat = re.compile(pat_str, re.IGNORECASE)
                matches = list(pat.finditer(text))
                if matches:
                    matched_patterns.append(pat_str)
                    # Extract full matched substring representation
                    pattern_matches[pat_str] = [m.group(0) for m in matches[:5]]

            is_triggered = False
            if rule.match_logic == "all":
                is_triggered = len(matched_patterns) == len(rule.patterns)
            else:  # 'any'
                is_triggered = len(matched_patterns) > 0

            if is_triggered:
                alerts.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "technique_id": rule.technique_id,
                    "technique_name": rule.technique_name,
                    "severity": rule.severity,
                    "source_label": source_label,
                    "description": rule.description,
                    "matched_patterns": matched_patterns,
                    "matches": pattern_matches,
                    "playbook": {
                        "containment": rule.containment_playbook,
                        "remediation": rule.remediation_playbook,
                    },
                    "containment_playbook": rule.containment_playbook,
                    "remediation_playbook": rule.remediation_playbook,
                })

        return alerts

    def evaluate_binary_triage(self, triage_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate output of BinaryTriageEngine.triage_file against SOC detection rules.
        Combines sample strings, detected APIs, URLs, registry keys, and PE section anomalies.
        """
        if not triage_result:
            return []
        if "success" in triage_result and not triage_result["success"]:
            return []

        # Aggregate all textual evidence from binary triage
        tokens: List[str] = []
        iocs = triage_result.get("iocs") or triage_result.get("ioc_strings") or {}
        tokens.extend(iocs.get("suspicious_apis") or iocs.get("suspicious_apis_detected") or [])
        tokens.extend(iocs.get("urls") or iocs.get("urls_detected") or [])
        tokens.extend(iocs.get("ips") or iocs.get("ips_detected") or [])
        tokens.extend(iocs.get("registry_keys") or iocs.get("registry_keys_detected") or [])

        header = triage_result.get("header", {})
        for anomaly in header.get("section_anomalies", []):
            tokens.append(anomaly)
        for sec in header.get("sections", []):
            tokens.append(sec.get("name", ""))

        for line in triage_result.get("evidence_chain", []):
            tokens.append(line)

        aggregate_text = " \n ".join(tokens)
        return self.evaluate_text(aggregate_text, source_label="binary_triage")
