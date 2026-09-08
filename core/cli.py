"""
Standalone Headless CLI for CookieCyberTeam Security Guardrails.
Provides command-line interfaces for:
- scan: SAST security scanning with JSON/SARIF output and threshold exit gating.
- triage: Air-gapped binary triage and SOC rule evaluation.
- contain: Multi-platform host firewall rule generation (Windows, Linux, DNS).
- quarantine: Zero-execution artifact quarantine vault operations.
- restore: Restore quarantined artifact from encrypted vault back to workspace.
"""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from core.ast_scanner import ASTScanner
from core.binary_triage import BinaryTriageEngine
from core.config import CookieCyberConfig
from core.containment import generate_firewall_rule, quarantine_file, restore_quarantined_file
from core.soc_rules import SOCRuleEngine


SEVERITY_RANKS = {
    "none": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute SAST scan against file(s) or directory."""
    target_paths: List[Path] = []
    if getattr(args, "paths", None):
        target_paths = [Path(p).resolve() for p in args.paths]
    else:
        target_paths = [Path(args.path).resolve()]

    repo_hint = target_paths[0] if target_paths else Path.cwd()
    config = CookieCyberConfig.load_from_repo(repo_hint)
    scanner = ASTScanner(config=config)

    findings: List[Any] = []
    for target in target_paths:
        if target.is_file():
            findings.extend(scanner.scan_file(target))
        elif target.is_dir():
            findings.extend(scanner.scan_directory(target))
        else:
            sys.stderr.write(f"Error: Target path '{target}' does not exist.\n")
            return 1

    findings_dicts = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]

    if getattr(args, "format", "json").lower() == "sarif":
        sarif_doc = scanner.to_sarif(findings_dicts)
        print(json.dumps(sarif_doc, indent=2))
    else:
        severity_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        max_score = 0.0
        for f in findings_dicts:
            sev = f.get("severity", "Low")
            if sev in severity_dist:
                severity_dist[sev] += 1
            score = float(f.get("cvss_score", 0.0))
            if score > max_score:
                max_score = score

        target_str = str(target_paths[0]) if len(target_paths) == 1 else [str(t) for t in target_paths]
        output_data = {
            "success": True,
            "target": target_str,
            "total_findings": len(findings_dicts),
            "max_cvss_score": max_score,
            "severity_distribution": severity_dist,
            "findings": findings_dicts,
        }
        print(json.dumps(output_data, indent=2))

    # Exit code gating
    if getattr(args, "fail_on", None):
        threshold_name = args.fail_on.lower()
        threshold_rank = SEVERITY_RANKS.get(threshold_name, 3)

        max_finding_rank = 0
        for f in findings_dicts:
            rank = SEVERITY_RANKS.get(str(f.get("severity", "")).lower(), 0)
            if rank > max_finding_rank:
                max_finding_rank = rank

        if max_finding_rank >= threshold_rank:
            sys.stderr.write(
                f"[SECURITY GATE FAIL] Found vulnerabilities matching or exceeding threshold '{threshold_name}' (highest: {max_finding_rank} >= {threshold_rank}).\n"
            )
            return 1

    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    """Execute air-gapped binary triage and evaluate SOC rules."""
    target_file = Path(args.file).resolve()
    if not target_file.is_file():
        sys.stderr.write(f"Error: Target binary '{args.file}' not found.\n")
        return 1

    engine = BinaryTriageEngine()
    soc = SOCRuleEngine()

    max_bytes = getattr(args, "max_bytes", 1048576) or 1048576
    triage_res = engine.triage_file(file_path=target_file, max_bytes=max_bytes)

    if triage_res.get("success"):
        alerts = soc.evaluate_binary_triage(triage_res)
        triage_res["soc_alerts"] = alerts
        for alert in alerts:
            triage_res["evidence_chain"].append(
                f"[SOC ALERT - {alert['technique_id']} {alert['technique_name']}]: {alert['rule_name']} (Severity: {alert['severity']})"
            )

    print(json.dumps(triage_res, indent=2))
    return 0 if triage_res.get("success") else 1


def cmd_contain(args: argparse.Namespace) -> int:
    """Generate host firewall rules across platforms."""
    rule_type = getattr(args, "rule_type", "block") or "block"
    port = getattr(args, "port", None)
    res = generate_firewall_rule(target=args.target, rule_type=rule_type, port=port)
    print(json.dumps(res, indent=2))
    return 0 if res.get("success") else 1


def cmd_quarantine(args: argparse.Namespace) -> int:
    """Quarantine suspicious file into vault."""
    target_file = Path(args.file).resolve()
    quar_dir = getattr(args, "quarantine_dir", None)
    res = quarantine_file(file_path=target_file, quarantine_dir=quar_dir)
    print(json.dumps(res, indent=2))
    return 0 if res.get("success") else 1


def cmd_restore(args: argparse.Namespace) -> int:
    """Restore quarantined artifact from encrypted vault back to workspace."""
    quar_target = getattr(args, "target", None)
    quar_dir = getattr(args, "quarantine_dir", None)
    dest = getattr(args, "destination", None)
    res = restore_quarantined_file(
        quarantine_id=quar_target,
        quarantine_dir=quar_dir,
        destination_path=dest,
    )
    print(json.dumps(res, indent=2))
    return 0 if res.get("success") else 1


def cmd_ponytail(args: argparse.Namespace) -> int:
    """Execute Ponytail audit, review, debt scan, or print decision ladder."""
    subaction = getattr(args, "action", "audit")
    if subaction == "ladder":
        from server import PONYTAIL_LADDER_RESOURCE
        print(PONYTAIL_LADDER_RESOURCE)
        return 0

    from server import CookieCyberMCPServer
    server = CookieCyberMCPServer()
    if subaction == "audit":
        res = server.tool_ponytail_audit({"path": getattr(args, "path", "."), "mode": getattr(args, "mode", "full")})
        print(json.dumps(res, indent=2))
        return 0 if res.get("success") else 1
    elif subaction == "review":
        res = server.tool_ponytail_review({"file_path": getattr(args, "file", None), "mode": getattr(args, "mode", "full")})
        print(json.dumps(res, indent=2))
        return 0 if res.get("success") else 1
    elif subaction == "debt":
        res = server.tool_ponytail_debt({"path": getattr(args, "path", ".")})
        print(json.dumps(res, indent=2))
        return 0 if res.get("success") else 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m core.cli",
        description="CookieCyberTeam CLI Security Guardrails Headless Interface",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan sub-command
    scan_parser = subparsers.add_parser("scan", help="Run SAST security scan against a file or repository")
    scan_parser.add_argument("paths", nargs="*", default=None, help="Optional file(s) or directory paths to scan")
    scan_parser.add_argument("--path", "-p", type=str, default=".", help="Path to file or directory to scan (default: current directory)")
    scan_parser.add_argument("--format", "-f", choices=["json", "sarif"], default="json", help="Output format (default: json)")
    scan_parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default=None, help="Exit with code 1 if findings meet or exceed severity threshold")

    # triage sub-command
    triage_parser = subparsers.add_parser("triage", help="Air-gapped static binary triage and SOC alert evaluation")
    triage_parser.add_argument("--file", "-f", type=str, required=True, help="Path to binary artifact to inspect")
    triage_parser.add_argument("--max-bytes", type=int, default=1048576, help="Maximum bytes to read (default: 1048576)")

    # contain sub-command
    contain_parser = subparsers.add_parser("contain", help="Generate multi-platform firewall and containment rules")
    contain_parser.add_argument("--target", "-t", type=str, required=True, help="Target IP, CIDR subnet, or domain name")
    contain_parser.add_argument("--rule-type", choices=["block", "allow"], default="block", help="Firewall action (default: block)")
    contain_parser.add_argument("--port", type=int, default=None, help="Optional TCP port number")

    # quarantine sub-command
    quar_parser = subparsers.add_parser("quarantine", help="Atomically quarantine suspicious file into secure vault")
    quar_parser.add_argument("--file", "-f", type=str, required=True, help="Path to suspicious file to quarantine")
    quar_parser.add_argument("--quarantine-dir", "-d", type=str, default=None, help="Optional custom quarantine directory")

    # restore sub-command
    restore_parser = subparsers.add_parser("restore", help="Restore quarantined file from vault back to workspace")
    restore_parser.add_argument("target", type=str, help="Quarantine ID, original file path, or vaulted filename to restore")
    restore_parser.add_argument("--destination", "-d", type=str, default=None, help="Optional custom destination path")
    restore_parser.add_argument("--quarantine-dir", "-q", type=str, default=None, help="Optional custom quarantine directory")

    # ponytail sub-command
    pony_parser = subparsers.add_parser("ponytail", help="Ponytail Lazy Senior Dev auditor, code review, debt scanner, and decision ladder")
    pony_parser.add_argument("action", choices=["audit", "review", "debt", "ladder"], default="audit", nargs="?", help="Action to perform (default: audit)")
    pony_parser.add_argument("--path", "-p", type=str, default=".", help="Path to audit or scan for debt (default: .)")
    pony_parser.add_argument("--file", "-f", type=str, default=None, help="Path to file to review")
    pony_parser.add_argument("--mode", "-m", choices=["ultra", "full", "lite"], default="full", help="Ponytail intensity mode (default: full)")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "triage":
        return cmd_triage(args)
    elif args.command == "contain":
        return cmd_contain(args)
    elif args.command == "quarantine":
        return cmd_quarantine(args)
    elif args.command == "restore":
        return cmd_restore(args)
    elif args.command == "ponytail":
        return cmd_ponytail(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
