"""
Meta-Orchestrator: the coordinating MCP.

Turns a single high-level intent (or an auto-detected one) into a concrete,
dependency-aware sequence of the *other* CookieCyberTeam tools, executes it,
threads each step's output into the next, and adapts when intermediate results
change the shape of the work (e.g. no findings -> skip validation; a binary ->
chain triage into attack-path reasoning).

Design notes:
* Pure stdlib, deterministic, and fully decoupled from the server: it reaches
  other tools exclusively through an injected ``call(tool_name, args)`` callback,
  which makes it trivially unit-testable with a fake dispatcher.
* Safety-first: every write/destructive step is planned but *proposed*, never
  executed, unless the caller explicitly opts in with ``allow_write=True``.
* Flexible: steps declare the context they need; missing context degrades the
  run gracefully (skip, not crash).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from core.scan_planner import BINARY_EXTENSIONS, DEPENDENCY_FILES, SOURCE_EXTENSIONS

CallFn = Callable[[str, Dict[str, Any]], Dict[str, Any]]

#: Tools that mutate the workspace or a running system. Never auto-run.
WRITE_TOOLS = {
    "mcp_quarantine_artifact",
    "mcp_terminate_process",
    "mcp_apply_safe_patch",
}

#: Recognised high-level intents.
INTENTS = {
    "auto",
    "audit_repo",
    "review_code",
    "triage_binary",
    "dependency_audit",
    "incident_response",
    "skill_audit",
    "agentic_audit",
}


class Orchestrator:
    """Plans and executes multi-tool defensive workflows."""

    def __init__(self, workspace_root: Optional[Union[str, Path]] = None):
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
        if self.workspace_root.is_file():
            self.workspace_root = self.workspace_root.parent

    # -- target classification -------------------------------------------------

    def classify_target(self, target: Optional[str]) -> Dict[str, Any]:
        """Classify a target into repo / source / binary / dependency / workspace."""
        if not target:
            return {"kind": "workspace", "path": str(self.workspace_root)}
        p = Path(target)
        resolved = p.resolve() if p.is_absolute() else (self.workspace_root / p).resolve()
        if resolved.is_dir():
            return {"kind": "repo", "path": str(resolved)}
        name = resolved.name
        suffix = resolved.suffix.lower()
        if suffix in BINARY_EXTENSIONS:
            return {"kind": "binary", "path": str(resolved)}
        if name in DEPENDENCY_FILES:
            return {"kind": "dependency", "path": str(resolved)}
        if suffix in SOURCE_EXTENSIONS:
            return {"kind": "source", "path": str(resolved), "language": SOURCE_EXTENSIONS[suffix]}
        return {"kind": "unknown", "path": str(resolved)}

    def resolve_intent(self, intent: str, target_kind: str, options: Dict[str, Any]) -> str:
        """Resolve 'auto' into a concrete intent from the target kind."""
        intent = (intent or "auto").strip().lower()
        if intent != "auto" and intent in INTENTS:
            return intent
        if options.get("code_content"):
            return "review_code"
        return {
            "binary": "triage_binary",
            "dependency": "dependency_audit",
            "repo": "audit_repo",
            "source": "audit_repo",
            "workspace": "audit_repo",
        }.get(target_kind, "audit_repo")

    # -- planning --------------------------------------------------------------

    def plan(
        self,
        intent: str = "auto",
        target: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build a dependency-aware step plan for the intent."""
        options = options or {}
        info = self.classify_target(target)
        resolved_intent = self.resolve_intent(intent, info["kind"], options)
        steps: List[Dict[str, Any]] = []

        if resolved_intent in ("audit_repo",):
            scan_args: Dict[str, Any] = {"target_path": info["path"]}
            steps.append(self._step("s_plan", "mcp_plan_scan",
                                    {"target_path": info["path"], "max_files": options.get("max_files", 50)},
                                    why="Decompose the workspace into focused tasks.", optional=True))
            steps.append(self._step("s_scan", "mcp_scan_vulnerabilities", scan_args,
                                    why="Static taint analysis across the target."))
            steps.append(self._step("s_validate", "mcp_validate_finding", {},
                                    args_from={"findings": "findings"},
                                    condition="has_findings",
                                    why="Suppress false positives via the 7-Question Gate."))
            steps.append(self._step("s_chains", "mcp_recall_findings",
                                    {"action": "chains"},
                                    args_from={"findings": "validated_findings"},
                                    condition="has_validated",
                                    why="Detect chained attack paths among survivors."))
            steps.append(self._step("s_bundle", "mcp_export_bundle", {},
                                    args_from={"findings": "validated_findings"},
                                    condition="has_validated", optional=True,
                                    why="Assemble a ranked SARIF/STIX/Markdown report bundle."))

        elif resolved_intent == "review_code":
            code = options.get("code_content")
            fp = info["path"] if info["kind"] != "workspace" else "<in-memory>"
            steps.append(self._step("s_scan", "mcp_scan_vulnerabilities",
                                    {"code_content": code, "target_path": fp},
                                    why="Scan the in-memory snippet."))
            steps.append(self._step("s_validate", "mcp_validate_finding",
                                    {"code_content": code, "file_path": fp},
                                    condition="always",
                                    why="Validate the snippet findings through the gate."))

        elif resolved_intent == "triage_binary":
            steps.append(self._step("s_triage", "mcp_triage_binary", {"file_path": info["path"]},
                                    why="Air-gapped static triage (zero execution)."))
            steps.append(self._step("s_path", "mcp_attack_path", {},
                                    args_from={"observed_techniques": "techniques"},
                                    condition="has_techniques",
                                    why="Place observed techniques on the ATT&CK kill chain."))
            steps.append(self._step("s_bundle", "mcp_export_bundle", {},
                                    args_from={"findings": "findings"},
                                    condition="has_findings", optional=True,
                                    why="Optionally bundle indicators and behaviours."))

        elif resolved_intent == "dependency_audit":
            steps.append(self._step("s_deps", "mcp_audit_dependencies", {"path": info["path"]},
                                    why="Offline supply-chain review with remediation advisories."))

        elif resolved_intent == "skill_audit":
            steps.append(self._step("s_import", "mcp_import_skills",
                                    {"root": info["path"],
                                     "max_skills": options.get("max_skills", 500)},
                                    optional=True,
                                    why="Ingest the SKILL.md knowledge catalog from the target tree."))
            steps.append(self._step("s_skill_audit", "mcp_audit_agent_skills",
                                    {"target_path": info["path"]},
                                    why="Audit skills and agent configs for prompt-injection, "
                                        "over-broad tool grants, and exfiltration shapes."))
            steps.append(self._step("s_bundle", "mcp_export_bundle", {},
                                    args_from={"findings": "findings"},
                                    condition="has_findings", optional=True,
                                    why="Bundle agent-surface findings for review."))

        elif resolved_intent == "agentic_audit":
            steps.append(self._step("s_skill_audit", "mcp_audit_agent_skills",
                                    {"target_path": info["path"]},
                                    why="Audit the agent surface for agentic threat classes."))
            steps.append(self._step("s_coverage", "mcp_detection_coverage", {},
                                    optional=True,
                                    why="Report ATT&CK detection coverage for the active rule set."))

        elif resolved_intent == "incident_response":
            if info["kind"] == "binary":
                steps.append(self._step("s_triage", "mcp_triage_binary", {"file_path": info["path"]},
                                        why="Triage the suspicious artifact."))
                steps.append(self._step("s_path", "mcp_attack_path", {},
                                        args_from={"observed_techniques": "techniques"},
                                        condition="has_techniques",
                                        why="Reason about likely next attacker moves."))
            if options.get("containment_target"):
                steps.append(self._step("s_contain", "mcp_generate_containment_rule",
                                        {"target": options["containment_target"], "rule_type": "block",
                                         "port": options.get("containment_port")},
                                        why="Generate host/network containment rules."))
            steps.append(self._step("s_quarantine", "mcp_quarantine_artifact",
                                    {"file_path": info["path"]}, write=True, optional=True,
                                    why="Quarantine the artifact (requires explicit approval)."))
            steps.append(self._step("s_terminate", "mcp_terminate_process",
                                    {"pid": options.get("pid")}, write=True, optional=True,
                                    condition="has_pid",
                                    why="Terminate the offending process tree (requires explicit approval)."))

        return {
            "intent": resolved_intent,
            "target": info,
            "steps": steps,
            "step_count": len(steps),
        }

    @staticmethod
    def _step(
        step_id: str,
        tool: str,
        args: Optional[Dict[str, Any]] = None,
        args_from: Optional[Dict[str, str]] = None,
        condition: str = "always",
        why: str = "",
        optional: bool = False,
        write: bool = False,
    ) -> Dict[str, Any]:
        return {
            "id": step_id,
            "tool": tool,
            "args": args or {},
            "args_from": args_from or {},
            "condition": condition,
            "why": why,
            "optional": optional,
            "write": write,
        }

    # -- execution -------------------------------------------------------------

    def run(
        self,
        intent: str = "auto",
        target: Optional[str] = None,
        call: Optional[CallFn] = None,
        allow_write: bool = False,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Plan and execute the workflow, threading context between steps."""
        if call is None:
            raise ValueError("Orchestrator.run requires a call(tool, args) dispatcher.")
        options = options or {}
        plan = self.plan(intent=intent, target=target, options=options)

        ctx: Dict[str, Any] = {
            "findings": [],
            "validated_findings": [],
            "techniques": [],
            "chains": [],
        }
        executed: List[Dict[str, Any]] = []

        for step in plan["steps"]:
            record: Dict[str, Any] = {
                "id": step["id"],
                "tool": step["tool"],
                "why": step["why"],
                "write": step["write"],
            }
            if step["write"] and not allow_write:
                record["status"] = "proposed"
                record["note"] = "Write action withheld; pass allow_write=true to execute."
                executed.append(record)
                continue
            if not self._condition_ok(step["condition"], ctx, options):
                record["status"] = "skipped"
                record["note"] = f"Condition not met: {step['condition']}."
                executed.append(record)
                continue

            args = self._resolve_args(step, plan["target"], ctx, options)
            if args is None:
                record["status"] = "skipped"
                record["note"] = "Required input unavailable."
                executed.append(record)
                continue

            try:
                out = call(step["tool"], args)
            except Exception as exc:  # noqa: BLE001 - surface, do not crash the run
                record["status"] = "error"
                record["error"] = f"{type(exc).__name__}: {exc}"
                executed.append(record)
                if not step["optional"]:
                    break
                continue

            self._ingest(step["id"], out, ctx)
            record["status"] = "ok"
            record["summary"] = self._summarize(step["tool"], out)
            executed.append(record)

        return {
            "success": True,
            "intent": plan["intent"],
            "target": plan["target"],
            "allow_write": allow_write,
            "steps": executed,
            "executed_count": sum(1 for s in executed if s["status"] == "ok"),
            "proposed_write_count": sum(1 for s in executed if s["status"] == "proposed"),
            "report": self._report(ctx, plan),
            "recommended_next": self._recommend(ctx, plan, allow_write),
        }

    def _condition_ok(self, condition: str, ctx: Dict[str, Any], options: Dict[str, Any]) -> bool:
        if condition == "always":
            return True
        if condition == "has_findings":
            return bool(ctx.get("findings"))
        if condition == "has_validated":
            return bool(ctx.get("validated_findings"))
        if condition == "has_techniques":
            return bool(ctx.get("techniques"))
        if condition == "has_pid":
            return options.get("pid") is not None
        return True

    def _resolve_args(
        self,
        step: Dict[str, Any],
        target_info: Dict[str, Any],
        ctx: Dict[str, Any],
        options: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        args: Dict[str, Any] = {}
        for key, value in step["args"].items():
            if value is None:
                continue
            args[key] = value
        for arg_name, ctx_key in step["args_from"].items():
            if ctx_key not in ctx or ctx[ctx_key] in (None, [], {}):
                return None
            args[arg_name] = ctx[ctx_key]
        return args

    def _ingest(self, step_id: str, out: Dict[str, Any], ctx: Dict[str, Any]) -> None:
        tool = step_id
        if step_id == "s_scan":
            findings = out.get("findings") or []
            ctx["findings"] = findings
            ctx["raw_finding_count"] = out.get("total_findings", len(findings))
        elif step_id == "s_validate":
            ctx["validated_findings"] = out.get("findings") or []
            ctx["suppressed_count"] = out.get("suppressed", 0)
        elif step_id == "s_chains":
            ctx["chains"] = out.get("chains") or []
        elif step_id == "s_triage":
            ctx["triage"] = out
            intel = out.get("malware_intel") or {}
            techniques = list(intel.get("techniques") or [])
            alerts = out.get("soc_alerts") or []
            seen_ids = {t.get("technique_id") for t in techniques}
            for alert in alerts:
                tid = alert.get("technique_id")
                if tid and tid not in seen_ids:
                    techniques.append({"technique_id": tid, "technique_name": alert.get("technique_name"),
                                       "tactic": alert.get("tactic")})
                    seen_ids.add(tid)
            ctx["techniques"] = techniques
            ctx["families"] = (intel.get("family_matches") or [])
            ctx["soc_alerts"] = alerts
            # Binary triage yields no source findings; keep findings empty.
            ctx["findings"] = []
        elif step_id == "s_deps":
            ctx["deps"] = out
        elif step_id == "s_path":
            ctx["attack_path"] = out
        elif step_id == "s_plan":
            ctx["scan_plan"] = out
        elif step_id == "s_skill_audit":
            ctx["findings"] = out.get("findings") or []
            ctx["raw_finding_count"] = out.get("total_findings", len(ctx["findings"]))
            ctx["agent_surface"] = {
                "artifacts_scanned": out.get("artifacts_scanned"),
                "max_severity": out.get("max_severity"),
            }
        elif step_id == "s_coverage":
            ctx["coverage"] = out

    def _summarize(self, tool: str, out: Dict[str, Any]) -> Dict[str, Any]:
        """Extract a compact, tool-specific summary from a step result."""
        if tool == "mcp_scan_vulnerabilities":
            return {
                "total_findings": out.get("total_findings"),
                "overall_severity": out.get("overall_severity"),
                "max_cvss": out.get("max_cvss_score"),
            }
        if tool == "mcp_validate_finding":
            return {
                "kept": out.get("total"),
                "suppressed": out.get("suppressed"),
                "by_verdict": out.get("by_verdict"),
            }
        if tool == "mcp_recall_findings":
            return {"chains": out.get("count")}
        if tool == "mcp_triage_binary":
            intel = out.get("malware_intel") or {}
            return {
                "format": (out.get("header") or {}).get("format"),
                "risk": (out.get("risk_assessment") or {}).get("severity"),
                "imphash": intel.get("imphash"),
                "families": [f.get("family") for f in intel.get("family_matches", [])],
                "soc_alerts": len(out.get("soc_alerts") or []),
            }
        if tool == "mcp_attack_path":
            return {
                "kill_chain_position": out.get("kill_chain_position"),
                "likely_next_tactics": out.get("likely_next_tactics"),
            }
        if tool == "mcp_audit_dependencies":
            return {
                "dependencies_checked": out.get("total_dependencies_checked"),
                "vulnerabilities": out.get("vulnerability_count"),
                "urgent": out.get("urgent_count"),
            }
        if tool == "mcp_plan_scan":
            return {"total_tasks": out.get("total_tasks"), "kinds": out.get("kind_counts")}
        if tool == "mcp_export_bundle":
            return {"finding_count": out.get("finding_count"), "chain_count": out.get("chain_count")}
        if tool == "mcp_generate_containment_rule":
            return {"generated": bool(out.get("success"))}
        if tool == "mcp_audit_agent_skills":
            return {
                "artifacts_scanned": out.get("artifacts_scanned"),
                "total_findings": out.get("total_findings"),
                "max_severity": out.get("max_severity"),
                "by_asi": out.get("by_asi"),
            }
        if tool == "mcp_import_skills":
            return {"total_skills": out.get("total_skills"), "domains": out.get("domains")}
        if tool == "mcp_detection_coverage":
            return {
                "distinct_techniques_covered": out.get("distinct_techniques_covered"),
                "tactics_with_coverage": out.get("tactics_with_coverage"),
            }
        return {"success": out.get("success", True)}

    def _report(self, ctx: Dict[str, Any], plan: Dict[str, Any]) -> Dict[str, Any]:
        report: Dict[str, Any] = {"intent": plan["intent"]}
        if "raw_finding_count" in ctx:
            report["findings_raw"] = ctx.get("raw_finding_count")
        if "validated_findings" in ctx and ctx.get("validated_findings") is not None:
            report["findings_kept"] = len(ctx.get("validated_findings") or [])
            report["findings_suppressed"] = ctx.get("suppressed_count", 0)
        if ctx.get("chains"):
            report["attack_chains"] = [{"title": c["title"], "impact": c["impact"]}
                                       for c in ctx["chains"]]
        if ctx.get("triage"):
            report["triage_risk"] = (ctx["triage"].get("risk_assessment") or {}).get("severity")
        if ctx.get("families"):
            report["families"] = [f.get("family") for f in ctx["families"]]
        if ctx.get("techniques"):
            report["techniques"] = [t.get("technique_id") for t in ctx["techniques"]]
        if ctx.get("soc_alerts"):
            report["soc_alerts"] = [a.get("technique_id") for a in ctx["soc_alerts"]]
        if ctx.get("deps"):
            report["dependency_vulnerabilities"] = ctx["deps"].get("vulnerability_count")
            report["dependency_urgent"] = ctx["deps"].get("urgent_count")
        if ctx.get("attack_path"):
            report["kill_chain_position"] = ctx["attack_path"].get("kill_chain_position")
        return report

    def _recommend(self, ctx: Dict[str, Any], plan: Dict[str, Any], allow_write: bool) -> List[str]:
        recs: List[str] = []
        if ctx.get("attack_path"):
            recs.extend(ctx["attack_path"].get("priority_detections", [])[:4])
        if ctx.get("chains"):
            recs.append("Investigate the detected attack chains before patching individual findings.")
        if (ctx.get("suppressed_count") or 0) > 0:
            recs.append(f"{ctx['suppressed_count']} findings were suppressed by the gate; review verdicts if unsure.")
        if ctx.get("deps") and (ctx["deps"].get("urgent_count") or 0) > 0:
            recs.append("Upgrade the urgent dependencies flagged in the advisory.")
        if not allow_write and any(s["write"] for s in plan["steps"]):
            recs.append("Re-run with allow_write=true to execute the withheld containment/quarantine steps.")
        if not recs:
            recs.append("No further action required; results were clean.")
        return recs
