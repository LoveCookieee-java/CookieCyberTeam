"""
Adaptive Scan Planner.

Rather than asking one agent to "find every vulnerability in this repo", the
planner decomposes a workspace into small, focused, well-scoped analysis tasks
(one concern per file plus repo-wide audits), each with a priority, a rationale,
and a suggested tool. The plan can be executed directly or seeded into the
multi-agent DAG engine as a dependency-ordered pipeline.

Zero external dependencies (Python stdlib only).
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from core.config import CookieCyberConfig

SOURCE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".sol": "solidity",
}

DEPENDENCY_FILES = {
    "requirements.txt", "pyproject.toml", "poetry.lock", "package.json",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "Cargo.toml",
    "pom.xml", "build.gradle", "Gemfile", "composer.json",
}

BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".apk", ".jar", ".dex"}

#: Task priority order (lower executes first).
PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class ScanTask:
    """A single focused analysis task."""

    task_id: str
    kind: str  # recon | sast | deps | secrets | binary | aggregate
    target: str
    language: str
    priority: str
    rationale: str
    suggested_tool: str
    assigned_to: str
    dependencies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ScanPlanner:
    """Decomposes a workspace into focused security analysis tasks."""

    def __init__(self, workspace_root: Optional[Union[str, Path]] = None, config: Optional[CookieCyberConfig] = None):
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
        if self.workspace_root.is_file():
            self.workspace_root = self.workspace_root.parent
        self.config = config or CookieCyberConfig.load_from_repo(self.workspace_root)

    def _is_excluded(self, path: Path) -> bool:
        parts = {p.lower() for p in path.parts}
        return any(ex.lower() in parts for ex in self.config.exclude_dirs)

    def plan(self, max_files: int = 50) -> Dict[str, Any]:
        """Build a prioritized, dependency-ordered scan plan for the workspace."""
        source_files: List[tuple] = []
        dep_files: List[str] = []
        binary_files: List[str] = []

        for path in self.workspace_root.rglob("*"):
            if not path.is_file() or self._is_excluded(path):
                continue
            suffix = path.suffix.lower()
            if path.name in DEPENDENCY_FILES:
                dep_files.append(str(path))
            elif suffix in BINARY_EXTENSIONS:
                binary_files.append(str(path))
            elif suffix in SOURCE_EXTENSIONS:
                source_files.append((str(path), SOURCE_EXTENSIONS[suffix], path.stat().st_size))

        # Prioritise larger files first (more surface), bounded by max_files.
        source_files.sort(key=lambda t: t[2], reverse=True)
        source_files = source_files[:max_files]

        tasks: List[ScanTask] = []
        recon_id = "scan_recon"
        tasks.append(ScanTask(
            task_id=recon_id,
            kind="recon",
            target=str(self.workspace_root),
            language="any",
            priority="high",
            rationale="Establish the attack surface and confirm the active stack before deep analysis.",
            suggested_tool="mcp_adaptive_guide",
            assigned_to="Lead Orchestrator",
        ))

        for idx, (path, lang, size) in enumerate(source_files):
            tid = self._task_id("sast", path, idx)
            priority = "high" if size > 20_000 else ("medium" if size > 4_000 else "low")
            tasks.append(ScanTask(
                task_id=tid,
                kind="sast",
                target=path,
                language=lang,
                priority=priority,
                rationale=f"Static taint analysis of a {lang} source file ({size} bytes).",
                suggested_tool="mcp_scan_vulnerabilities",
                assigned_to="Security Auditor",
                dependencies=[recon_id],
            ))

        if dep_files:
            tasks.append(ScanTask(
                task_id="scan_deps",
                kind="deps",
                target=",".join(dep_files[:20]),
                language="any",
                priority="high",
                rationale="Offline supply-chain review of declared dependencies.",
                suggested_tool="mcp_audit_dependencies",
                assigned_to="Security Auditor",
                dependencies=[recon_id],
            ))

        tasks.append(ScanTask(
            task_id="scan_secrets",
            kind="secrets",
            target=str(self.workspace_root),
            language="any",
            priority="medium",
            rationale="Hunt for hard-coded credentials and entropy outliers in source.",
            suggested_tool="mcp_scan_vulnerabilities",
            assigned_to="Security Auditor",
            dependencies=[recon_id],
        ))

        for idx, path in enumerate(binary_files[:20]):
            tid = self._task_id("binary", path, idx)
            tasks.append(ScanTask(
                task_id=tid,
                kind="binary",
                target=path,
                language="binary",
                priority="critical",
                rationale="Air-gapped static triage of a binary artifact.",
                suggested_tool="mcp_triage_binary",
                assigned_to="SOC Incident Responder",
                dependencies=[recon_id],
            ))

        leaf_ids = [t.task_id for t in tasks if t.task_id != recon_id]
        tasks.append(ScanTask(
            task_id="scan_aggregate",
            kind="aggregate",
            target=str(self.workspace_root),
            language="any",
            priority="high",
            rationale="Validate, de-duplicate, rank, and chain findings from all analysis tasks.",
            suggested_tool="mcp_validate_finding",
            assigned_to="QA Reviewer",
            dependencies=leaf_ids,
        ))

        tasks.sort(key=lambda t: (PRIORITY.get(t.priority, 9), t.kind, t.task_id))
        plan_dicts = [t.to_dict() for t in tasks]
        return {
            "success": True,
            "workspace_root": str(self.workspace_root),
            "total_tasks": len(plan_dicts),
            "source_files_planned": len(source_files),
            "dependency_files": dep_files[:20],
            "binary_files": binary_files[:20],
            "priority_counts": self._count_by(plan_dicts, "priority"),
            "kind_counts": self._count_by(plan_dicts, "kind"),
            "tasks": plan_dicts,
            "workflow": [
                "recon", "sast", "deps", "secrets", "binary", "aggregate",
            ],
        }

    def seed_dag(self, dag_engine: Any, plan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Seed the given DAG engine with a plan, returning the created pipeline summary."""
        plan = plan or self.plan()
        created = []
        for task in plan["tasks"]:
            deps = [d for d in task["dependencies"] if any(t["task_id"] == d for t in plan["tasks"])]
            dag_engine.add_task(
                task_id=task["task_id"],
                name=f"{task['kind']}: {Path(task['target']).name}",
                assigned_to=task["assigned_to"],
                dependencies=deps,
            )
            created.append(task["task_id"])
        return {
            "success": True,
            "seeded_tasks": created,
            "total": len(created),
            "dag_summary": dag_engine.get_dag_summary(),
        }

    @staticmethod
    def _task_id(kind: str, path: str, idx: int) -> str:
        digest = hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()[:8]
        return f"scan_{kind}_{idx}_{digest}"

    @staticmethod
    def _count_by(items: Sequence[Dict[str, Any]], key: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for item in items:
            counts[item[key]] = counts.get(item[key], 0) + 1
        return counts
