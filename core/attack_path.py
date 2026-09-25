"""
ATT&CK Attack-Path Reasoning & Pentesting Task Tree.

Two complementary structures for structured investigations:

* **Kill-chain reasoning** — given the techniques already observed, place the
  intrusion on the ATT&CK tactic chain, infer the likely next moves, and surface
  the highest-value detections to look for next.
* **Pentesting Task Tree (PTT)** — an explicit, persistent tree of investigation
  tasks with reasoning / generation / parsing roles, so an investigation keeps
  its plan across turns and agents instead of losing it in chat history.

Zero external dependencies (Python stdlib only). Descriptive/defensive only.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.technique_catalog import TECHNIQUE_CATALOG, get_technique


#: Ordered ATT&CK tactics as a simplified kill chain.
KILL_CHAIN: List[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

#: Fallback technique-prefix -> tactic map when the catalog has no entry.
_PREFIX_TACTIC: Dict[str, str] = {
    "T1595": "Reconnaissance", "T1592": "Reconnaissance", "T1590": "Reconnaissance",
    "T1583": "Resource Development", "T1587": "Resource Development",
    "T1566": "Initial Access", "T1190": "Initial Access", "T1133": "Initial Access",
    "T1059": "Execution", "T1204": "Execution", "T1047": "Execution", "T1053": "Persistence",
    "T1547": "Persistence", "T1543": "Persistence", "T1068": "Privilege Escalation",
    "T1055": "Defense Evasion", "T1027": "Defense Evasion", "T1218": "Defense Evasion",
    "T1620": "Defense Evasion", "T1497": "Defense Evasion", "T1140": "Defense Evasion",
    "T1562": "Defense Evasion", "T1003": "Credential Access", "T1555": "Credential Access",
    "T1082": "Discovery", "T1083": "Discovery", "T1016": "Discovery", "T1033": "Discovery",
    "T1021": "Lateral Movement", "T1570": "Lateral Movement", "T1210": "Lateral Movement",
    "T1071": "Command and Control", "T1571": "Command and Control", "T1105": "Command and Control",
    "T1041": "Exfiltration", "T1048": "Exfiltration", "T1486": "Impact", "T1490": "Impact",
    "T1489": "Impact", "T1505": "Persistence", "T1070": "Defense Evasion",
}


def _tactic_for(technique_id: str) -> Optional[str]:
    info = get_technique(technique_id)
    if info and info.get("tactic"):
        return info["tactic"]
    base = technique_id.split(".")[0].upper()
    return _PREFIX_TACTIC.get(base)


def _normalise_techniques(observed: Any) -> List[str]:
    ids: List[str] = []
    if not observed:
        return ids
    items = observed if isinstance(observed, (list, tuple, set)) else [observed]
    for item in items:
        if isinstance(item, str):
            ids.append(item.strip().upper())
        elif isinstance(item, dict):
            tid = item.get("technique_id") or item.get("id")
            if tid:
                ids.append(str(tid).strip().upper())
    # Deduplicate preserving order.
    seen: Set[str] = set()
    ordered: List[str] = []
    for tid in ids:
        if tid not in seen:
            seen.add(tid)
            ordered.append(tid)
    return ordered


def reason(observed: Any, max_next: int = 6) -> Dict[str, Any]:
    """
    Reason about the likely next stages of an intrusion from observed techniques.

    Returns the kill-chain position, reached tactics, likely next tactics,
    candidate next techniques, and the highest-priority detections.
    """
    techniques = _normalise_techniques(observed)
    tactics_hit: List[str] = []
    mapping: Dict[str, str] = {}
    for tid in techniques:
        tactic = _tactic_for(tid)
        if tactic:
            mapping[tid] = tactic
            if tactic not in tactics_hit:
                tactics_hit.append(tactic)

    if tactics_hit:
        furthest_idx = max(KILL_CHAIN.index(t) for t in tactics_hit if t in KILL_CHAIN)
    else:
        furthest_idx = -1

    next_tactics = KILL_CHAIN[furthest_idx + 1 : furthest_idx + 3] if furthest_idx >= 0 else KILL_CHAIN[:2]
    candidate_next: List[Dict[str, Any]] = []
    for sig in TECHNIQUE_CATALOG:
        if sig.tactic in next_tactics:
            candidate_next.append({
                "technique_id": sig.technique_id,
                "technique_name": sig.technique_name,
                "tactic": sig.tactic,
                "severity": sig.severity,
                "remediation": sig.remediation,
            })
    candidate_next = candidate_next[:max_next]

    priority_detections: List[str] = []
    for sig in TECHNIQUE_CATALOG:
        if sig.tactic in next_tactics and sig.severity in ("Critical", "High"):
            priority_detections.append(f"{sig.technique_id} {sig.technique_name} — {sig.remediation}")
    priority_detections = priority_detections[:max_next]

    return {
        "success": True,
        "observed_techniques": techniques,
        "technique_to_tactic": mapping,
        "kill_chain_position": KILL_CHAIN[furthest_idx] if furthest_idx >= 0 else "Pre-attack",
        "kill_chain_index": furthest_idx,
        "tactics_observed": tactics_hit,
        "likely_next_tactics": next_tactics,
        "candidate_next_techniques": candidate_next,
        "priority_detections": priority_detections,
    }


# ---------------------------------------------------------------------------
# Pentesting / Investigation Task Tree (PTT)
# ---------------------------------------------------------------------------

def _now() -> float:
    return time.time()


class PentestingTaskTree:
    """
    A persistent tree of investigation tasks with explicit reasoning roles.

    Roles mirror the PentestGPT reasoning / generation / parsing split:
    ``reasoning`` plans, ``generation`` produces artifacts, ``parsing`` extracts
    signal from output.
    """

    VALID_ROLES = {"reasoning", "generation", "parsing"}
    VALID_STATUS = {"pending", "active", "done", "failed"}

    def __init__(
        self,
        goal: str = "",
        path: Optional[str | Path] = None,
        root_id: Optional[str] = None,
    ):
        self.goal = goal
        self.path = Path(path) if path else None
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.root_id = root_id or self._new_id("root")
        self.nodes[self.root_id] = {
            "id": self.root_id,
            "name": goal or "Investigation",
            "role": "reasoning",
            "parent": None,
            "status": "pending",
            "notes": "",
            "created_at": _now(),
        }

    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:8]}"

    def add_task(
        self,
        name: str,
        role: str = "reasoning",
        parent_id: Optional[str] = None,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Add a child task under ``parent_id`` (defaults to the root)."""
        if role not in self.VALID_ROLES:
            raise ValueError(f"Invalid role '{role}'. Allowed: {sorted(self.VALID_ROLES)}")
        parent = parent_id or self.root_id
        if parent not in self.nodes:
            raise KeyError(f"Parent node not found: {parent}")
        node_id = self._new_id(role)
        self.nodes[node_id] = {
            "id": node_id,
            "name": name,
            "role": role,
            "parent": parent,
            "status": "pending",
            "notes": notes,
            "created_at": _now(),
        }
        return dict(self.nodes[node_id])

    def update_status(self, node_id: str, status: str, notes: Optional[str] = None) -> Dict[str, Any]:
        """Update a node's status and optionally its notes."""
        if node_id not in self.nodes:
            raise KeyError(f"Node not found: {node_id}")
        if status not in self.VALID_STATUS:
            raise ValueError(f"Invalid status '{status}'. Allowed: {sorted(self.VALID_STATUS)}")
        self.nodes[node_id]["status"] = status
        if notes is not None:
            self.nodes[node_id]["notes"] = notes
        return dict(self.nodes[node_id])

    def get_next_actions(self) -> List[Dict[str, Any]]:
        """Return pending nodes whose parent is done or which are the root's children."""
        actions: List[Dict[str, Any]] = []
        for node in self.nodes.values():
            if node["status"] != "pending":
                continue
            parent = node["parent"]
            if parent is None:
                actions.append(node)
                continue
            parent_node = self.nodes.get(parent)
            if parent_node and parent_node["status"] in ("done", "active"):
                actions.append(node)
        actions.sort(key=lambda n: n["created_at"])
        return [dict(a) for a in actions]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "root_id": self.root_id,
            "node_count": len(self.nodes),
            "status_counts": self._status_counts(),
            "next_actions": self.get_next_actions(),
            "nodes": list(self.nodes.values()),
        }

    def _status_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s: 0 for s in self.VALID_STATUS}
        for node in self.nodes.values():
            counts[node["status"]] = counts.get(node["status"], 0) + 1
        return counts

    def save(self, path: Optional[str | Path] = None) -> str:
        """Persist the tree to JSON (creates the file; never deletes)."""
        target = Path(path) if path else self.path
        if target is None:
            raise ValueError("No path provided for saving the task tree.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return str(target)

    @classmethod
    def load(cls, path: str | Path) -> "PentestingTaskTree":
        """Load a tree from a previously saved JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        tree = cls(goal=data.get("goal", ""), path=path, root_id=data.get("root_id"))
        tree.nodes = {n["id"]: n for n in data.get("nodes", [])}
        return tree
