"""
Multi-Agent DAG Orchestration Engine with SQLite WAL Shared State.
Coordinates Lead-Worker workflows (Lead Orchestrator, Security Auditor,
Debugger, Patch Developer, QA Reviewer, SOC Incident Responder) with cycle
detection via graphlib, Point-to-Point Mailbox messaging, and Loop Drainage Stop-Hooks.
"""

from __future__ import annotations
import contextlib
import graphlib
import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple


DEFAULT_DB_PATH = Path(".cookiegli/security_agent_state.db")

# User Mandate: Max Hop TTL set to 20 to prevent infinite ping-pong while allowing thorough collaboration
MAX_HOP_TTL = 20

ALLOWED_SPEECH_ACTS = {"INFORM", "REQUEST", "PROPOSE", "CONFIRM", "ESCALATE"}

ALLOWED_AGENT_ROLES = {
    "Lead Orchestrator",
    "Security Auditor",
    "Debugger",
    "Patch Developer",
    "QA Reviewer",
    "SOC Incident Responder",
}


class DAGCycleError(Exception):
    """Raised when a circular dependency is detected in DAG tasks."""
    pass


class DAGEngine:
    """Manages Multi-Agent DAG workflows, task dependencies, SQLite WAL shared memory, and Point-to-Point Mailbox."""

    def __init__(self, db_path: Optional[str | Path] = None):
        self.db_path_str = str(db_path) if db_path else str(DEFAULT_DB_PATH)
        self.is_memory = self.db_path_str == ":memory:"
        self._mem_conn: Optional[sqlite3.Connection] = None
        if not self.is_memory:
            self.db_path = Path(self.db_path_str)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        self._init_db()

    @contextlib.contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        if self.is_memory and self._mem_conn:
            yield self._mem_conn
            self._mem_conn.commit()
        else:
            conn = sqlite3.connect(self.db_path_str, timeout=15.0)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def _init_db(self) -> None:
        """Initialize tables and enable SQLite WAL mode when on disk."""
        with self._connection() as conn:
            if not self.is_memory:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    assigned_to TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    dependencies TEXT NOT NULL DEFAULT '[]',
                    result TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS shared_context (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );
            """)

            # Multi-Agent Point-to-Point Mailbox Table (Munder Difflin Pattern)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    msg_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    from_agent TEXT NOT NULL,
                    to_agent TEXT NOT NULL,
                    speech_act TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'UNREAD',
                    hop_count INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_inbox ON messages(task_id, to_agent, status);")
            conn.commit()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def log_event(self, event_type: str, agent: str, message: str) -> None:
        """Record an immutable audit log entry."""
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO audit_log (event_type, agent, message, timestamp) VALUES (?, ?, ?, ?)",
                (event_type, agent, message, self._now()),
            )
            conn.commit()

    def add_task(
        self,
        task_id: str,
        name: str,
        assigned_to: str,
        dependencies: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add a new task and validate DAG acyclicity before committing."""
        deps = dependencies or []

        # 1. Pre-validate DAG acyclicity with proposed task BEFORE committing to SQLite
        with self._connection() as conn:
            rows = conn.execute("SELECT task_id, dependencies FROM tasks").fetchall()

        candidate_graph: Dict[str, Set[str]] = {}
        for r in rows:
            candidate_graph[r["task_id"]] = set(json.loads(r["dependencies"]))
        candidate_graph[task_id] = set(deps)

        ts = graphlib.TopologicalSorter(candidate_graph)
        try:
            list(ts.static_order())
        except graphlib.CycleError as exc:
            raise DAGCycleError(f"Circular dependency detected in tasks: {exc}")

        # 2. Graph is verified acyclic; now safely commit to database
        deps_json = json.dumps(deps)
        now = self._now()

        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO tasks (task_id, name, assigned_to, status, dependencies, created_at, updated_at)
                VALUES (?, ?, ?, 'PENDING', ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    name=excluded.name,
                    assigned_to=excluded.assigned_to,
                    dependencies=excluded.dependencies,
                    updated_at=excluded.updated_at
                """,
                (task_id, name, assigned_to, deps_json, now, now),
            )
            conn.commit()

        self.log_event("TASK_ADDED", "Lead Orchestrator", f"Task '{task_id}' assigned to {assigned_to}")

        return {
            "task_id": task_id,
            "name": name,
            "assigned_to": assigned_to,
            "dependencies": deps,
            "status": "PENDING",
        }

    def validate_dag(self) -> List[str]:
        """
        Validate DAG with graphlib.TopologicalSorter.
        Returns topological ordering or raises DAGCycleError.
        """
        with self._connection() as conn:
            rows = conn.execute("SELECT task_id, dependencies FROM tasks").fetchall()

        graph: Dict[str, Set[str]] = {}
        for r in rows:
            t_id = r["task_id"]
            deps = set(json.loads(r["dependencies"]))
            graph[t_id] = deps

        ts = graphlib.TopologicalSorter(graph)
        try:
            order = list(ts.static_order())
            return order
        except graphlib.CycleError as exc:
            raise DAGCycleError(f"Circular dependency detected in tasks: {exc}")

    def get_ready_tasks(self) -> List[Dict[str, Any]]:
        """
        Find all tasks whose status is PENDING and all dependency tasks are COMPLETED.
        """
        with self._connection() as conn:
            all_tasks = conn.execute("SELECT * FROM tasks").fetchall()

        completed_ids = {t["task_id"] for t in all_tasks if t["status"] == "COMPLETED"}
        ready: List[Dict[str, Any]] = []

        for t in all_tasks:
            if t["status"] in ("PENDING", "READY"):
                deps = json.loads(t["dependencies"])
                if all(dep in completed_ids for dep in deps):
                    ready.append({
                        "task_id": t["task_id"],
                        "name": t["name"],
                        "assigned_to": t["assigned_to"],
                        "dependencies": deps,
                        "status": t["status"],
                    })

        return ready

    def update_task_status(
        self,
        task_id: str,
        status: str,
        result: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Update task status ('READY', 'RUNNING', 'COMPLETED', 'FAILED') and store result payload."""
        allowed = {"PENDING", "READY", "RUNNING", "COMPLETED", "FAILED"}
        if status not in allowed:
            raise ValueError(f"Invalid status: {status}. Allowed: {allowed}")

        res_json = json.dumps(result) if result is not None else None
        now = self._now()

        with self._connection() as conn:
            if res_json is not None:
                cursor = conn.execute(
                    "UPDATE tasks SET status = ?, result = ?, updated_at = ? WHERE task_id = ?",
                    (status, res_json, now, task_id),
                )
            else:
                cursor = conn.execute(
                    "UPDATE tasks SET status = ?, updated_at = ? WHERE task_id = ?",
                    (status, now, task_id),
                )
            conn.commit()
            if cursor.rowcount == 0:
                return False

        self.log_event("TASK_STATUS_UPDATED", "DAGEngine", f"Task '{task_id}' -> {status}")
        return True

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full details for a single task."""
        with self._connection() as conn:
            r = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
            if not r:
                return None
            return {
                "task_id": r["task_id"],
                "name": r["name"],
                "assigned_to": r["assigned_to"],
                "status": r["status"],
                "dependencies": json.loads(r["dependencies"]),
                "result": json.loads(r["result"]) if r["result"] else None,
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }

    def set_shared_context(self, key: str, value: Any) -> None:
        """Set shared state data accessible by all agents."""
        val_json = json.dumps(value)
        now = self._now()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO shared_context (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (key, val_json, now),
            )
            conn.commit()

    def get_shared_context(self, key: str) -> Optional[Any]:
        """Read shared state value."""
        with self._connection() as conn:
            r = conn.execute("SELECT value FROM shared_context WHERE key = ?", (key,)).fetchone()
            if r:
                return json.loads(r["value"])
            return None

    def get_dag_summary(self) -> Dict[str, Any]:
        """Summarize current DAG execution state."""
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM tasks ORDER BY created_at ASC").fetchall()

        tasks_list = []
        counts = {"PENDING": 0, "READY": 0, "RUNNING": 0, "COMPLETED": 0, "FAILED": 0}
        for r in rows:
            st = r["status"]
            if st in counts:
                counts[st] += 1
            tasks_list.append({
                "task_id": r["task_id"],
                "name": r["name"],
                "assigned_to": r["assigned_to"],
                "status": st,
                "dependencies": json.loads(r["dependencies"]),
                "has_result": r["result"] is not None,
            })

        ready = self.get_ready_tasks()

        return {
            "success": True,
            "total_tasks": len(tasks_list),
            "status_counts": counts,
            "ready_to_execute": [t["task_id"] for t in ready],
            "tasks": tasks_list,
        }

    # -----------------------------------------------------------------------
    # Multi-Agent Point-to-Point Mailbox Subsystem (Munder Difflin Pattern)
    # -----------------------------------------------------------------------

    def get_task_message_count(self, task_id: str) -> int:
        """Count total messages dispatched for a given task."""
        with self._connection() as conn:
            r = conn.execute("SELECT COUNT(*) as cnt FROM messages WHERE task_id = ?", (task_id,)).fetchone()
            return int(r["cnt"]) if r else 0

    def send_agent_message(
        self,
        task_id: str,
        from_agent: str,
        to_agent: str,
        speech_act: str,
        subject: str,
        payload: Any,
        hop_count: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Send a point-to-point message between agents.
        Enforces Max Hop TTL = 20 to prevent infinite ping-pong.
        """
        speech_act_upper = speech_act.upper()
        if speech_act_upper not in ALLOWED_SPEECH_ACTS:
            raise ValueError(f"Invalid speech_act '{speech_act}'. Allowed: {sorted(ALLOWED_SPEECH_ACTS)}")

        # Check total messages for this task
        current_task_msgs = self.get_task_message_count(task_id)
        if current_task_msgs >= MAX_HOP_TTL:
            raise ValueError(
                f"Max Hop TTL ({MAX_HOP_TTL}) exceeded for task '{task_id}'. "
                f"Loop drainage stop-hook triggered to prevent infinite ping-pong."
            )

        assigned_hop = hop_count if hop_count is not None else (current_task_msgs + 1)
        if assigned_hop > MAX_HOP_TTL:
            raise ValueError(
                f"Hop count {assigned_hop} exceeds Max Hop TTL ({MAX_HOP_TTL}) for task '{task_id}'."
            )

        msg_id = f"msg_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}"
        now = self._now()
        payload_str = json.dumps(payload)

        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO messages (
                    msg_id, task_id, from_agent, to_agent, speech_act, subject, payload, status, hop_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'UNREAD', ?, ?);
                """,
                (msg_id, task_id, from_agent, to_agent, speech_act_upper, subject, payload_str, assigned_hop, now),
            )
            conn.commit()

        self.log_event("MESSAGE_SENT", from_agent, f"[{speech_act_upper}] to {to_agent} on task {task_id}: {subject}")

        return {
            "msg_id": msg_id,
            "task_id": task_id,
            "from_agent": from_agent,
            "to_agent": to_agent,
            "speech_act": speech_act_upper,
            "subject": subject,
            "payload": payload,
            "status": "UNREAD",
            "hop_count": assigned_hop,
            "created_at": now,
        }

    def get_agent_inbox(
        self,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        unread_only: bool = True,
    ) -> List[Dict[str, Any]]:
        """Retrieve inbox messages filtered by task, agent recipient, and read status."""
        query = "SELECT * FROM messages WHERE 1=1"
        params: List[Any] = []

        if task_id:
            query += " AND task_id = ?"
            params.append(task_id)
        if agent_id:
            query += " AND to_agent = ?"
            params.append(agent_id)
        if unread_only:
            query += " AND status = 'UNREAD'"

        query += " ORDER BY created_at ASC"

        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()

        messages: List[Dict[str, Any]] = []
        for r in rows:
            messages.append({
                "msg_id": r["msg_id"],
                "task_id": r["task_id"],
                "from_agent": r["from_agent"],
                "to_agent": r["to_agent"],
                "speech_act": r["speech_act"],
                "subject": r["subject"],
                "payload": json.loads(r["payload"]) if r["payload"] else {},
                "status": r["status"],
                "hop_count": r["hop_count"],
                "created_at": r["created_at"],
            })
        return messages

    def mark_message_processed(self, msg_id: str) -> bool:
        """Mark message as PROCESSED in the mailbox."""
        with self._connection() as conn:
            c = conn.execute("UPDATE messages SET status = 'PROCESSED' WHERE msg_id = ?", (msg_id,))
            conn.commit()
            return c.rowcount > 0

    def is_inbox_drained(self, task_id: str, agent_id: Optional[str] = None) -> bool:
        """
        Autonomous Loop Stop-Hook.
        Returns True when an agent (or the entire task if agent_id is None) has 0 UNREAD messages remaining.
        """
        with self._connection() as conn:
            if agent_id:
                r = conn.execute(
                    "SELECT COUNT(*) as cnt FROM messages WHERE task_id = ? AND to_agent = ? AND status = 'UNREAD'",
                    (task_id, agent_id),
                ).fetchone()
            else:
                r = conn.execute(
                    "SELECT COUNT(*) as cnt FROM messages WHERE task_id = ? AND status = 'UNREAD'",
                    (task_id,),
                ).fetchone()
            return (int(r["cnt"]) if r else 0) == 0

    def get_task_messages(self, task_id: str) -> List[Dict[str, Any]]:
        """Retrieve full conversation history for a task."""
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM messages WHERE task_id = ? ORDER BY created_at ASC", (task_id,)).fetchall()

        return [
            {
                "msg_id": r["msg_id"],
                "task_id": r["task_id"],
                "from_agent": r["from_agent"],
                "to_agent": r["to_agent"],
                "speech_act": r["speech_act"],
                "subject": r["subject"],
                "payload": json.loads(r["payload"]) if r["payload"] else {},
                "status": r["status"],
                "hop_count": r["hop_count"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def create_standard_security_pipeline(
        self,
        pipeline_id: str,
        target_file: str,
        include_soc: bool = False,
    ) -> Dict[str, Any]:
        """
        Scaffold standard Lead-Worker pipeline:
        1. sec_audit (Security Auditor)
        2. debug_repro (Debugger) -> depends on sec_audit
        3. patch_dev (Patch Developer) -> depends on sec_audit, debug_repro
        4. qa_review (QA Reviewer) -> depends on patch_dev
        5. (optional) soc_triage (SOC Incident Responder) -> depends on sec_audit
        """
        t1 = f"{pipeline_id}_sec_audit"
        t2 = f"{pipeline_id}_debug_repro"
        t3 = f"{pipeline_id}_patch_dev"
        t4 = f"{pipeline_id}_qa_review"

        self.add_task(t1, f"Audit Attack Surface & CWEs for {target_file}", "Security Auditor", [])
        self.add_task(t2, f"Hypothesis Debug & Reproduction Test for {target_file}", "Debugger", [t1])
        self.add_task(t3, f"Draft Minimal Patch (diff <= 50) for {target_file}", "Patch Developer", [t1, t2])
        self.add_task(t4, f"QA Sandbox Verification & Zero-Regression SAST for {target_file}", "QA Reviewer", [t3])

        if include_soc:
            t_soc = f"{pipeline_id}_soc_incident_triage"
            self.add_task(t_soc, f"SOC Incident Triage & IOC Containment for {target_file}", "SOC Incident Responder", [t1])

        self.set_shared_context("current_pipeline", {
            "pipeline_id": pipeline_id,
            "target_file": target_file,
            "stage": "INITIALIZED",
            "include_soc": include_soc,
        })

        return self.get_dag_summary()
