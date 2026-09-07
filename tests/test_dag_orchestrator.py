"""
Unit tests for Multi-Agent DAG Orchestration, SQLite WAL Shared State,
Point-to-Point Mailbox, Loop Drainage Stop-Hooks, and Max Hop TTL = 20.
"""

import unittest
from core.dag_engine import DAGEngine, DAGCycleError, MAX_HOP_TTL


class TestDAGOrchestrator(unittest.TestCase):

    def setUp(self):
        # Use isolated in-memory DB for unit test speed and purity
        self.engine = DAGEngine(db_path=":memory:")

    def test_add_task_and_topological_sort(self):
        """Verify adding tasks and sorting topologically."""
        self.engine.add_task("task_a", "Task A", "Worker 1", [])
        self.engine.add_task("task_b", "Task B", "Worker 2", ["task_a"])
        self.engine.add_task("task_c", "Task C", "Worker 3", ["task_b"])

        order = self.engine.validate_dag()
        self.assertIn("task_a", order)
        self.assertIn("task_b", order)
        self.assertIn("task_c", order)
        self.assertLess(order.index("task_a"), order.index("task_b"))
        self.assertLess(order.index("task_b"), order.index("task_c"))

    def test_cycle_detection(self):
        """Circular dependencies must be caught and raise DAGCycleError."""
        self.engine.add_task("task_1", "One", "Worker", ["task_3"])
        self.engine.add_task("task_2", "Two", "Worker", ["task_1"])
        with self.assertRaises(DAGCycleError):
            self.engine.add_task("task_3", "Three", "Worker", ["task_2"])

    def test_ready_tasks_progression(self):
        """Ready tasks should progress dynamically as dependencies complete."""
        self.engine.add_task("t1", "Audit", "Auditor", [])
        self.engine.add_task("t2", "Debug", "Debugger", ["t1"])
        self.engine.add_task("t3", "Patch", "Developer", ["t2"])

        # Initially, only t1 is ready
        ready_0 = self.engine.get_ready_tasks()
        self.assertEqual([t["task_id"] for t in ready_0], ["t1"])

        # Complete t1
        self.engine.update_task_status("t1", "COMPLETED", result={"status": "clean"})
        ready_1 = self.engine.get_ready_tasks()
        self.assertEqual([t["task_id"] for t in ready_1], ["t2"])

        # Complete t2
        self.engine.update_task_status("t2", "COMPLETED", result={"repro": "passed"})
        ready_2 = self.engine.get_ready_tasks()
        self.assertEqual([t["task_id"] for t in ready_2], ["t3"])

    def test_shared_context_state(self):
        """Verify setting and reading shared context memory across agents."""
        self.engine.set_shared_context("lead_decision", {"approved": True, "reviewer": "Alice"})
        val = self.engine.get_shared_context("lead_decision")
        self.assertEqual(val["approved"], True)

    def test_standard_security_pipeline(self):
        """Verify the standard 4-Worker security pipeline scaffolding."""
        summary = self.engine.create_standard_security_pipeline("issue_42", "main_service.py")
        self.assertEqual(summary["total_tasks"], 4)
        self.assertEqual(len(summary["ready_to_execute"]), 1)
        self.assertTrue(summary["ready_to_execute"][0].endswith("_sec_audit"))

    def test_standard_security_pipeline_with_soc(self):
        """Verify 5-Worker pipeline when include_soc is enabled."""
        summary = self.engine.create_standard_security_pipeline("issue_42", "main_service.py", include_soc=True)
        self.assertEqual(summary["total_tasks"], 5)

    def test_cycle_rejection_leaves_database_unpoisoned(self):
        """Rejecting a circular dependency must NOT leave the database poisoned."""
        self.engine.add_task("task_1", "One", "Worker", [])
        self.engine.add_task("task_2", "Two", "Worker", ["task_1"])
        with self.assertRaises(DAGCycleError):
            self.engine.add_task("task_1", "One", "Worker", ["task_2"])  # cycle!

        # DAG must remain valid and operational
        order = self.engine.validate_dag()
        self.assertEqual(order, ["task_1", "task_2"])
        summary = self.engine.get_dag_summary()
        self.assertEqual(summary["total_tasks"], 2)

    def test_update_nonexistent_task_returns_false(self):
        """Updating a task that does not exist must return False."""
        res = self.engine.update_task_status("nonexistent_id", "COMPLETED")
        self.assertFalse(res)

    def test_update_invalid_status_raises_value_error(self):
        """Updating with an invalid status must raise ValueError."""
        self.engine.add_task("t1", "Task 1", "Worker", [])
        with self.assertRaises(ValueError):
            self.engine.update_task_status("t1", "INVALID_STATUS")

    # -----------------------------------------------------------------------
    # Point-to-Point Mailbox & Loop Drainage Tests
    # -----------------------------------------------------------------------

    def test_mailbox_send_and_inbox_drainage(self):
        """Verify sending messages, reading inbox, marking processed, and checking drainage."""
        task_id = "task_debug_1"
        self.engine.add_task(task_id, "Debug Memory Leak", "Debugger", [])

        # Initially inbox is drained
        self.assertTrue(self.engine.is_inbox_drained(task_id, "Debugger"))

        # Send message from Lead Orchestrator to Debugger
        msg = self.engine.send_agent_message(
            task_id=task_id,
            from_agent="Lead Orchestrator",
            to_agent="Debugger",
            speech_act="REQUEST",
            subject="Isolate root cause",
            payload={"repro_steps": ["step1", "step2"]},
        )
        self.assertEqual(msg["status"], "UNREAD")
        self.assertEqual(msg["speech_act"], "REQUEST")

        # Inbox is no longer drained
        self.assertFalse(self.engine.is_inbox_drained(task_id, "Debugger"))

        # Retrieve inbox
        inbox = self.engine.get_agent_inbox(task_id=task_id, agent_id="Debugger", unread_only=True)
        self.assertEqual(len(inbox), 1)
        self.assertEqual(inbox[0]["msg_id"], msg["msg_id"])

        # Mark message as processed
        ok = self.engine.mark_message_processed(msg["msg_id"])
        self.assertTrue(ok)

        # Autonomous Loop Stop-Hook: inbox is drained now
        self.assertTrue(self.engine.is_inbox_drained(task_id, "Debugger"))
        unread_inbox = self.engine.get_agent_inbox(task_id=task_id, agent_id="Debugger", unread_only=True)
        self.assertEqual(len(unread_inbox), 0)

    def test_max_hop_ttl_enforcement(self):
        """Verify Max Hop TTL = 20 prevents infinite communication loops."""
        task_id = "task_pingpong"
        self.engine.add_task(task_id, "Collaborative Debugging", "Debugger", [])

        # Send 20 valid hops
        for hop in range(1, MAX_HOP_TTL + 1):
            sender = "Security Auditor" if hop % 2 == 1 else "Debugger"
            recipient = "Debugger" if hop % 2 == 1 else "Security Auditor"
            msg = self.engine.send_agent_message(
                task_id=task_id,
                from_agent=sender,
                to_agent=recipient,
                speech_act="INFORM",
                subject=f"Hop {hop}",
                payload={"hop": hop},
            )
            self.assertEqual(msg["hop_count"], hop)

        self.assertEqual(self.engine.get_task_message_count(task_id), 20)

        # 21st message must raise ValueError triggering the loop drainage stop-hook
        with self.assertRaises(ValueError) as ctx:
            self.engine.send_agent_message(
                task_id=task_id,
                from_agent="Security Auditor",
                to_agent="Debugger",
                speech_act="INFORM",
                subject="Hop 21 - Should Fail",
                payload={"hop": 21},
            )
        self.assertIn(f"Max Hop TTL ({MAX_HOP_TTL}) exceeded", str(ctx.exception))

    def test_invalid_speech_act_raises_value_error(self):
        """Unrecognized speech act must raise ValueError."""
        with self.assertRaises(ValueError):
            self.engine.send_agent_message(
                task_id="t1",
                from_agent="Auditor",
                to_agent="Debugger",
                speech_act="INVALID_SPEECH_ACT",
                subject="Hello",
                payload={},
            )


    def test_task_wide_inbox_drainage_check(self):
        """Verify is_inbox_drained checks entire task mailbox when agent_id is None."""
        task_id = "task_broadcast"
        self.engine.add_task(task_id, "Multi-Agent Coordination", "Lead Orchestrator", [])

        # Initially empty task is drained
        self.assertTrue(self.engine.is_inbox_drained(task_id))

        # Send message
        msg = self.engine.send_agent_message(
            task_id=task_id,
            from_agent="Security Auditor",
            to_agent="Patch Developer",
            speech_act="INFORM",
            subject="Attack surface report",
            payload={"cwe": "CWE-78"},
        )
        self.assertFalse(self.engine.is_inbox_drained(task_id))

        # Mark processed -> task-wide is drained again
        self.engine.mark_message_processed(msg["msg_id"])
        self.assertTrue(self.engine.is_inbox_drained(task_id))

    def test_recover_orphaned_tasks(self):
        """Verify recovering orphaned RUNNING tasks resets to READY or PENDING based on dependencies."""
        # Task 1: COMPLETED
        self.engine.add_task("t1", "Audit", "Auditor", [])
        self.engine.update_task_status("t1", "COMPLETED")

        # Task 2: RUNNING, depends on t1 (completed) -> should become READY
        self.engine.add_task("t2", "Debug", "Debugger", ["t1"])
        self.engine.update_task_status("t2", "RUNNING")

        # Task 3: PENDING
        self.engine.add_task("t3", "Patch", "Developer", ["t2"])

        # Task 4: RUNNING, depends on t3 (pending) -> should become PENDING
        self.engine.add_task("t4", "Deploy", "Operator", ["t3"])
        self.engine.update_task_status("t4", "RUNNING")

        res = self.engine.recover_orphaned_tasks()
        self.assertTrue(res["success"])
        self.assertEqual(res["recovered_count"], 2)

        task_2 = self.engine.get_task("t2")
        self.assertEqual(task_2["status"], "READY")

        task_4 = self.engine.get_task("t4")
        self.assertEqual(task_4["status"], "PENDING")

        logs = self.engine.get_audit_log(event_type="TASK_ORPHAN_RECOVERED")
        self.assertEqual(len(logs), 2)


if __name__ == "__main__":
    unittest.main()
