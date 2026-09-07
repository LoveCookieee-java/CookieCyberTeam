"""
Unit tests for Blue Team MCP Server JSON-RPC protocol & Tool dispatching.
Tests all 7 Tools, 6 Resources, 6 Prompts, Mailbox routing, Code Search, and Binary Triage.
"""

import json
import tempfile
import unittest
from pathlib import Path
from server import BlueTeamMCPServer


class TestMCPServer(unittest.TestCase):

    def setUp(self):
        self.server = BlueTeamMCPServer(db_path=":memory:")

    def test_initialize_handshake(self):
        """Verify initialize RPC response adheres to MCP protocol."""
        req = {"jsonrpc": "2.0", "id": 101, "method": "initialize", "params": {}}
        resp = self.server.handle_request(req)
        self.assertEqual(resp["id"], 101)
        res = resp["result"]
        self.assertEqual(res["protocolVersion"], "2024-11-05")
        self.assertEqual(res["serverInfo"]["name"], "blue-team-security-guardrails")

    def test_tools_list_all_nine(self):
        """Verify all 9 core tools are registered."""
        req = {"jsonrpc": "2.0", "id": 102, "method": "tools/list", "params": {}}
        resp = self.server.handle_request(req)
        tools = resp["result"]["tools"]
        self.assertEqual(len(tools), 9)
        tool_names = {t["name"] for t in tools}
        expected = {
            "mcp_scan_vulnerabilities",
            "mcp_execute_sandbox_test",
            "mcp_create_reproduction_test",
            "mcp_apply_safe_patch",
            "mcp_orchestrate_dag",
            "mcp_search_code",
            "mcp_triage_binary",
            "mcp_run_diagnostic_tool",
            "mcp_submit_dynamic_sandbox",
        }
        self.assertEqual(tool_names, expected)

    def test_resources_list_and_read_all_six(self):
        """Verify all 6 resources are registered and readable."""
        req = {"jsonrpc": "2.0", "id": 103, "method": "resources/list", "params": {}}
        resp = self.server.handle_request(req)
        resources = resp["result"]["resources"]
        self.assertEqual(len(resources), 6)
        uris = {r["uri"] for r in resources}
        expected_uris = {
            "mcp://rules/security-standards",
            "mcp://rules/debugging-mindset",
            "mcp://state/agent-context",
            "mcp://state/tool-index",
            "mcp://playbooks/malware-triage",
            "mcp://playbooks/compromise-assessment",
        }
        self.assertEqual(uris, expected_uris)

        for uri in expected_uris:
            read_req = {
                "jsonrpc": "2.0",
                "id": 104,
                "method": "resources/read",
                "params": {"uri": uri},
            }
            read_resp = self.server.handle_request(read_req)
            self.assertNotIn("error", read_resp)
            content = read_resp["result"]["contents"][0]["text"]
            self.assertGreater(len(content), 20)

    def test_prompts_list_and_get_all_six(self):
        """Verify prompt templates generation for all 6 agent personas."""
        req = {"jsonrpc": "2.0", "id": 105, "method": "prompts/list", "params": {}}
        resp = self.server.handle_request(req)
        prompts = resp["result"]["prompts"]
        self.assertEqual(len(prompts), 6)

        expected_prompts = [
            "mcp_prompt_orchestrator",
            "mcp_prompt_security_audit",
            "mcp_prompt_hypothesis_debug",
            "mcp_prompt_safe_patch",
            "mcp_prompt_qa_review",
            "mcp_prompt_soc_incident_responder",
        ]

        for p_name in expected_prompts:
            get_req = {
                "jsonrpc": "2.0",
                "id": 106,
                "method": "prompts/get",
                "params": {
                    "name": p_name,
                    "arguments": {
                        "target_file": "auth.py",
                        "issue_description": "SQLi",
                        "incident_description": "Malware activity",
                        "artifact_path": "malware.exe",
                    },
                },
            }
            resp = self.server.handle_request(get_req)
            self.assertNotIn("error", resp)
            self.assertTrue(len(resp["result"]["messages"]) > 0)

    def test_tool_call_scan_vulnerabilities(self):
        """Verify calling mcp_scan_vulnerabilities through JSON-RPC."""
        code = (
            "import os\n"
            "def ping(ip):\n"
            "    os.system('ping -c 1 ' + ip)\n"
        )
        req = {
            "jsonrpc": "2.0",
            "id": 107,
            "method": "tools/call",
            "params": {
                "name": "mcp_scan_vulnerabilities",
                "arguments": {"code_content": code},
            },
        }
        resp = self.server.handle_request(req)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(payload["success"])
        self.assertEqual(payload["findings"][0]["cwe_id"], "CWE-78")
        self.assertEqual(payload["overall_severity"], "Critical")
        self.assertIn("residual_vulnerabilities", payload)
        self.assertEqual(len(payload["residual_vulnerabilities"]), 1)

    def test_tool_call_create_reproduction_test(self):
        """Verify mcp_create_reproduction_test writes and runs test."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test_repro.py"
            failing_test_code = (
                "import unittest\n"
                "class TestBug(unittest.TestCase):\n"
                "    def test_failure(self):\n"
                "        self.assertEqual(1, 2)\n"
                "if __name__ == '__main__':\n"
                "    unittest.main()\n"
            )
            req = {
                "jsonrpc": "2.0",
                "id": 108,
                "method": "tools/call",
                "params": {
                    "name": "mcp_create_reproduction_test",
                    "arguments": {
                        "save_path": str(test_file),
                        "test_code": failing_test_code,
                        "vulnerability_type": "Logic Defect",
                    },
                },
            }
            resp = self.server.handle_request(req)
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertTrue(payload["success"])
            self.assertTrue(payload["reproduced_successfully"])

    def test_tool_call_search_code(self):
        """Verify mcp_search_code returns surgical AST chunks."""
        req = {
            "jsonrpc": "2.0",
            "id": 109,
            "method": "tools/call",
            "params": {
                "name": "mcp_search_code",
                "arguments": {"query": "DAGEngine", "target_path": "core", "top_k": 3},
            },
        }
        resp = self.server.handle_request(req)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(payload["success"])
        self.assertGreaterEqual(payload["total_matches"], 1)

    def test_tool_call_triage_binary(self):
        """Verify mcp_triage_binary executes static analysis under Zero-Execution Policy."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_bin = Path(tmpdir) / "test_sample.elf"
            # Mock ELF header + URL string
            elf_data = b"\x7fELF\x02\x01" + (b"\x00" * 20) + b"https://telemetry-beacon.org/check\x00"
            sample_bin.write_bytes(elf_data)

            req = {
                "jsonrpc": "2.0",
                "id": 110,
                "method": "tools/call",
                "params": {
                    "name": "mcp_triage_binary",
                    "arguments": {"file_path": str(sample_bin)},
                },
            }
            resp = self.server.handle_request(req)
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertTrue(payload["success"])
            self.assertEqual(payload["header"]["format"], "ELF")
            self.assertTrue(any("telemetry-beacon.org" in u for u in payload["iocs"]["urls"]))

    def test_tool_call_orchestrate_dag_mailbox_workflow(self):
        """Verify DAG mailbox send, inbox query, and drainage via RPC."""
        # 1. Init pipeline
        init_req = {
            "jsonrpc": "2.0",
            "id": 111,
            "method": "tools/call",
            "params": {
                "name": "mcp_orchestrate_dag",
                "arguments": {"action": "init_pipeline", "pipeline_id": "p_test", "target_file": "app.py"},
            },
        }
        self.server.handle_request(init_req)

        # 2. Send message
        send_req = {
            "jsonrpc": "2.0",
            "id": 112,
            "method": "tools/call",
            "params": {
                "name": "mcp_orchestrate_dag",
                "arguments": {
                    "action": "send_message",
                    "task_id": "p_test_sec_audit",
                    "from_agent": "Lead Orchestrator",
                    "to_agent": "Security Auditor",
                    "speech_act": "REQUEST",
                    "subject": "Scan endpoints",
                    "payload": {"endpoints": ["/api/login"]},
                },
            },
        }
        send_resp = self.server.handle_request(send_req)
        send_data = json.loads(send_resp["result"]["content"][0]["text"])
        self.assertTrue(send_data["success"])
        msg_id = send_data["message"]["msg_id"]

        # 3. Check drainage before processing (should be False)
        drain_req = {
            "jsonrpc": "2.0",
            "id": 113,
            "method": "tools/call",
            "params": {
                "name": "mcp_orchestrate_dag",
                "arguments": {
                    "action": "check_drainage",
                    "task_id": "p_test_sec_audit",
                    "agent_id": "Security Auditor",
                },
            },
        }
        drain_resp = self.server.handle_request(drain_req)
        drain_data = json.loads(drain_resp["result"]["content"][0]["text"])
        self.assertFalse(drain_data["is_drained"])

        # 4. Mark processed
        mark_req = {
            "jsonrpc": "2.0",
            "id": 114,
            "method": "tools/call",
            "params": {
                "name": "mcp_orchestrate_dag",
                "arguments": {"action": "mark_processed", "msg_id": msg_id},
            },
        }
        mark_resp = self.server.handle_request(mark_req)
        mark_data = json.loads(mark_resp["result"]["content"][0]["text"])
        self.assertTrue(mark_data["success"])

        # 5. Check drainage after processing (should be True)
        drain_resp2 = self.server.handle_request(drain_req)
        drain_data2 = json.loads(drain_resp2["result"]["content"][0]["text"])
        self.assertTrue(drain_data2["is_drained"])

        # 6. Check task-wide drainage without agent_id (should also be True)
        task_drain_req = {
            "jsonrpc": "2.0",
            "id": 115,
            "method": "tools/call",
            "params": {
                "name": "mcp_orchestrate_dag",
                "arguments": {"action": "check_drainage", "task_id": "p_test_sec_audit"},
            },
        }
        task_drain_resp = self.server.handle_request(task_drain_req)
        task_drain_data = json.loads(task_drain_resp["result"]["content"][0]["text"])
        self.assertTrue(task_drain_data["is_drained"])

    def test_unknown_method_error(self):
        """Verify standard -32601 error for unknown methods."""
        req = {"jsonrpc": "2.0", "id": 999, "method": "non_existent_method"}
        resp = self.server.handle_request(req)
        self.assertEqual(resp["error"]["code"], -32601)

    def test_tool_call_orchestrate_dag_update_nonexistent_task_returns_error(self):
        """Verify that updating a non-existent task returns an error response."""
        req = {
            "jsonrpc": "2.0",
            "id": 115,
            "method": "tools/call",
            "params": {
                "name": "mcp_orchestrate_dag",
                "arguments": {
                    "action": "update_task",
                    "task_id": "ghost_task_404",
                    "status": "COMPLETED",
                },
            },
        }
        resp = self.server.handle_request(req)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertFalse(payload["success"])
        self.assertIn("not found", payload["error"])
        self.assertTrue(resp["result"]["isError"])

    def test_tool_call_run_diagnostic_tool(self):
        """Verify mcp_run_diagnostic_tool via JSON-RPC enforces whitelisting and argument sanitization."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(b"SAMPLE_BINARY_HEADER")
            tf_path = tf.name

        try:
            # 1. Non-whitelisted tool rejected
            req_bad = {
                "jsonrpc": "2.0",
                "id": 120,
                "method": "tools/call",
                "params": {
                    "name": "mcp_run_diagnostic_tool",
                    "arguments": {"tool_name": "malicious_binary", "target_file": tf_path},
                },
            }
            resp_bad = self.server.handle_request(req_bad)
            data_bad = json.loads(resp_bad["result"]["content"][0]["text"])
            self.assertFalse(data_bad["success"])
            self.assertIn("whitelist", data_bad["error"])

            # 2. Forbidden shell metacharacter rejected
            req_meta = {
                "jsonrpc": "2.0",
                "id": 121,
                "method": "tools/call",
                "params": {
                    "name": "mcp_run_diagnostic_tool",
                    "arguments": {
                        "tool_name": "strings",
                        "target_file": tf_path,
                        "args": ["-a", "; rm -rf /"],
                    },
                },
            }
            resp_meta = self.server.handle_request(req_meta)
            data_meta = json.loads(resp_meta["result"]["content"][0]["text"])
            self.assertFalse(data_meta["success"])
            self.assertIn("forbidden shell metacharacters", data_meta["error"])
        finally:
            Path(tf_path).unlink(missing_ok=True)

    def test_tool_call_submit_dynamic_sandbox(self):
        """Verify mcp_submit_dynamic_sandbox returns structured response and fallback guidance when unconfigured."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf.write(b"MZ\x90\x00SAMPLE_PE")
            tf_path = tf.name

        try:
            req = {
                "jsonrpc": "2.0",
                "id": 122,
                "method": "tools/call",
                "params": {
                    "name": "mcp_submit_dynamic_sandbox",
                    "arguments": {"file_path": tf_path, "tags": "win10"},
                },
            }
            resp = self.server.handle_request(req)
            data = json.loads(resp["result"]["content"][0]["text"])
            self.assertFalse(data["success"])
            self.assertFalse(data["configured"])
            self.assertIn("CAPE_API_URL", data["advisory"])
            self.assertEqual(data["setup_guide"]["fallback_tool"], "mcp_triage_binary")
        finally:
            Path(tf_path).unlink(missing_ok=True)

    def test_handle_call_tool_direct_dispatch(self):
        """Verify server.handle_call_tool directly executes handlers and raises KeyError for unknown tools."""
        # 1. Successful direct call to mcp_run_diagnostic_tool
        res_diag = self.server.handle_call_tool(
            "mcp_run_diagnostic_tool",
            {"tool_name": "unwhitelisted_tool", "target_file": "dummy.exe"},
        )
        self.assertFalse(res_diag["success"])
        self.assertIn("whitelist", res_diag["error"])

        # 2. Successful direct call to mcp_submit_dynamic_sandbox
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf.write(b"MZ\x90\x00")
            tf_path = tf.name
        try:
            res_sb = self.server.handle_call_tool("mcp_submit_dynamic_sandbox", {"file_path": tf_path})
            self.assertFalse(res_sb["success"])
            self.assertFalse(res_sb["configured"])
        finally:
            Path(tf_path).unlink(missing_ok=True)

        # 3. Unknown tool raises KeyError
        with self.assertRaises(KeyError):
            self.server.handle_call_tool("mcp_nonexistent_tool", {})

    def test_prompts_contain_three_mandatory_user_advisories(self):
        """Verify prompt templates contain Dual-Tier Sandbox, Zero-Execution, and File Safety Invariants."""
        orch = self.server.get_prompt("mcp_prompt_orchestrator", {"issue_description": "CVE-2026-0001", "target_file": "main.py"})
        orch_txt = orch["messages"][0]["content"]["text"]
        self.assertIn("Dual-Tier Sandbox", orch_txt)
        self.assertIn("Zero-Execution Policy", orch_txt)
        self.assertIn("File Safety Invariant", orch_txt)

        soc = self.server.get_prompt("mcp_prompt_soc_incident_responder", {"incident_description": "APT", "artifact_path": "apt.bin"})
        soc_txt = soc["messages"][0]["content"]["text"]
        self.assertIn("Dual-Tier Sandbox", soc_txt)
        self.assertIn("Zero-Execution Policy", soc_txt)
        self.assertIn("File Safety Invariant", soc_txt)


if __name__ == "__main__":
    unittest.main()
