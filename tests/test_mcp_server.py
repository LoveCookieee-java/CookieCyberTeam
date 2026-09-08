"""
Unit tests for CookieCyberTeam MCP Server JSON-RPC protocol & Tool dispatching.
Tests all 16 Tools, 8 Resources, 6 Prompts, Mailbox routing, Code Search, and Binary Triage.
"""

import json
import tempfile
import unittest
from pathlib import Path
from server import CookieCyberMCPServer


class TestMCPServer(unittest.TestCase):

    def setUp(self):
        self.server = CookieCyberMCPServer(db_path=":memory:")

    def test_initialize_handshake(self):
        """Verify initialize RPC response adheres to MCP protocol."""
        req = {"jsonrpc": "2.0", "id": 101, "method": "initialize", "params": {}}
        resp = self.server.handle_request(req)
        self.assertEqual(resp["id"], 101)
        res = resp["result"]
        self.assertEqual(res["protocolVersion"], "2024-11-05")
        self.assertEqual(res["serverInfo"]["name"], "cookie-cyber-team")

    def test_tools_list_all_nineteen(self):
        """Verify all 19 core tools are registered."""
        req = {"jsonrpc": "2.0", "id": 102, "method": "tools/list", "params": {}}
        resp = self.server.handle_request(req)
        tools = resp["result"]["tools"]
        self.assertEqual(len(tools), 19)
        tool_names = {t["name"] for t in tools}
        expected = {
            "mcp_adaptive_guide",
            "mcp_scan_vulnerabilities",
            "mcp_audit_dependencies",
            "mcp_execute_sandbox_test",
            "mcp_create_reproduction_test",
            "mcp_preview_surgical_patch",
            "mcp_apply_safe_patch",
            "mcp_orchestrate_dag",
            "mcp_search_code",
            "mcp_triage_binary",
            "mcp_run_diagnostic_tool",
            "mcp_submit_dynamic_sandbox",
            "mcp_quarantine_artifact",
            "mcp_restore_quarantined_file",
            "mcp_generate_containment_rule",
            "mcp_terminate_process",
            "mcp_ponytail_review",
            "mcp_ponytail_audit",
            "mcp_ponytail_debt",
        }
        self.assertEqual(tool_names, expected)

    def test_resources_list_and_read_all_nine(self):
        """Verify all 9 resources are registered and readable."""
        req = {"jsonrpc": "2.0", "id": 103, "method": "resources/list", "params": {}}
        resp = self.server.handle_request(req)
        resources = resp["result"]["resources"]
        self.assertEqual(len(resources), 9)
        uris = {r["uri"] for r in resources}
        expected_uris = {
            "mcp://rules/security-standards",
            "mcp://rules/debugging-mindset",
            "mcp://rules/ponytail-ladder",
            "mcp://state/agent-context",
            "mcp://state/tool-index",
            "mcp://playbooks/malware-triage",
            "mcp://playbooks/compromise-assessment",
            "mcp://context/project-genome",
            "mcp://rules/active-guardrails",
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

    def test_prompts_list_and_get_all_eight(self):
        """Verify prompt templates generation for all 8 agent personas."""
        req = {"jsonrpc": "2.0", "id": 105, "method": "prompts/list", "params": {}}
        resp = self.server.handle_request(req)
        prompts = resp["result"]["prompts"]
        self.assertEqual(len(prompts), 8)

        expected_prompts = [
            "mcp_prompt_orchestrator",
            "mcp_prompt_security_audit",
            "mcp_prompt_hypothesis_debug",
            "mcp_prompt_safe_patch",
            "mcp_prompt_qa_review",
            "mcp_prompt_soc_incident_responder",
            "mcp_prompt_ponytail_review",
            "mcp_prompt_ponytail_minimalist",
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
        """Verify mcp_create_reproduction_test writes and runs test within isolated workspace."""
        with tempfile.TemporaryDirectory() as tmpdir:
            server = CookieCyberMCPServer(db_path=":memory:", workspace_root=tmpdir)
            test_file = Path(tmpdir) / "tests" / "repro" / "test_repro.py"
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
            resp = server.handle_request(req)
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertTrue(payload["success"])
            self.assertTrue(payload["reproduced_successfully"])

    def test_tool_call_create_reproduction_test_path_traversal_rejections(self):
        """Verify mcp_create_reproduction_test strictly rejects path traversal and sensitive targets (case-insensitive)."""
        dummy_code = "import unittest\nclass T(unittest.TestCase): pass\n"

        # 1. Traversal outside workspace
        req_traversal = {
            "jsonrpc": "2.0",
            "id": 190,
            "method": "tools/call",
            "params": {
                "name": "mcp_create_reproduction_test",
                "arguments": {"save_path": "../malicious_escape.py", "test_code": dummy_code},
            },
        }
        resp = self.server.handle_request(req_traversal)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertFalse(payload["success"])
        self.assertIn("Path traversal", payload["error"])

        # 2. Writing into .git directory (including Windows case-variations like .GIT)
        for git_variant in (".git/hooks/pre-commit", ".GIT/hooks/pre-commit", ".Git/config"):
            req_git = {
                "jsonrpc": "2.0",
                "id": 191,
                "method": "tools/call",
                "params": {
                    "name": "mcp_create_reproduction_test",
                    "arguments": {"save_path": git_variant, "test_code": dummy_code},
                },
            }
            resp = self.server.handle_request(req_git)
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertFalse(payload["success"])
            self.assertIn(".git directory is strictly forbidden", payload["error"])

        # 3. Writing to sensitive environment files (including uppercase .ENV)
        for env_variant in (".env", ".ENV", ".ssh/authorized_keys"):
            req_env = {
                "jsonrpc": "2.0",
                "id": 192,
                "method": "tools/call",
                "params": {
                    "name": "mcp_create_reproduction_test",
                    "arguments": {"save_path": env_variant, "test_code": dummy_code},
                },
            }
            resp = self.server.handle_request(req_env)
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertFalse(payload["success"])
            self.assertIn("sensitive path", payload["error"])

    def test_tool_call_apply_safe_patch_single_committer_token_validation(self):
        """Verify mcp_apply_safe_patch enforces single-committer session tokens issued via DAG pipeline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            server = CookieCyberMCPServer(db_path=":memory:", workspace_root=tmpdir)
            test_file = Path(tmpdir) / "app.py"
            test_file.write_text("x = 10\n", encoding="utf-8")

            # 1. Initialize DAG pipeline -> issues committer_token for Lead Orchestrator
            init_req = {
                "jsonrpc": "2.0",
                "id": 193,
                "method": "tools/call",
                "params": {
                    "name": "mcp_orchestrate_dag",
                    "arguments": {"action": "init_pipeline", "target_file": str(test_file)},
                },
            }
            init_resp = server.handle_request(init_req)
            init_data = json.loads(init_resp["result"]["content"][0]["text"])
            self.assertIn("committer_token", init_data)
            token = init_data["committer_token"]
            self.assertTrue(token.startswith("lead-token-"))

            # 2. Applying patch without token fails Single-Committer Gate
            patch_no_token = {
                "jsonrpc": "2.0",
                "id": 194,
                "method": "tools/call",
                "params": {
                    "name": "mcp_apply_safe_patch",
                    "arguments": {
                        "target_file": str(test_file),
                        "patched_content": "x = 20\n",
                        "committer": "Lead Orchestrator",
                    },
                },
            }
            res = server.handle_request(patch_no_token)
            payload = json.loads(res["result"]["content"][0]["text"])
            self.assertFalse(payload["success"])
            self.assertTrue(payload.get("violation"))
            self.assertEqual(payload.get("gate"), "Single-Committer Gate")
            self.assertIn("Missing or invalid session token", payload.get("message", ""))

            # 3. Applying patch with invalid token fails Single-Committer Gate
            patch_bad_token = {
                "jsonrpc": "2.0",
                "id": 195,
                "method": "tools/call",
                "params": {
                    "name": "mcp_apply_safe_patch",
                    "arguments": {
                        "target_file": str(test_file),
                        "patched_content": "x = 20\n",
                        "committer": "Lead Orchestrator",
                        "committer_token": "invalid-token-xyz",
                    },
                },
            }
            res = server.handle_request(patch_bad_token)
            payload = json.loads(res["result"]["content"][0]["text"])
            self.assertFalse(payload["success"])
            self.assertTrue(payload.get("violation"))
            self.assertEqual(payload.get("gate"), "Single-Committer Gate")

            # 4. Applying patch with valid token succeeds
            patch_valid_token = {
                "jsonrpc": "2.0",
                "id": 196,
                "method": "tools/call",
                "params": {
                    "name": "mcp_apply_safe_patch",
                    "arguments": {
                        "target_file": str(test_file),
                        "patched_content": "x = 20\n",
                        "committer": "Lead Orchestrator",
                        "committer_token": token,
                    },
                },
            }
            res = server.handle_request(patch_valid_token)
            payload = json.loads(res["result"]["content"][0]["text"])
            self.assertTrue(payload["success"])
            self.assertTrue(payload["token_verified"])
            self.assertEqual(test_file.read_text(encoding="utf-8"), "x = 20\n")

    def test_tool_call_apply_safe_patch_blocks_absolute_and_relative_path_traversal(self):
        """Verify mcp_apply_safe_patch strictly rejects both relative and absolute paths outside workspace root."""
        with tempfile.TemporaryDirectory() as ws_dir, tempfile.TemporaryDirectory() as outside_dir:
            server = CookieCyberMCPServer(db_path=":memory:", workspace_root=ws_dir)
            outside_target = Path(outside_dir) / "escaped.py"

            # 1. Absolute path outside workspace root
            patch_abs = {
                "jsonrpc": "2.0",
                "id": 201,
                "method": "tools/call",
                "params": {
                    "name": "mcp_apply_safe_patch",
                    "arguments": {
                        "target_file": str(outside_target),
                        "patched_content": "hacked = True\n",
                        "committer": "Lead Orchestrator",
                    },
                },
            }
            res_abs = server.handle_request(patch_abs)
            payload_abs = json.loads(res_abs["result"]["content"][0]["text"])
            self.assertFalse(payload_abs["success"])
            self.assertTrue(payload_abs.get("violation"))
            self.assertIn("Path traversal violation", payload_abs.get("message", ""))

            # 2. Relative traversal path outside workspace root
            patch_rel = {
                "jsonrpc": "2.0",
                "id": 202,
                "method": "tools/call",
                "params": {
                    "name": "mcp_apply_safe_patch",
                    "arguments": {
                        "target_file": "../outside.py",
                        "patched_content": "hacked = True\n",
                        "committer": "Lead Orchestrator",
                    },
                },
            }
            res_rel = server.handle_request(patch_rel)
            payload_rel = json.loads(res_rel["result"]["content"][0]["text"])
            self.assertFalse(payload_rel["success"])
            self.assertTrue(payload_rel.get("violation"))
            self.assertIn("Path traversal violation", payload_rel.get("message", ""))

    def test_tool_call_apply_safe_patch_rejects_without_token_at_startup(self):
        """Verify mcp_apply_safe_patch rejects unauthenticated commits at server startup before any pipeline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            server = CookieCyberMCPServer(db_path=":memory:", workspace_root=tmpdir)
            test_file = Path(tmpdir) / "startup_test.py"
            test_file.write_text("v = 1\n", encoding="utf-8")

            # Patch attempt without prior init_pipeline or token
            patch_req = {
                "jsonrpc": "2.0",
                "id": 199,
                "method": "tools/call",
                "params": {
                    "name": "mcp_apply_safe_patch",
                    "arguments": {
                        "target_file": str(test_file),
                        "patched_content": "v = 2\n",
                        "committer": "Lead Orchestrator",
                    },
                },
            }
            resp = server.handle_request(patch_req)
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertFalse(payload["success"])
            self.assertTrue(payload.get("violation"))
            self.assertEqual(payload.get("gate"), "Single-Committer Gate")
            self.assertIn("Missing or invalid session token", payload.get("message", ""))

    def test_tool_call_orchestrate_dag_issue_committer_token(self):
        """Verify requesting committer tokens via mcp_orchestrate_dag action."""
        # 1. Unauthorized requester in issue_committer_token fails
        req_unauth = {
            "jsonrpc": "2.0",
            "id": 197,
            "method": "tools/call",
            "params": {
                "name": "mcp_orchestrate_dag",
                "arguments": {"action": "issue_committer_token", "agent_id": "Security Auditor"},
            },
        }
        resp = self.server.handle_request(req_unauth)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertFalse(payload["success"])
        self.assertIn("not authorized", payload["error"])

        # 2. Worker calling init_pipeline does NOT receive committer_token
        req_worker_init = {
            "jsonrpc": "2.0",
            "id": 198,
            "method": "tools/call",
            "params": {
                "name": "mcp_orchestrate_dag",
                "arguments": {"action": "init_pipeline", "agent_id": "Patch Developer", "target_file": "sample.py"},
            },
        }
        resp_worker = self.server.handle_request(req_worker_init)
        payload_worker = json.loads(resp_worker["result"]["content"][0]["text"])
        self.assertTrue(payload_worker["success"])
        self.assertNotIn("committer_token", payload_worker)

        # 3. Authorized Lead Orchestrator succeeds
        req_auth = {
            "jsonrpc": "2.0",
            "id": 199,
            "method": "tools/call",
            "params": {
                "name": "mcp_orchestrate_dag",
                "arguments": {"action": "issue_committer_token", "agent_id": "Lead Orchestrator"},
            },
        }
        resp = self.server.handle_request(req_auth)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(payload["success"])
        self.assertTrue(payload["committer_token"].startswith("lead-token-"))

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

    def test_tool_scan_vulnerabilities_sarif_output(self):
        """Verify mcp_scan_vulnerabilities returns OASIS SARIF v2.1.0 format when requested."""
        code = "import os\ndef run(cmd): os.system(cmd)\n"
        req = {
            "jsonrpc": "2.0",
            "id": 201,
            "method": "tools/call",
            "params": {
                "name": "mcp_scan_vulnerabilities",
                "arguments": {"code_content": code, "output_format": "sarif"},
            },
        }
        resp = self.server.handle_request(req)
        self.assertNotIn("error", resp)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(payload["success"])
        self.assertEqual(payload["output_format"], "sarif")
        self.assertIn("sarif", payload)
        sarif = payload["sarif"]
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "CookieCyberTeam-AST-Scanner")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "CWE-78")

    def test_tool_submit_dynamic_sandbox_async_and_check_status(self):
        """Verify mcp_submit_dynamic_sandbox supports async_mode and check_status_task_id parameters."""
        # 1. Unconfigured async mode returns guidance with configured=False
        res_async = self.server.handle_call_tool(
            "mcp_submit_dynamic_sandbox",
            {"file_path": "dummy.exe", "async_mode": True},
        )
        self.assertFalse(res_async["success"])
        self.assertFalse(res_async["configured"])

        # 2. Check status by task_id without file_path (primary parameter)
        res_task_id = self.server.handle_call_tool(
            "mcp_submit_dynamic_sandbox",
            {"task_id": 505},
        )
        self.assertFalse(res_task_id["success"])
        self.assertFalse(res_task_id["configured"])
        self.assertEqual(res_task_id["task_id"], 505)

        # 3. Check status by check_status_task_id (legacy alias)
        res_status = self.server.handle_call_tool(
            "mcp_submit_dynamic_sandbox",
            {"check_status_task_id": 404},
        )
        self.assertFalse(res_status["success"])
        self.assertFalse(res_status["configured"])
        self.assertEqual(res_status["task_id"], 404)

        # 4. JSON-RPC tools/call dispatch using task_id
        rpc_req = {
            "jsonrpc": "2.0",
            "id": 202,
            "method": "tools/call",
            "params": {
                "name": "mcp_submit_dynamic_sandbox",
                "arguments": {"task_id": 707},
            },
        }
        rpc_resp = self.server.handle_request(rpc_req)
        self.assertNotIn("error", rpc_resp)
        rpc_payload = json.loads(rpc_resp["result"]["content"][0]["text"])
        self.assertFalse(rpc_payload["success"])
        self.assertEqual(rpc_payload["task_id"], 707)

    def test_tool_submit_dynamic_sandbox_configured_happy_path(self):
        """Verify mcp_submit_dynamic_sandbox happy path with mock configured adapter."""
        class MockResp:
            def __init__(self, data):
                self._raw = json.dumps(data).encode("utf-8")
            def read(self):
                return self._raw
            def __enter__(self): return self
            def __exit__(self, *args): pass

        def mock_transport(req):
            url = req.full_url
            if "/api/v2/tasks/create/file/" in url:
                return MockResp({"task_id": 808})
            elif "/api/v2/tasks/view/808/" in url:
                return MockResp({"data": {"status": "running"}})
            raise ValueError(url)

        from core.cape_adapter import CapeSandboxAdapter
        with tempfile.TemporaryDirectory() as td:
            test_file = Path(td) / "test_artifact.bin"
            test_file.write_bytes(b"MZ\x90\x00data")

            configured_adapter = CapeSandboxAdapter(
                api_url="https://cape.test.local",
                api_key="valid_token",
                transport=mock_transport,
            )
            self.server.cape_adapter = configured_adapter

            # 1. Async submit via JSON-RPC
            submit_req = {
                "jsonrpc": "2.0",
                "id": 301,
                "method": "tools/call",
                "params": {
                    "name": "mcp_submit_dynamic_sandbox",
                    "arguments": {"file_path": str(test_file), "async_mode": True},
                },
            }
            submit_resp = self.server.handle_request(submit_req)
            self.assertNotIn("error", submit_resp)
            submit_payload = json.loads(submit_resp["result"]["content"][0]["text"])
            self.assertTrue(submit_payload["success"])
            self.assertEqual(submit_payload["task_id"], 808)
            self.assertEqual(submit_payload["status"], "pending")

            # 2. Check running status via JSON-RPC
            poll_req = {
                "jsonrpc": "2.0",
                "id": 302,
                "method": "tools/call",
                "params": {
                    "name": "mcp_submit_dynamic_sandbox",
                    "arguments": {"task_id": 808},
                },
            }
            poll_resp = self.server.handle_request(poll_req)
            self.assertNotIn("error", poll_resp)
            poll_payload = json.loads(poll_resp["result"]["content"][0]["text"])
            self.assertTrue(poll_payload["success"])
            self.assertEqual(poll_payload["status"], "running")
            self.assertFalse(poll_payload["completed"])

    def test_quarantine_artifact_tool_jsonrpc(self):
        """Verify mcp_quarantine_artifact via JSON-RPC executes safely."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = CookieCyberMCPServer(db_path=":memory:", workspace_root=tmp_dir)
            sample = Path(tmp_dir) / "suspicious_trojan.exe"
            sample.write_bytes(b"MALWARE_PAYLOAD_TEST_12345")

            req = {
                "jsonrpc": "2.0",
                "id": 401,
                "method": "tools/call",
                "params": {
                    "name": "mcp_quarantine_artifact",
                    "arguments": {"file_path": str(sample)},
                },
            }
            resp = server.handle_request(req)
            self.assertNotIn("error", resp)
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertTrue(payload["success"])
            self.assertIn("quarantine_id", payload)
            self.assertFalse(sample.exists())
            self.assertTrue(Path(payload["quarantine_path"]).exists())

    def test_generate_containment_rule_tool_jsonrpc(self):
        """Verify mcp_generate_containment_rule via JSON-RPC generates rules across platforms."""
        req = {
            "jsonrpc": "2.0",
            "id": 402,
            "method": "tools/call",
            "params": {
                "name": "mcp_generate_containment_rule",
                "arguments": {"target": "203.0.113.50", "rule_type": "block", "port": 8443},
            },
        }
        resp = self.server.handle_request(req)
        self.assertNotIn("error", resp)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(payload["success"])
        self.assertIn("windows_netsh", payload)
        self.assertIn("linux_iptables", payload)
        self.assertIn("linux_ufw", payload)
        self.assertIn("dns_sinkhole", payload)
        self.assertIn("203.0.113.50", payload["windows_netsh"])
        self.assertIn("8443", payload["windows_netsh"])

    def test_tool_call_scan_vulnerabilities_directory(self):
        """Verify mcp_scan_vulnerabilities can scan a directory without crashing."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ws = Path(tmp_dir)
            f = ws / "clean_mod.py"
            f.write_text("def ping(): pass\n", encoding="utf-8")

            server = CookieCyberMCPServer(db_path=":memory:", workspace_root=ws)
            req = {
                "jsonrpc": "2.0",
                "id": 403,
                "method": "tools/call",
                "params": {
                    "name": "mcp_scan_vulnerabilities",
                    "arguments": {"target_path": str(ws)},
                },
            }
            resp = server.handle_request(req)
            self.assertNotIn("error", resp)
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertTrue(payload["success"])
            self.assertEqual(payload["total_findings"], 0)


if __name__ == "__main__":
    unittest.main()

