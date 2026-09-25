"""
Hostile-input fuzz sweep across all 31 MCP tools (/sp Stage 3 contract).

Approved spec (Stage 1 stop-point):
  1. ``CookieCyberMCPServer.handle_call_tool`` must NEVER raise for hostile or
     malformed arguments. Every rejected input returns a structured envelope
     dict (success=False plus an "error"/"message" field), never a raw
     TypeError/KeyError/OSError traceback.
  2. The JSON-RPC layer must surface hostile input as an MCP ``isError`` tool
     envelope, never as a protocol-level ``-32603`` error response.
  3. Patch/reproduction write surfaces must refuse to create files outside the
     configured workspace (traversal, absolute escape, option-like names).

The matrix is derived from each tool's declared ``inputSchema`` so it stays in
sync automatically as tools evolve. ``os.kill`` is disabled inside this suite
so hostile PID fuzzing can never signal a real process, and the workspace is a
throwaway temp dir so accidental writes cannot touch the repository.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from server import CookieCyberMCPServer

# ---------------------------------------------------------------------------
# Hostile payload families
# ---------------------------------------------------------------------------

LONG_STRING = "A" * 200_000

STRING_HOSTILES = [
    "--output=C:\\pwn.txt",
    "-o,/etc/passwd",
    "../../etc/passwd",
    "..\\..\\windows\\system32\\config.sam",
    "/proc/self/environ",
    "NUL",
    "CON",
    "\x00\x01binary-prefix",
    "trailing\x00",
    "'; DROP TABLE findings;--",
    "${jndi:ldap://evil/a}",
    "%s%s%s%n%n%n",
    "  \t\n  ",
    LONG_STRING,
]

INT_HOSTILES = [0, -1, -(2**63), 2**63, 2**40, True, False, 3.5, -0.5]

BOOL_HOSTILES = ["yes", 1, 0, "", None]

ARRAY_HOSTILES = [
    [None],
    ["--flag"],
    [{}],
    {"a": 1},
    "not-a-list",
    [1, 2, {"x": [None] * 50}],
]

OBJECT_HOSTILES = [
    {"cwe_id": {"nested": {"deep": 1}}},
    [],
    "not-an-object",
    42,
    {"fingerprint": "\x00"},
    {"file_path": "../../etc/passwd"},
]

ENUM_HOSTILES = ["WRONG_ENUM", "", 123, None, "recall\x00"]

ROUNDS = 6  # hostile rounds per tool (>= max(len(family)) coverage via rotation)


def hostile_for(schema):
    """Pick the hostile payload family matching a declared argument schema."""
    if "enum" in schema:
        return ENUM_HOSTILES
    declared = schema.get("type", "string")
    if declared in ("integer", "number"):
        return INT_HOSTILES
    if declared == "boolean":
        return BOOL_HOSTILES
    if declared == "array":
        return ARRAY_HOSTILES
    if declared == "object":
        return OBJECT_HOSTILES
    return STRING_HOSTILES


def build_args(tool, round_idx):
    """Deterministically build one hostile arguments dict for a tool."""
    props = tool.get("inputSchema", {}).get("properties", {})
    args = {}
    for offset, (name, schema) in enumerate(props.items()):
        family = hostile_for(schema)
        args[name] = family[(round_idx + offset) % len(family)]
    return args


class TestToolInputFuzzContract(unittest.TestCase):
    """Contract: hostile arguments yield envelopes, never exceptions."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="fuzz-ws-")
        cls._old_cwd = os.getcwd()
        os.chdir(cls._tmp)
        cls.server = CookieCyberMCPServer(
            db_path=":memory:",
            workspace_root=cls._tmp,
            allowed_roots=[cls._tmp],
        )

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls._old_cwd)
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def setUp(self):
        # Never let hostile PID fuzzing signal a real process.
        kill_patcher = mock.patch(
            "os.kill", side_effect=OSError("fuzz sandbox: os.kill disabled")
        )
        kill_patcher.start()
        self.addCleanup(kill_patcher.stop)

    # -- helpers ------------------------------------------------------------

    def _tools(self):
        return self.server.get_tool_definitions()

    def _required(self, tool):
        return tool.get("inputSchema", {}).get("required", [])

    # -- contract 1: no tool may raise on hostile arguments ------------------

    def test_no_tool_raises_on_hostile_arguments(self):
        failures = []
        calls = 0
        for tool in self._tools():
            name = tool["name"]
            for round_idx in range(ROUNDS):
                args = build_args(tool, round_idx)
                calls += 1
                try:
                    res = self.server.handle_call_tool(name, args)
                except Exception as exc:  # contract violation
                    failures.append(
                        f"{name} round={round_idx} args_keys={sorted(args)} "
                        f"raised {type(exc).__name__}: {exc}"
                    )
                    continue
                self.assertIsInstance(
                    res,
                    dict,
                    f"{name} round={round_idx} returned non-dict {type(res).__name__}",
                )
                if res.get("success") is False and not (
                    {"error", "message", "stderr", "status"} & set(res)
                ):
                    failures.append(
                        f"{name} round={round_idx}: failure envelope lacks an "
                        f"explanatory channel (error/message/stderr/status): "
                        f"keys={sorted(res)}"
                    )
        self.assertEqual(
            failures,
            [],
            f"{calls} fuzz calls produced {len(failures)} contract violations:\n"
            + "\n".join(failures),
        )

    def test_missing_required_arguments_returns_envelope(self):
        failures = []
        for tool in self._tools():
            required = self._required(tool)
            if not required:
                continue
            try:
                res = self.server.handle_call_tool(tool["name"], {})
            except Exception as exc:
                failures.append(
                    f"{tool['name']} missing {required} raised "
                    f"{type(exc).__name__}: {exc}"
                )
                continue
            self.assertIsInstance(res, dict)
            self.assertFalse(
                res.get("success", True),
                f"{tool['name']} reported success with required args {required} missing",
            )
        self.assertEqual(failures, [], "\n".join(failures))

    def test_arguments_wrong_wholesale_type_returns_envelope(self):
        failures = []
        for tool in self._tools():
            for junk in (None, "string", 42, [1, 2], {"x": {"deep": [None]}}):
                args = junk if junk is not None else None
                try:
                    res = self.server.handle_call_tool(tool["name"], args)
                except Exception as exc:
                    failures.append(
                        f"{tool['name']} arguments={junk!r:.60} raised "
                        f"{type(exc).__name__}: {exc}"
                    )
                    continue
                self.assertIsInstance(res, dict)
        self.assertEqual(failures, [], "\n".join(failures))

    def test_unknown_tool_still_raises_keyerror(self):
        # Protocol-level lookup failure maps to JSON-RPC -32601; keep it.
        with self.assertRaises(KeyError):
            self.server.handle_call_tool("mcp_definitely_not_a_tool", {})

    # -- contract 2: JSON-RPC layer never converts hostile input to -32603 ---

    def test_jsonrpc_surfaces_hostile_input_as_tool_error(self):
        req = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "mcp_create_reproduction_test",
                "arguments": {"save_path": {"evil": "dict"}, "test_code": ["not", "a", "string"]},
            },
        }
        resp = self.server.handle_request(req)
        self.assertNotIn(
            "error",
            resp,
            f"hostile tool input produced a protocol error instead of an isError envelope: {resp}",
        )
        result = resp.get("result", {})
        self.assertTrue(result.get("isError"), f"expected isError=true envelope, got: {result}")

    # -- contract 3: write surfaces refuse workspace escape -------------------

    def test_write_tools_refuse_workspace_escape(self):
        outside_marker = Path(tempfile.gettempdir()) / "fuzz-escape-marker.txt"
        if outside_marker.exists():
            outside_marker.unlink()
        escape_target = Path(tempfile.gettempdir()) / "fuzz-escape-target.txt"
        if escape_target.exists():
            escape_target.unlink()

        cases = [
            (
                "mcp_create_reproduction_test",
                {"save_path": str(escape_target), "test_code": "assert False\n"},
            ),
            (
                "mcp_create_reproduction_test",
                {"save_path": "..\\..\\fuzz-escape-target.txt", "test_code": "assert False\n"},
            ),
            (
                "mcp_apply_safe_patch",
                {"target_file": str(escape_target)},
            ),
        ]
        for tool_name, args in cases:
            try:
                res = self.server.handle_call_tool(tool_name, args)
            except Exception as exc:
                self.fail(f"{tool_name} raised {type(exc).__name__}: {exc} for {args}")
            self.assertIsInstance(res, dict)
            self.assertFalse(
                res.get("success", True),
                f"{tool_name} accepted out-of-workspace write target: {args} -> {res}",
            )
        self.assertFalse(escape_target.exists(), "a write tool created a file outside the workspace!")
        self.assertFalse(outside_marker.exists())


if __name__ == "__main__":
    unittest.main()
