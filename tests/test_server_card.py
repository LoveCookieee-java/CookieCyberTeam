"""
Drift guard for the published MCP discovery card.

``.well-known/mcp/server-card.json`` duplicates the tool, resource, and prompt
surface that ``server.py`` exposes. Duplication is fine for discovery, but it
must never silently diverge: a stale card makes clients advertise tools that no
longer exist (or hide ones that do). These tests fail loudly on any drift so the
card has to be updated in the same change as the server.
"""

import json
import unittest
from pathlib import Path

from server import CookieCyberMCPServer


CARD_PATH = Path(__file__).resolve().parent.parent / ".well-known" / "mcp" / "server-card.json"


class TestServerCard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.card = json.loads(CARD_PATH.read_text(encoding="utf-8"))
        cls.server = CookieCyberMCPServer(db_path=":memory:")

    def test_card_is_valid_json_with_server_info(self):
        self.assertEqual(self.card["serverInfo"]["name"], "cookie-cyber-team")
        self.assertIn("version", self.card["serverInfo"])

    def test_card_version_matches_server_version(self):
        import server as server_module
        self.assertEqual(self.card["serverInfo"]["version"], server_module.SERVER_VERSION)

    def test_tool_names_match_server(self):
        card_tools = {t["name"] for t in self.card["tools"]}
        server_tools = {t["name"] for t in self.server.get_tool_definitions()}
        self.assertEqual(card_tools, server_tools)
        self.assertEqual(len(self.card["tools"]), len(server_tools))

    def test_resource_uris_match_server(self):
        card_uris = {r["uri"] for r in self.card["resources"]}
        server_uris = {r["uri"] for r in self.server.get_resource_definitions()}
        self.assertEqual(card_uris, server_uris)

    def test_prompt_names_match_server(self):
        card_prompts = {p["name"] for p in self.card["prompts"]}
        server_prompts = {p["name"] for p in self.server.get_prompt_definitions()}
        self.assertEqual(card_prompts, server_prompts)

    def test_every_card_tool_declares_an_input_schema(self):
        for tool in self.card["tools"]:
            self.assertIn("inputSchema", tool, tool.get("name"))
            self.assertEqual(tool["inputSchema"].get("type"), "object", tool.get("name"))


if __name__ == "__main__":
    unittest.main()
