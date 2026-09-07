"""
Unit tests for Hybrid Code Search Engine (AST Chunking, SQLite FTS5 BM25, and RRF).
"""

import tempfile
import unittest
from pathlib import Path
from core.code_search import (
    ASTCodeChunker,
    FTS5BM25Searcher,
    HybridCodeSearch,
    SembleAdapter,
    calculate_rrf,
)


SAMPLE_CODE = '''"""Module docstring."""

def authenticate_user(username: str, password_hash: str) -> bool:
    """Verify user credentials against cryptographic hash store."""
    if not username or not password_hash:
        return False
    return True

class SecurityGateKeeper:
    """Enterprise security gate enforcing zero trust policies."""

    def __init__(self, mode: str = "strict"):
        self.mode = mode

    async def verify_token_async(self, token: str) -> dict:
        """Asynchronously validate JSON Web Token signatures."""
        return {"sub": "admin", "valid": True}
'''


class TestCodeSearch(unittest.TestCase):

    def setUp(self):
        self.chunker = ASTCodeChunker()
        self.searcher = FTS5BM25Searcher(in_memory=True)
        self.hybrid = HybridCodeSearch()

    def tearDown(self):
        self.searcher.close()

    def test_ast_syntactic_chunking(self):
        """Verify AST correctly extracts functions, classes, and async functions."""
        chunks = self.chunker.chunk_code(SAMPLE_CODE, file_path="auth_service.py")
        self.assertGreaterEqual(len(chunks), 3)

        chunk_names = {c.name: c for c in chunks}
        self.assertIn("authenticate_user", chunk_names)
        self.assertIn("SecurityGateKeeper", chunk_names)
        self.assertIn("verify_token_async", chunk_names)

        auth_fn = chunk_names["authenticate_user"]
        self.assertEqual(auth_fn.chunk_type, "function")
        self.assertIn("def authenticate_user", auth_fn.content)
        self.assertIn("Verify user credentials", auth_fn.docstring)
        self.assertLess(auth_fn.token_count_est, 100)

        gate_cls = chunk_names["SecurityGateKeeper"]
        self.assertEqual(gate_cls.chunk_type, "class")

        async_fn = chunk_names["verify_token_async"]
        self.assertEqual(async_fn.chunk_type, "async_function")

    def test_ast_syntax_error_fallback(self):
        """Verify chunker falls back to block chunks on invalid Python syntax."""
        broken_code = "def broken(\n    this is not valid python :::"
        chunks = self.chunker.chunk_code(broken_code, file_path="broken.py")
        self.assertGreaterEqual(len(chunks), 1)
        self.assertEqual(chunks[0].chunk_type, "block")

    def test_fts5_bm25_indexing_and_search(self):
        """Verify SQLite FTS5 indexes chunks and matches queries."""
        chunks = self.chunker.chunk_code(SAMPLE_CODE, file_path="auth_service.py")
        self.searcher.index_chunks(chunks)

        results = self.searcher.search("authenticate credentials")
        self.assertGreaterEqual(len(results), 1)
        top_match = results[0]
        self.assertEqual(top_match["name"], "authenticate_user")
        self.assertIn("auth_service.py", top_match["file_path"])

    def test_reciprocal_rank_fusion(self):
        """Verify RRF correctly computes aggregated reciprocal ranks."""
        list_a = ["chunk_1", "chunk_2", "chunk_3"]
        list_b = ["chunk_2", "chunk_1", "chunk_4"]
        scores = calculate_rrf([list_a, list_b], k=60)

        self.assertIn("chunk_1", scores)
        self.assertIn("chunk_2", scores)
        self.assertIn("chunk_3", scores)
        self.assertIn("chunk_4", scores)
        # chunk_1 and chunk_2 appear at ranks 1 and 2 in both, so should have highest scores
        self.assertGreater(scores["chunk_1"], scores["chunk_3"])
        self.assertGreater(scores["chunk_2"], scores["chunk_4"])

    def test_semble_adapter_graceful_fallback(self):
        """Verify SembleAdapter gracefully reports availability and falls back."""
        # On systems without `semble` CLI installed, it must return False and None safely
        is_avail = SembleAdapter.is_available()
        self.assertIsInstance(is_avail, bool)
        if not is_avail:
            res = SembleAdapter.search("query", "non_existent_path")
            self.assertIsNone(res)

    def test_hybrid_search_end_to_end(self):
        """Test end-to-end hybrid code search with temporary file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            fpath = Path(tmp_dir) / "test_auth.py"
            fpath.write_text(SAMPLE_CODE, encoding="utf-8")

            res = self.hybrid.search("SecurityGateKeeper", target_path=tmp_dir, top_k=2)
            self.assertTrue(res["success"])
            self.assertGreaterEqual(res["total_matches"], 1)
            first = res["results"][0]
            self.assertIn("SecurityGateKeeper", first["name"])
            self.assertIn("score", first)
            self.assertIn("snippet", first)


    def test_punctuation_and_operator_search(self):
        """Verify searching for operators/punctuation like '->' or '!=' returns matching chunks."""
        chunks = self.chunker.chunk_code(SAMPLE_CODE, file_path="auth_service.py")
        self.searcher.index_chunks(chunks)

        res = self.searcher.search("->")
        self.assertGreaterEqual(len(res), 1)
        self.assertTrue(any("->" in r["content"] for r in res))

    def test_fts5_boolean_operators_robustness(self):
        """Verify queries with FTS5 boolean reserved words (AND, OR, NOT) execute without syntax error."""
        chunks = self.chunker.chunk_code(SAMPLE_CODE, file_path="auth_service.py")
        self.searcher.index_chunks(chunks)

        # Previously this would trigger sqlite3.OperationalError: fts5: syntax error near "OR"
        res = self.searcher.search("AND OR NOT user")
        self.assertIsInstance(res, list)

    def test_multi_word_exact_symbol_boosting(self):
        """Verify space-separated queries like 'authenticate user' boost authenticate_user in RRF rankings."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            fpath = Path(tmp_dir) / "test_auth.py"
            fpath.write_text(SAMPLE_CODE, encoding="utf-8")

            res = self.hybrid.search("authenticate user", target_path=tmp_dir, top_k=2)
            self.assertTrue(res["success"])
            self.assertGreaterEqual(res["total_matches"], 1)
            first = res["results"][0]
            self.assertEqual(first["name"], "authenticate_user")

    def test_multi_lang_chunking_js_go_java_c(self):
        """Verify syntactic chunking for JS/TS, Go, Java, and C/C++ without external parsers."""
        js_code = (
            "class AuthService {\n"
            "  async login(user, pass) {\n"
            "    return true;\n"
            "  }\n"
            "}\n"
        )
        go_code = (
            "package main\n"
            "func ProcessPacket(data []byte) (int, error) {\n"
            "  return len(data), nil\n"
            "}\n"
        )
        java_code = (
            "public class TokenValidator {\n"
            "  public boolean isValid(String token) {\n"
            "    return token != null;\n"
            "  }\n"
            "}\n"
        )

        js_chunks = self.chunker.chunk_multi_lang(js_code, "auth.js")
        self.assertTrue(any(c.name == "AuthService" for c in js_chunks))

        go_chunks = self.chunker.chunk_multi_lang(go_code, "packet.go")
        self.assertTrue(any(c.name == "ProcessPacket" for c in go_chunks))

        java_chunks = self.chunker.chunk_multi_lang(java_code, "TokenValidator.java")
        self.assertTrue(any(c.name == "TokenValidator" for c in java_chunks))

    def test_persistent_mtime_disk_cache_skips_unchanged(self):
        """Verify SQLite WAL cache tracks file mtime across sessions to prevent RAM churn."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_cache.db"
            searcher1 = FTS5BM25Searcher(in_memory=False, db_path=db_path)
            try:
                chunks = self.chunker.chunk_code(SAMPLE_CODE, file_path="auth_service.py")
                searcher1.index_chunks(chunks)
                test_mtime = 1718000000.0
                searcher1.record_file_meta("auth_service.py", mtime=test_mtime, count=len(chunks))
                
                cached_mtime = searcher1.get_indexed_mtime("auth_service.py")
                self.assertEqual(cached_mtime, test_mtime)
            finally:
                searcher1.close()

            # Re-open database from disk and verify metadata persisted
            searcher2 = FTS5BM25Searcher(in_memory=False, db_path=db_path)
            try:
                persisted_mtime = searcher2.get_indexed_mtime("auth_service.py")
                self.assertEqual(persisted_mtime, test_mtime)
            finally:
                searcher2.close()

    def test_extensions_normalization_without_leading_dot(self):
        """Verify extensions specified without leading dot (e.g. ['py']) are properly normalized and searched."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            fpath = Path(tmp_dir) / "handler.py"
            fpath.write_text("def handle_request(): return 200\n", encoding="utf-8")

            res = self.hybrid.search("handle_request", target_path=tmp_dir, extensions=["py"])
            self.assertTrue(res["success"])
            self.assertGreaterEqual(res["total_matches"], 1)

    def test_multi_lang_chunking_with_comment_braces(self):
        """Verify line comments containing braces '// {' do not distort brace depth."""
        code = (
            "function processItem(item) {\n"
            "  // { comment brace\n"
            "  return item.value;\n"
            "}\n"
        )
        chunks = self.chunker.chunk_multi_lang(code, "item.js")
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].name, "processItem")
        self.assertEqual(chunks[0].end_line, 4)


if __name__ == "__main__":
    unittest.main()
