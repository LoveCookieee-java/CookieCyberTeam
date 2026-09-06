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


if __name__ == "__main__":
    unittest.main()
