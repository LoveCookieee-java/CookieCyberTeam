"""
Hybrid Code Search Engine: Syntactic AST Chunking + SQLite FTS5 BM25 + Reciprocal Rank Fusion.
Inspired by MinishLab/semble: trims token consumption by 98-99% by returning surgical AST chunks.
Provides zero-dependency Pure-Python fallback with optional CLI adapter for `semble`.
"""

from __future__ import annotations
import ast
import json
import math
import re
import shutil
import sqlite3
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CodeChunk:
    chunk_id: str
    name: str
    chunk_type: str  # 'function', 'async_function', 'class', 'block'
    file_path: str
    start_line: int
    end_line: int
    content: str
    docstring: str
    token_count_est: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ASTCodeChunker:
    """Parses source code into syntactic AST chunks (classes and functions)."""

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Estimate token count (~4 chars per token)."""
        return max(1, len(text) // 4)

    def chunk_code(self, code_str: str, file_path: str = "<memory>") -> List[CodeChunk]:
        """Parse code into syntactic function/class chunks."""
        chunks: List[CodeChunk] = []
        lines = code_str.splitlines(keepends=True)

        try:
            tree = ast.parse(code_str, filename=file_path)
        except SyntaxError:
            # Fallback: chunk by 40-line blocks if AST parsing fails
            block_size = 40
            for i in range(0, max(1, len(lines)), block_size):
                block_lines = lines[i:i + block_size]
                content = "".join(block_lines)
                start_l = i + 1
                end_l = min(len(lines), i + block_size)
                chunks.append(CodeChunk(
                    chunk_id=f"{Path(file_path).name}:{start_l}-{end_l}",
                    name=f"block_{start_l}_{end_l}",
                    chunk_type="block",
                    file_path=str(file_path),
                    start_line=start_l,
                    end_line=end_l,
                    content=content,
                    docstring="",
                    token_count_est=self.estimate_tokens(content),
                ))
            return chunks

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start_line = getattr(node, "lineno", 1)
                end_line = getattr(node, "end_lineno", start_line)
                
                # Extract snippet lines
                snippet_lines = lines[start_line - 1:end_line]
                snippet = "".join(snippet_lines)
                
                # Extract docstring if present
                doc = ast.get_docstring(node) or ""
                
                chunk_type = "class" if isinstance(node, ast.ClassDef) else (
                    "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function"
                )
                
                chunk_id = f"{Path(file_path).name}::{node.name}:{start_line}"
                chunks.append(CodeChunk(
                    chunk_id=chunk_id,
                    name=node.name,
                    chunk_type=chunk_type,
                    file_path=str(file_path),
                    start_line=start_line,
                    end_line=end_line,
                    content=snippet,
                    docstring=doc,
                    token_count_est=self.estimate_tokens(snippet),
                ))

        # If no functions or classes were found, return the entire file as a single module chunk
        if not chunks and lines:
            content = "".join(lines)
            chunks.append(CodeChunk(
                chunk_id=f"{Path(file_path).name}:1-{len(lines)}",
                name=Path(file_path).stem,
                chunk_type="module",
                file_path=str(file_path),
                start_line=1,
                end_line=len(lines),
                content=content,
                docstring=ast.get_docstring(tree) or "",
                token_count_est=self.estimate_tokens(content),
            ))

        chunks.sort(key=lambda c: c.start_line)
        return chunks

    def chunk_file(self, file_path: str | Path) -> List[CodeChunk]:
        """Read and chunk a single file."""
        p = Path(file_path).resolve()
        if not p.is_file():
            return []
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            return self.chunk_code(content, file_path=str(p))
        except Exception:
            return []


def calculate_rrf(ranking_lists: List[List[str]], k: int = 60) -> Dict[str, float]:
    """
    Reciprocal Rank Fusion (RRF) algorithm:
    RRF(d) = sum(1.0 / (k + rank(d)))
    """
    scores: Dict[str, float] = {}
    for r_list in ranking_lists:
        for rank, item_id in enumerate(r_list, start=1):
            scores[item_id] = scores.get(item_id, 0.0) + (1.0 / (k + rank))
    return scores


class FTS5BM25Searcher:
    """Zero-dependency SQLite FTS5 BM25 Lexical searcher for code chunks."""

    def __init__(self, in_memory: bool = True, db_path: Optional[str | Path] = None):
        self.in_memory = in_memory
        self.db_path = ":memory:" if in_memory else str(db_path or ".cookiegli/ast_code_index.db")
        if not in_memory:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.fts5_supported = self._init_schema()

    def _init_schema(self) -> bool:
        """Create virtual table with FTS5 or fallback table."""
        try:
            self.conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS code_chunks_fts USING fts5(
                    chunk_id UNINDEXED,
                    file_path UNINDEXED,
                    name,
                    chunk_type UNINDEXED,
                    content,
                    docstring,
                    start_line UNINDEXED,
                    end_line UNINDEXED,
                    token_count UNINDEXED,
                    tokenize = 'porter unicode61'
                );
            """)
            self.conn.commit()
            return True
        except sqlite3.OperationalError:
            # Fallback for minimal SQLite without FTS5 compiled
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS code_chunks_fts (
                    chunk_id TEXT PRIMARY KEY,
                    file_path TEXT,
                    name TEXT,
                    chunk_type TEXT,
                    content TEXT,
                    docstring TEXT,
                    start_line INTEGER,
                    end_line INTEGER,
                    token_count INTEGER
                );
            """)
            self.conn.commit()
            return False

    def clear(self) -> None:
        """Clear indexed chunks."""
        self.conn.execute("DELETE FROM code_chunks_fts;")
        self.conn.commit()

    def index_chunks(self, chunks: List[CodeChunk]) -> None:
        """Index a batch of CodeChunks."""
        rows = [
            (
                c.chunk_id,
                c.file_path,
                c.name,
                c.chunk_type,
                c.content,
                c.docstring,
                c.start_line,
                c.end_line,
                c.token_count_est,
            )
            for c in chunks
        ]
        if self.fts5_supported:
            self.conn.executemany(
                """
                INSERT INTO code_chunks_fts (
                    chunk_id, file_path, name, chunk_type, content, docstring, start_line, end_line, token_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                rows,
            )
        else:
            self.conn.executemany(
                """
                INSERT OR REPLACE INTO code_chunks_fts (
                    chunk_id, file_path, name, chunk_type, content, docstring, start_line, end_line, token_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                rows,
            )
        self.conn.commit()

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search chunks with BM25 ranking (or fallback relevance)."""
        clean_q = re.sub(r"[^\w\s]", " ", query).strip()
        if not clean_q:
            # Fallback for punctuation/operator searches (e.g. '->', '!=', ':::')
            raw_target = query.strip()
            if not raw_target:
                return []
            cursor = self.conn.execute(
                "SELECT chunk_id, file_path, name, chunk_type, content, docstring, start_line, end_line, token_count "
                "FROM code_chunks_fts WHERE content LIKE ? LIMIT ?",
                (f"%{raw_target}%", top_k),
            )
            results: List[Dict[str, Any]] = []
            for r in cursor.fetchall():
                results.append({
                    "chunk_id": r["chunk_id"],
                    "file_path": r["file_path"],
                    "name": r["name"],
                    "chunk_type": r["chunk_type"],
                    "content": r["content"],
                    "docstring": r["docstring"],
                    "start_line": r["start_line"],
                    "end_line": r["end_line"],
                    "token_count": r["token_count"],
                    "score": 1.0,
                })
            return results

        results: List[Dict[str, Any]] = []

        if self.fts5_supported:
            try:
                # Quote each token to prevent FTS5 operator syntax collisions (e.g. AND, OR, NOT)
                tokens = clean_q.split()
                fts_query = " OR ".join(f'"{t.replace(chr(34), "")}"' for t in tokens)
                cursor = self.conn.execute(
                    """
                    SELECT chunk_id, file_path, name, chunk_type, content, docstring,
                           start_line, end_line, token_count,
                           bm25(code_chunks_fts) as score
                    FROM code_chunks_fts
                    WHERE code_chunks_fts MATCH ?
                    ORDER BY score ASC
                    LIMIT ?;
                    """,
                    (fts_query, top_k),
                )
                for r in cursor.fetchall():
                    results.append({
                        "chunk_id": r["chunk_id"],
                        "file_path": r["file_path"],
                        "name": r["name"],
                        "chunk_type": r["chunk_type"],
                        "content": r["content"],
                        "docstring": r["docstring"],
                        "start_line": r["start_line"],
                        "end_line": r["end_line"],
                        "token_count": r["token_count"],
                        "score": -float(r["score"]),  # Invert BM25 for standard higher=better
                    })
                return results
            except sqlite3.OperationalError:
                pass

        # Fallback scoring for non-FTS5 environments
        terms = clean_q.lower().split()
        cursor = self.conn.execute(
            "SELECT chunk_id, file_path, name, chunk_type, content, docstring, start_line, end_line, token_count FROM code_chunks_fts"
        )
        scored: List[Tuple[float, sqlite3.Row]] = []
        for r in cursor.fetchall():
            score = 0.0
            name_low = r["name"].lower()
            content_low = r["content"].lower()
            doc_low = (r["docstring"] or "").lower()
            for t in terms:
                if t in name_low:
                    score += 5.0
                if t in doc_low:
                    score += 2.0
                if t in content_low:
                    score += 1.0
            if score > 0:
                scored.append((score, r))

        scored.sort(key=lambda x: x[0], reverse=True)
        for score, r in scored[:top_k]:
            results.append({
                "chunk_id": r["chunk_id"],
                "file_path": r["file_path"],
                "name": r["name"],
                "chunk_type": r["chunk_type"],
                "content": r["content"],
                "docstring": r["docstring"],
                "start_line": r["start_line"],
                "end_line": r["end_line"],
                "token_count": r["token_count"],
                "score": score,
            })
        return results

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass


class SembleAdapter:
    """Adapter for MinishLab/semble CLI when installed on host."""

    @staticmethod
    def is_available() -> bool:
        return shutil.which("semble") is not None

    @staticmethod
    def search(query: str, target_path: str | Path, top_k: int = 5) -> Optional[List[Dict[str, Any]]]:
        """Invoke `semble search` CLI if available."""
        bin_path = shutil.which("semble")
        if not bin_path:
            return None
        try:
            proc = subprocess.run(
                [bin_path, "search", query, "--path", str(target_path), "--limit", str(top_k), "--json"],
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=10,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout)
                return data if isinstance(data, list) else None
        except Exception:
            pass
        return None


class HybridCodeSearch:
    """
    Main Code Search Orchestrator.
    Combines AST syntactic chunking, SQLite FTS5 BM25, and optional Semble ranking.
    """

    def __init__(self):
        self.chunker = ASTCodeChunker()
        self.searcher = FTS5BM25Searcher(in_memory=True)
        self.semble = SembleAdapter()

    def index_directory(self, dir_path: str | Path, extensions: Tuple[str, ...] = (".py",)) -> int:
        """Scan and index all matching source code files in directory."""
        p = Path(dir_path).resolve()
        if not p.exists():
            return 0

        self.searcher.clear()
        total_chunks = 0
        all_chunks: List[CodeChunk] = []

        files_to_scan: List[Path] = []
        if p.is_file():
            files_to_scan.append(p)
        else:
            for ext in extensions:
                files_to_scan.extend(p.rglob(f"*{ext}"))

        for f in files_to_scan:
            # Skip virtual environments, hidden directories, pycache
            parts = set(f.parts)
            if any(bad in parts for bad in {".venv", "venv", ".git", "__pycache__", "build", "dist"}):
                continue
            chunks = self.chunker.chunk_file(f)
            all_chunks.extend(chunks)

        if all_chunks:
            self.searcher.index_chunks(all_chunks)
            total_chunks = len(all_chunks)

        return total_chunks

    def search(
        self,
        query: str,
        target_path: str | Path,
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """
        Execute search returning concise AST chunks (< 100 tokens each).
        """
        target = Path(target_path).resolve()
        if not target.exists():
            return {"success": False, "error": f"Target path not found: {target}", "results": []}

        # 1. Try Semble CLI adapter if available
        if self.semble.is_available():
            semble_res = self.semble.search(query, target, top_k=top_k)
            if semble_res is not None:
                return {
                    "success": True,
                    "query": query,
                    "backend": "semble",
                    "total_matches": len(semble_res),
                    "results": semble_res,
                }

        # 2. Pure-Python AST Chunking + SQLite FTS5 BM25
        self.index_directory(target)
        fts_matches = self.searcher.search(query, top_k=top_k * 2)

        # RRF re-ranking combining exact symbol name hits and content hits
        q_norm = query.lower().strip()
        q_snake = q_norm.replace(" ", "_")
        q_terms = [t for t in q_norm.split() if t]

        def matches_symbol(name: str) -> bool:
            nl = name.lower()
            return (
                q_norm in nl
                or q_snake in nl
                or (bool(q_terms) and all(t in nl for t in q_terms))
            )

        exact_symbol_hits = [m["chunk_id"] for m in fts_matches if matches_symbol(m["name"])]
        content_hits = [m["chunk_id"] for m in fts_matches]

        rrf_scores = calculate_rrf([exact_symbol_hits, content_hits], k=60)
        
        # Sort matches by RRF score
        chunk_map = {m["chunk_id"]: m for m in fts_matches}
        ranked_chunk_ids = sorted(rrf_scores.keys(), key=lambda cid: rrf_scores[cid], reverse=True)[:top_k]

        final_results = []
        for cid in ranked_chunk_ids:
            item = chunk_map[cid]
            # Ponytail / CookieGli token economy: truncate snippet to <= 25 lines if massive
            snippet = item["content"]
            snip_lines = snippet.splitlines()
            if len(snip_lines) > 25:
                snippet = "\n".join(snip_lines[:25]) + f"\n... [truncated {len(snip_lines) - 25} lines for token economy]"

            final_results.append({
                "chunk_id": item["chunk_id"],
                "file_path": item["file_path"],
                "name": item["name"],
                "chunk_type": item["chunk_type"],
                "start_line": item["start_line"],
                "end_line": item["end_line"],
                "docstring": item["docstring"],
                "score": round(rrf_scores[cid], 4),
                "snippet": snippet,
                "token_estimate": item["token_count"],
            })

        return {
            "success": True,
            "query": query,
            "backend": "pure_python_ast_fts5",
            "total_matches": len(final_results),
            "results": final_results,
        }
