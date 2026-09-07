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


PROGRAMMING_STOPWORDS = {
    "def", "class", "self", "return", "import", "from", "for", "if", "else", "elif",
    "in", "and", "or", "not", "as", "none", "true", "false", "try", "except", "finally",
    "with", "async", "await", "lambda", "yield", "pass", "raise", "while", "break", "continue",
}


def tokenize_identifier(identifier: str) -> List[str]:
    """Tokenize camelCase, PascalCase, and snake_case identifiers into semantic sub-words."""
    parts = identifier.split("_")
    tokens = []
    for part in parts:
        subparts = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z][a-z]|\b)", part)
        if subparts:
            tokens.extend(subparts)
        elif part:
            tokens.append(part)
    return [t.lower() for t in tokens if t]


def filter_stopwords(tokens: List[str]) -> List[str]:
    """Filter out common syntax stopwords from search tokens."""
    return [t for t in tokens if t.lower() not in PROGRAMMING_STOPWORDS]


class ASTCodeChunker:
    """Parses source code into syntactic AST chunks (classes and functions)."""

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Estimate token count (~4 chars per token)."""
        return max(1, len(text) // 4)

    def chunk_code(self, code_str: str, file_path: str = "<memory>") -> List[CodeChunk]:
        """Parse code into hierarchical syntactic function/class chunks."""
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

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_line = getattr(node, "lineno", 1)
                end_line = getattr(node, "end_lineno", start_line)
                snippet = "".join(lines[start_line - 1:end_line])
                doc = ast.get_docstring(node) or ""
                chunk_type = "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function"
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
            elif isinstance(node, ast.ClassDef):
                start_line = getattr(node, "lineno", 1)
                doc = ast.get_docstring(node) or ""
                first_method_line = None
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        first_method_line = getattr(item, "lineno", None)
                        break
                header_end = (first_method_line - 1) if first_method_line and first_method_line > start_line else getattr(node, "end_lineno", start_line)
                header_snippet = "".join(lines[start_line - 1:min(header_end, start_line + 5)])
                chunk_id = f"{Path(file_path).name}::{node.name}:{start_line}"
                chunks.append(CodeChunk(
                    chunk_id=chunk_id,
                    name=node.name,
                    chunk_type="class",
                    file_path=str(file_path),
                    start_line=start_line,
                    end_line=header_end,
                    content=header_snippet,
                    docstring=doc,
                    token_count_est=self.estimate_tokens(header_snippet),
                ))
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        m_start = getattr(item, "lineno", start_line)
                        m_end = getattr(item, "end_lineno", m_start)
                        m_snippet = "".join(lines[m_start - 1:m_end])
                        m_doc = ast.get_docstring(item) or ""
                        m_type = "async_function" if isinstance(item, ast.AsyncFunctionDef) else "function"
                        chunks.append(CodeChunk(
                            chunk_id=f"{Path(file_path).name}::{node.name}.{item.name}:{m_start}",
                            name=item.name,
                            chunk_type=m_type,
                            file_path=str(file_path),
                            start_line=m_start,
                            end_line=m_end,
                            content=m_snippet,
                            docstring=m_doc,
                            token_count_est=self.estimate_tokens(m_snippet),
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

    CLASS_PATTERNS = [
        re.compile(r"^\s*(?:export\s+|public\s+|private\s+|protected\s+|static\s+|abstract\s+)*(?:class|interface|struct|enum)\s+([A-Za-z0-9_]+)"),
        re.compile(r"^\s*type\s+([A-Za-z0-9_]+)\s+(?:struct|interface)\b"),
    ]
    FUNC_PATTERNS = [
        re.compile(r"^\s*func\s+(?:\([^)]+\)\s+)?([A-Za-z0-9_]+)\s*\("),
        re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\("),
        re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z0-9_]+)\s*=>"),
        re.compile(r"^\s*(?:export\s+|public\s+|private\s+|protected\s+|static\s+|async\s+|inline\s+|virtual\s+)*(?:[A-Za-z0-9_<>[\]*&:]+\s+)+([A-Za-z0-9_]+)\s*\([^;{}]*\)\s*\{?"),
    ]

    def chunk_multi_lang(self, code_str: str, file_path: str = "<memory>") -> List[CodeChunk]:
        """Syntactic chunking for JS/TS, Go, Java, C/C++ via brace and declaration tracking."""
        chunks: List[CodeChunk] = []
        lines = code_str.splitlines(keepends=True)
        n_lines = len(lines)
        i = 0

        while i < n_lines:
            line = lines[i]
            matched_name = None
            chunk_type = None

            for pat in self.CLASS_PATTERNS:
                m = pat.match(line)
                if m:
                    matched_name = m.group(1)
                    chunk_type = "class"
                    break

            if not matched_name:
                for pat in self.FUNC_PATTERNS:
                    m = pat.match(line)
                    if m:
                        matched_name = m.group(1)
                        chunk_type = "function"
                        break

            if matched_name:
                start_line = i + 1
                brace_depth = 0
                started = False
                end_line = start_line

                for j in range(i, n_lines):
                    curr_l = lines[j]
                    code_only = curr_l.split("//", 1)[0]
                    for ch in code_only:
                        if ch == "{":
                            brace_depth += 1
                            started = True
                        elif ch == "}":
                            brace_depth -= 1
                    if started and brace_depth <= 0:
                        end_line = j + 1
                        break
                else:
                    if started and brace_depth > 0:
                        end_line = n_lines

                snippet = "".join(lines[i:end_line])
                chunk_id = f"{Path(file_path).name}::{matched_name}:{start_line}"
                chunks.append(CodeChunk(
                    chunk_id=chunk_id,
                    name=matched_name,
                    chunk_type=chunk_type or "block",
                    file_path=str(file_path),
                    start_line=start_line,
                    end_line=end_line,
                    content=snippet,
                    docstring="",
                    token_count_est=self.estimate_tokens(snippet),
                ))
                i = max(i + 1, end_line)
            else:
                i += 1

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
                docstring="",
                token_count_est=self.estimate_tokens(content),
            ))

        return chunks

    def chunk_file(self, file_path: str | Path) -> List[CodeChunk]:
        """Read and chunk a single file, routing Python to AST and other languages to multi-lang tokenizer."""
        p = Path(file_path).resolve()
        if not p.is_file():
            return []
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            suffix = p.suffix.lower()
            if suffix == ".py":
                return self.chunk_code(content, file_path=str(p))
            elif suffix in (".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".c", ".cpp", ".h", ".hpp"):
                return self.chunk_multi_lang(content, file_path=str(p))
            else:
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
    """Zero-dependency SQLite FTS5 BM25 Lexical searcher for code chunks with persistent WAL cache."""

    def __init__(self, in_memory: bool = False, db_path: Optional[str | Path] = None):
        self.in_memory = in_memory
        self.db_path = ":memory:" if in_memory else str(db_path or ".cookiegli/ast_cache.db")
        if not in_memory:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        if not in_memory:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.fts5_supported = self._init_schema()

    def _init_schema(self) -> bool:
        """Create virtual table with FTS5 or fallback table, and file metadata table."""
        # File metadata table for mtime checking
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS file_index_meta (
                file_path TEXT PRIMARY KEY,
                mtime REAL NOT NULL,
                chunk_count INTEGER NOT NULL
            );
        """)
        self.conn.commit()

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

    def get_indexed_mtime(self, file_path: str) -> Optional[float]:
        """Get cached file modification time if indexed."""
        cursor = self.conn.execute(
            "SELECT mtime FROM file_index_meta WHERE file_path = ?",
            (file_path,),
        )
        row = cursor.fetchone()
        return float(row["mtime"]) if row else None

    def delete_file_chunks(self, file_path: str) -> None:
        """Delete old indexed chunks and metadata for a file."""
        self.conn.execute("DELETE FROM code_chunks_fts WHERE file_path = ?", (file_path,))
        self.conn.execute("DELETE FROM file_index_meta WHERE file_path = ?", (file_path,))
        self.conn.commit()

    def record_file_meta(self, file_path: str, mtime: float, count: Optional[int] = None, chunk_count: Optional[int] = None) -> None:
        """Record file metadata after indexing."""
        actual_count = count if count is not None else (chunk_count if chunk_count is not None else 0)
        self.conn.execute(
            "INSERT OR REPLACE INTO file_index_meta (file_path, mtime, chunk_count) VALUES (?, ?, ?)",
            (file_path, mtime, actual_count),
        )
        self.conn.commit()

    def clear(self) -> None:
        """Clear all indexed chunks and metadata."""
        self.conn.execute("DELETE FROM code_chunks_fts;")
        self.conn.execute("DELETE FROM file_index_meta;")
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
                tokens = clean_q.split()
                expanded = []
                for t in tokens:
                    expanded.append(t)
                    for sub in tokenize_identifier(t):
                        if sub not in expanded:
                            expanded.append(sub)
                filtered = filter_stopwords(expanded) or expanded
                fts_query = " OR ".join(f'"{t.replace(chr(34), "")}"' for t in filtered)
                cursor = self.conn.execute(
                    """
                    SELECT chunk_id, file_path, name, chunk_type, content, docstring,
                           start_line, end_line, token_count,
                           bm25(code_chunks_fts, 10.0, 1.0, 2.0) as score
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


DEFAULT_SEARCH_EXTENSIONS: Tuple[str, ...] = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".c", ".cpp", ".h", ".hpp"
)


class HybridCodeSearch:
    """
    Main Code Search Orchestrator.
    Combines AST syntactic chunking, SQLite FTS5 BM25 with WAL disk caching, and optional Semble ranking.
    """

    def __init__(self, in_memory: bool = False, db_path: Optional[str | Path] = None):
        self.chunker = ASTCodeChunker()
        self.searcher = FTS5BM25Searcher(in_memory=in_memory, db_path=db_path or ".cookiegli/ast_cache.db")
        self.semble = SembleAdapter()

    def index_directory(
        self,
        dir_path: str | Path,
        extensions: Optional[Tuple[str, ...]] = None,
    ) -> int:
        """Scan and index all matching source code files in directory using incremental mtime caching."""
        p = Path(dir_path).resolve()
        if not p.exists():
            return 0

        raw_exts = extensions or DEFAULT_SEARCH_EXTENSIONS
        target_exts = tuple(e if e.startswith(".") else f".{e}" for e in raw_exts)
        files_to_scan: List[Path] = []
        if p.is_file():
            files_to_scan.append(p)
        else:
            for ext in target_exts:
                files_to_scan.extend(p.rglob(f"*{ext}"))

        indexed_chunks = 0
        for f in files_to_scan:
            # Skip virtual environments, hidden directories, pycache, .cookiegli cache
            parts = {part.lower() for part in f.parts}
            if any(bad in parts for bad in {".venv", "venv", ".git", "__pycache__", "build", "dist", ".cookiegli", ".quarantine", "node_modules", ".tox"}):
                continue
            try:
                st_mtime = f.stat().st_mtime
            except Exception:
                continue

            file_str = str(f)
            cached_mtime = self.searcher.get_indexed_mtime(file_str)
            # Incremental cache: if file modification time has not changed, skip re-chunking (<10ms)
            if cached_mtime is not None and abs(cached_mtime - st_mtime) < 0.001:
                continue

            self.searcher.delete_file_chunks(file_str)
            chunks = self.chunker.chunk_file(f)
            if chunks:
                self.searcher.index_chunks(chunks)
            self.searcher.record_file_meta(file_str, st_mtime, len(chunks))
            indexed_chunks += len(chunks)

        return indexed_chunks

    def search(
        self,
        query: str,
        target_path: str | Path,
        top_k: int = 5,
        extensions: Optional[Tuple[str, ...]] = None,
        mode: str = "full",
    ) -> Dict[str, Any]:
        """
        Execute search returning concise AST chunks (< 100 tokens each).
        Supports mode='full' (default), mode='skeleton' (signatures), mode='compact' (cleaned).
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

        # 2. Pure-Python AST Chunking + SQLite FTS5 BM25 with incremental mtime cache
        self.index_directory(target, extensions=extensions)
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
            snippet = item["content"]

            if mode == "skeleton":
                # Skeleton mode: return signature line and docstring (~20 tokens)
                non_empty = [l for l in snippet.splitlines() if l.strip()]
                sig = non_empty[0] if non_empty else ""
                doc = f'    """{item["docstring"]}"""' if item.get("docstring") else ""
                snippet = f"{sig}\n{doc}".strip()
            elif mode == "compact":
                # Compact mode: strip comment lines and blank lines
                compact_lines = [l for l in snippet.splitlines() if l.strip() and not l.strip().startswith("#")]
                snippet = "\n".join(compact_lines[:20])
            else:
                # Ponytail / CookieGli token economy: truncate snippet to <= 25 lines if massive
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

    def close(self) -> None:
        """Close database connection."""
        self.searcher.close()
