from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()

_COLLECTION_NAME = "odin_code_chunks"


@dataclass
class CodeChunk:
    chunk_id: str
    file_path: str
    name: str
    kind: str
    code: str
    signature: str | None = None
    docstring: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def _make_chunk_id(file_path: str, name: str, line_start: int) -> str:
    raw = f"{file_path}:{name}:{line_start}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def extract_chunks_from_code(
    code: str,
    file_path: str,
    language: str,
) -> list[CodeChunk]:
    from app.graph_rag.extractor import extract_graph_entities
    from app.models.enums import Language

    try:
        lang = Language(language)
    except ValueError:
        return []

    nodes, _ = extract_graph_entities(code, lang, file_path)
    code_lines = code.splitlines()

    chunks: list[CodeChunk] = []
    for node in nodes:
        if node.kind not in ("function", "class"):
            continue
        if node.line_start is None or node.line_end is None:
            continue
        if node.name == "<anonymous>":
            continue

        ls = node.line_start
        le = node.line_end
        if ls > len(code_lines) or le > len(code_lines):
            continue

        body = "\n".join(code_lines[ls - 1 : le])
        chunk_id = _make_chunk_id(file_path, node.name, ls)

        embed_text = body
        if node.signature:
            embed_text = f"{node.signature}\n{body}"
        if node.docstring:
            embed_text = f"{node.docstring}\n{embed_text}"

        chunks.append(
            CodeChunk(
                chunk_id=chunk_id,
                file_path=file_path,
                name=node.name,
                kind=node.kind,
                code=body,
                signature=node.signature,
                docstring=node.docstring,
                line_start=ls,
                line_end=le,
            )
        )
    return chunks


class VectorStore:
    def __init__(self, persist_dir: str | None = None) -> None:
        self._client: Any = None
        self._collection: Any = None
        self._persist_dir = persist_dir
        self._embedding_fn: Any = None

    def initialize(self) -> bool:
        try:
            import chromadb

            if self._persist_dir:
                self._client = chromadb.PersistentClient(path=self._persist_dir)
            else:
                self._client = chromadb.Client()

            self._embedding_fn = chromadb.utils.embedding_functions.DefaultEmbeddingFunction()

            self._collection = self._client.get_or_create_collection(
                name=_COLLECTION_NAME,
                embedding_function=self._embedding_fn,
                metadata={"hnsw:space": "cosine"},
            )
            logger.info("vector store initialized")
            return True
        except Exception as e:
            logger.warning("vector store initialization failed", error=str(e))
            return False

    @property
    def is_initialized(self) -> bool:
        return self._collection is not None

    def index_chunks(self, chunks: list[CodeChunk]) -> None:
        if not self._collection or not chunks:
            return

        existing = self._collection.get(ids=[c.chunk_id for c in chunks])
        existing_ids = set(existing["ids"]) if existing else set()

        new_chunks = [c for c in chunks if c.chunk_id not in existing_ids]
        if not new_chunks:
            return

        ids = [c.chunk_id for c in new_chunks]
        documents = [c.code for c in new_chunks]
        metadatas = [
            {
                "file_path": c.file_path,
                "name": c.name,
                "kind": c.kind,
                "line_start": c.line_start or 0,
                "line_end": c.line_end or 0,
                "signature": c.signature or "",
                "docstring": c.docstring or "",
            }
            for c in new_chunks
        ]

        try:
            self._collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
            logger.debug("indexed chunks", count=len(new_chunks))
        except Exception as e:
            logger.warning("failed to index chunks", error=str(e))

    def index_file(self, code: str, file_path: str, language: str) -> None:
        chunks = extract_chunks_from_code(code, file_path, language)
        self.index_chunks(chunks)

    def search(
        self,
        query: str,
        top_k: int = 5,
        file_filter: str | None = None,
        kind_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self._collection:
            return []

        where_filter: dict[str, Any] | None = None
        conditions: list[dict[str, Any]] = []
        if file_filter:
            conditions.append({"file_path": file_filter})
        if kind_filter:
            conditions.append({"kind": kind_filter})
        if len(conditions) == 1:
            where_filter = conditions[0]
        elif len(conditions) > 1:
            where_filter = {"$and": conditions}

        try:
            kwargs: dict[str, Any] = {
                "query_texts": [query],
                "n_results": min(top_k, 20),
            }
            if where_filter:
                kwargs["where"] = where_filter

            results = self._collection.query(**kwargs)

            if not results or not results["ids"] or not results["ids"][0]:
                return []

            output: list[dict[str, Any]] = []
            ids = results["ids"][0]
            documents = results["documents"][0] if results["documents"] else [""] * len(ids)
            metadatas = results["metadatas"][0] if results["metadatas"] else [{}] * len(ids)
            distances = results["distances"][0] if results["distances"] else [0.0] * len(ids)

            for i, chunk_id in enumerate(ids):
                output.append(
                    {
                        "chunk_id": chunk_id,
                        "code": documents[i] if i < len(documents) else "",
                        "metadata": metadatas[i] if i < len(metadatas) else {},
                        "distance": distances[i] if i < len(distances) else 0.0,
                        "similarity": 1.0 - (distances[i] if i < len(distances) else 0.0),
                    }
                )
            return output
        except Exception as e:
            logger.warning("vector search failed", error=str(e))
            return []

    def delete_file(self, file_path: str) -> None:
        if not self._collection:
            return
        try:
            results = self._collection.get(where={"file_path": file_path})
            if results and results["ids"]:
                self._collection.delete(ids=results["ids"])
        except Exception as e:
            logger.warning("failed to delete file chunks", file_path=file_path, error=str(e))


_vector_store: VectorStore | None = None


def get_vector_store() -> VectorStore | None:
    return _vector_store


def init_vector_store(persist_dir: str | None = None) -> VectorStore | None:
    global _vector_store
    store = VectorStore(persist_dir=persist_dir)
    if store.initialize():
        _vector_store = store
        return store
    return None
