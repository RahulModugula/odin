from __future__ import annotations

import contextlib
from typing import Any

import structlog

from app.graph_rag.extractor import extract_graph_entities
from app.graph_rag.models import CodebaseContext, GraphEdge, GraphNode
from app.models.enums import Language

logger = structlog.get_logger()


class GraphStore:
    """Async Memgraph client using the Neo4j Bolt protocol driver."""

    def __init__(self, uri: str, auth: tuple[str, str] | None = None) -> None:
        self._uri = uri
        self._auth = auth
        self._driver: Any = None

    async def connect(self) -> None:
        try:
            from neo4j import AsyncGraphDatabase

            self._driver = AsyncGraphDatabase.driver(
                self._uri,
                auth=self._auth,
            )
            await self._ensure_indexes()
            logger.info("graph store connected", uri=self._uri)
        except Exception as e:
            logger.warning("graph store connection failed", uri=self._uri, error=str(e))
            self._driver = None

    async def close(self) -> None:
        if self._driver is not None:
            with contextlib.suppress(Exception):
                await self._driver.close()
            self._driver = None

    @property
    def is_connected(self) -> bool:
        return self._driver is not None

    async def _ensure_indexes(self) -> None:
        """Create indexes for fast node lookups."""
        if self._driver is None:
            return
        async with self._driver.session() as session:
            await session.run("CREATE INDEX ON :CodeNode(id) IF NOT EXISTS")
            await session.run("CREATE INDEX ON :CodeNode(name) IF NOT EXISTS")

    async def upsert_nodes(self, nodes: list[GraphNode]) -> None:
        if self._driver is None or not nodes:
            return
        async with self._driver.session() as session:
            for node in nodes:
                await session.run(
                    """
                    MERGE (n:CodeNode {id: $id})
                    SET n.name = $name,
                        n.kind = $kind,
                        n.file_path = $file_path,
                        n.language = $language,
                        n.line_start = $line_start,
                        n.line_end = $line_end
                    """,
                    id=node.id,
                    name=node.name,
                    kind=node.kind,
                    file_path=node.file_path,
                    language=node.language,
                    line_start=node.line_start,
                    line_end=node.line_end,
                )

    async def upsert_edges(self, edges: list[GraphEdge]) -> None:
        if self._driver is None or not edges:
            return
        async with self._driver.session() as session:
            for edge in edges:
                await session.run(
                    """
                    MATCH (a:CodeNode {id: $source_id})
                    MATCH (b:CodeNode {id: $target_id})
                    MERGE (a)-[r:RELATES {type: $rel}]->(b)
                    """,
                    source_id=edge.source_id,
                    target_id=edge.target_id,
                    rel=edge.relationship,
                )

    async def index_file(self, code: str, language: Language, file_path: str) -> None:
        """Extract entities from code and persist them to the graph."""
        nodes, edges = extract_graph_entities(code, language, file_path)
        await self.upsert_nodes(nodes)
        await self.upsert_edges(edges)
        logger.info("indexed file", file_path=file_path, nodes=len(nodes), edges=len(edges))

    async def query_context(
        self,
        function_names: list[str],
        file_path: str,
    ) -> CodebaseContext:
        """Query the graph for context around the given function names."""
        if self._driver is None or not function_names:
            return CodebaseContext(queried_names=function_names)

        from app.graph_rag.models import CalleeInfo, CallerInfo

        callers: list[CallerInfo] = []
        callees: list[CalleeInfo] = []
        siblings: list[str] = []
        imports: list[str] = []
        parent_class: str | None = None

        async with self._driver.session() as session:
            # Find what calls these functions
            result = await session.run(
                """
                MATCH (caller:CodeNode)-[r:RELATES {type: 'CALLS'}]->(callee:CodeNode)
                WHERE callee.name IN $names
                RETURN caller.name AS name, caller.file_path AS file_path, caller.kind AS kind
                LIMIT 10
                """,
                names=function_names,
            )
            async for record in result:
                callers.append(
                    CallerInfo(
                        name=record["name"],
                        file_path=record["file_path"],
                        kind=record["kind"],
                    )
                )

            # Find what these functions call
            result = await session.run(
                """
                MATCH (caller:CodeNode)-[r:RELATES {type: 'CALLS'}]->(callee:CodeNode)
                WHERE caller.name IN $names
                RETURN callee.name AS name, callee.file_path AS file_path
                LIMIT 10
                """,
                names=function_names,
            )
            async for record in result:
                callees.append(
                    CalleeInfo(
                        name=record["name"],
                        file_path=record["file_path"],
                    )
                )

            # Find sibling functions in the same file
            result = await session.run(
                """
                MATCH (m:CodeNode {file_path: $file_path, kind: 'module'})-[r:RELATES {type: 'CONTAINS'}]->(f:CodeNode)                WHERE f.kind = 'function' AND NOT f.name IN $names
                RETURN f.name AS name
                LIMIT 10
                """,
                file_path=file_path,
                names=function_names,
            )
            async for record in result:
                siblings.append(record["name"])

            # Find imports of the file's module
            result = await session.run(
                """
                MATCH (m:CodeNode {file_path: $file_path, kind: 'module'})-[r:RELATES {type: 'IMPORTS'}]->(dep:CodeNode)                RETURN dep.name AS name
                LIMIT 10
                """,
                file_path=file_path,
            )
            async for record in result:
                imports.append(record["name"])

            # Find parent class if function is a method
            result = await session.run(
                """
                MATCH (c:CodeNode {file_path: $file_path, kind: 'class'})-[r:RELATES {type: 'CONTAINS'}]->(f:CodeNode)                WHERE f.name IN $names
                RETURN c.name AS name
                LIMIT 1
                """,
                file_path=file_path,
                names=function_names,
            )
            record = await result.single()
            if record:
                parent_class = record["name"]

        return CodebaseContext(
            queried_names=function_names,
            callers=callers,
            callees=callees,
            siblings=siblings,
            imports=imports,
            parent_class=parent_class,
        )
