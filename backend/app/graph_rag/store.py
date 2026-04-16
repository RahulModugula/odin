from __future__ import annotations

import contextlib
from typing import Any

import structlog

from app.graph_rag.extractor import extract_graph_entities
from app.graph_rag.models import (
    CalleeInfo,
    CallerInfo,
    CodebaseContext,
    DataflowPath,
    GraphEdge,
    GraphNode,
    InheritanceInfo,
)
from app.models.enums import Language

logger = structlog.get_logger()

_FILE_CONTENT_CACHE: dict[str, str] = {}


def cache_file_content(file_path: str, code: str) -> None:
    _FILE_CONTENT_CACHE[file_path] = code


def get_cached_content(file_path: str) -> str | None:
    return _FILE_CONTENT_CACHE.get(file_path)


class GraphStore:
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
        if self._driver is None:
            return
        async with self._driver.session() as session:
            await session.run("CREATE INDEX ON :CodeNode(id) IF NOT EXISTS")
            await session.run("CREATE INDEX ON :CodeNode(name) IF NOT EXISTS")
            await session.run("CREATE INDEX ON :CodeNode(kind) IF NOT EXISTS")
            await session.run("CREATE INDEX ON :CodeNode(file_path) IF NOT EXISTS")

    async def upsert_nodes(self, nodes: list[GraphNode]) -> None:
        if self._driver is None or not nodes:
            return
        async with self._driver.session() as session:
            for node in nodes:
                props = {
                    "id": node.id,
                    "name": node.name,
                    "kind": node.kind,
                    "file_path": node.file_path,
                    "language": node.language,
                    "line_start": node.line_start,
                    "line_end": node.line_end,
                    "signature": node.signature,
                    "return_type": node.return_type,
                    "docstring": node.docstring,
                    "parent_class_name": node.parent_class_name,
                    "source_hash": node.source_hash,
                }
                await session.run(
                    """
                    MERGE (n:CodeNode {id: $id})
                    SET n.name = $name,
                        n.kind = $kind,
                        n.file_path = $file_path,
                        n.language = $language,
                        n.line_start = $line_start,
                        n.line_end = $line_end,
                        n.signature = $signature,
                        n.return_type = $return_type,
                        n.docstring = $docstring,
                        n.parent_class_name = $parent_class_name,
                        n.source_hash = $source_hash
                    """,
                    **props,
                )
                if node.decorators:
                    await session.run(
                        """
                        MATCH (n:CodeNode {id: $id})
                        SET n.decorators = $decorators
                        """,
                        id=node.id,
                        decorators=node.decorators,
                    )
                if node.param_types:
                    await session.run(
                        """
                        MATCH (n:CodeNode {id: $id})
                        SET n.param_types = $param_types
                        """,
                        id=node.id,
                        param_types=node.param_types,
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
                    SET r.weight = $weight
                    """,
                    source_id=edge.source_id,
                    target_id=edge.target_id,
                    rel=edge.relationship,
                    weight=edge.weight,
                )

    async def index_file(self, code: str, language: Language, file_path: str) -> None:
        nodes, edges = extract_graph_entities(code, language, file_path)
        await self.upsert_nodes(nodes)
        await self.upsert_edges(edges)
        cache_file_content(file_path, code)
        logger.info("indexed file", file_path=file_path, nodes=len(nodes), edges=len(edges))

    async def store_dataflow_edge(
        self,
        source_name: str,
        sink_name: str,
        source_file: str,
        sink_file: str,
        source_kind: str,
        sink_kind: str,
        hops: list[str] | None = None,
    ) -> None:
        if self._driver is None:
            return
        source_id = f"dataflow_src:{source_name}:{source_file}"
        sink_id = f"dataflow_snk:{sink_name}:{sink_file}"
        async with self._driver.session() as session:
            await session.run(
                """
                MERGE (a:CodeNode {id: $source_id})
                SET a.name = $source_name, a.kind = 'dataflow_source', a.file_path = $source_file
                """,
                source_id=source_id,
                source_name=source_name,
                source_file=source_file,
            )
            await session.run(
                """
                MERGE (b:CodeNode {id: $sink_id})
                SET b.name = $sink_name, b.kind = 'dataflow_sink', b.file_path = $sink_file
                """,
                sink_id=sink_id,
                sink_name=sink_name,
                sink_file=sink_file,
            )
            await session.run(
                """
                MATCH (a:CodeNode {id: $source_id})
                MATCH (b:CodeNode {id: $sink_id})
                MERGE (a)-[r:RELATES {type: 'DATAFLOWS_TO'}]->(b)
                SET r.source_kind = $source_kind, r.sink_kind = $sink_kind,
                    r.hops = $hops
                """,
                source_id=source_id,
                sink_id=sink_id,
                source_kind=source_kind,
                sink_kind=sink_kind,
                hops=hops or [],
            )

    async def query_context(
        self,
        function_names: list[str],
        file_path: str,
        cross_file_paths: list[str] | None = None,
    ) -> CodebaseContext:
        if self._driver is None or not function_names:
            return CodebaseContext(queried_names=function_names)

        callers: list[CallerInfo] = []
        callees: list[CalleeInfo] = []
        siblings: list[str] = []
        imports: list[str] = []
        parent_class: str | None = None
        inheritance: list[InheritanceInfo] = []
        decorators: list[str] = []
        dataflow_paths: list[DataflowPath] = []
        overridden_methods: list[str] = []
        cross_file_relations: list[str] = []

        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (caller:CodeNode)-[r:RELATES {type: 'CALLS'}]->(callee:CodeNode)
                WHERE callee.name IN $names
                RETURN caller.name AS name, caller.file_path AS file_path,
                       caller.kind AS kind, caller.signature AS signature,
                       caller.decorators AS decorators,
                       caller.line_start AS line_start, caller.line_end AS line_end
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
                        signature=record.get("signature"),
                        decorators=record.get("decorators", []),
                        line_start=record.get("line_start"),
                        line_end=record.get("line_end"),
                    )
                )

            result = await session.run(
                """
                MATCH (caller:CodeNode)-[r:RELATES {type: 'CALLS'}]->(callee:CodeNode)
                WHERE caller.name IN $names
                RETURN callee.name AS name, callee.file_path AS file_path,
                       callee.signature AS signature,
                       callee.line_start AS line_start, callee.line_end AS line_end
                LIMIT 10
                """,
                names=function_names,
            )
            async for record in result:
                callees.append(
                    CalleeInfo(
                        name=record["name"],
                        file_path=record["file_path"],
                        signature=record.get("signature"),
                        line_start=record.get("line_start"),
                        line_end=record.get("line_end"),
                    )
                )

            result = await session.run(
                """
                MATCH (m:CodeNode {file_path: $file_path, kind: 'module'})-[r:RELATES {type: 'CONTAINS'}]->(f:CodeNode)
                WHERE f.kind = 'function' AND NOT f.name IN $names
                RETURN f.name AS name
                LIMIT 10
                """,
                file_path=file_path,
                names=function_names,
            )
            async for record in result:
                siblings.append(record["name"])

            result = await session.run(
                """
                MATCH (m:CodeNode {file_path: $file_path, kind: 'module'})-[r:RELATES {type: 'IMPORTS'}]->(dep:CodeNode)
                RETURN dep.name AS name
                LIMIT 10
                """,
                file_path=file_path,
            )
            async for record in result:
                imports.append(record["name"])

            result = await session.run(
                """
                MATCH (c:CodeNode {file_path: $file_path, kind: 'class'})-[r:RELATES {type: 'CONTAINS'}]->(f:CodeNode)
                WHERE f.name IN $names
                RETURN c.name AS name, c.decorators AS decorators
                LIMIT 1
                """,
                file_path=file_path,
                names=function_names,
            )
            record = await result.single()
            if record:
                parent_class = record["name"]
                decs = record.get("decorators")
                if decs:
                    decorators.extend(decs)

            result = await session.run(
                """
                MATCH (child:CodeNode {file_path: $file_path, kind: 'class'})-[r:RELATES {type: 'INHERITS'}]->(parent:CodeNode)
                RETURN child.name AS class_name, parent.name AS parent_class,
                       child.file_path AS file_path
                """,
                file_path=file_path,
            )
            async for record in result:
                parent_name = record["parent_class"]
                cls_name = record["class_name"]
                inheritance.append(
                    InheritanceInfo(
                        class_name=cls_name,
                        parent_class=parent_name,
                        file_path=record["file_path"],
                    )
                )

                ovr_result = await session.run(
                    """
                    MATCH (m:CodeNode)-[r:RELATES {type: 'OVERRIDES'}]->(pm:CodeNode)
                    WHERE r.class = $cls_name AND r.parent_class = $parent_name
                    RETURN m.name AS method_name
                    """,
                    cls_name=cls_name,
                    parent_name=parent_name,
                )
                async for ovr_record in ovr_result:
                    overridden_methods.append(ovr_record["method_name"])

            result = await session.run(
                """
                MATCH (src:CodeNode)-[r:RELATES {type: 'DATAFLOWS_TO'}]->(snk:CodeNode)
                WHERE src.file_path = $file_path
                RETURN src.name AS source_name, snk.name AS sink_name,
                       src.file_path AS source_file, snk.file_path AS sink_file,
                       r.source_kind AS source_kind, r.sink_kind AS sink_kind,
                       r.hops AS hops
                """,
                file_path=file_path,
            )
            async for record in result:
                dataflow_paths.append(
                    DataflowPath(
                        source_name=record["source_name"],
                        sink_name=record["sink_name"],
                        source_file=record["source_file"],
                        sink_file=record["sink_file"],
                        source_kind=record.get("source_kind", ""),
                        sink_kind=record.get("sink_kind", ""),
                        hops=record.get("hops", []),
                    )
                )

            result = await session.run(
                """
                MATCH (f:CodeNode)-[r:RELATES {type: 'HAS_DECORATOR'}]->(d:CodeNode)
                WHERE f.name IN $names AND f.file_path = $file_path
                RETURN d.name AS decorator_name, r.decorator_text AS decorator_text
                """,
                names=function_names,
                file_path=file_path,
            )
            async for record in result:
                dec_text = record.get("decorator_text") or record.get("decorator_name", "")
                if dec_text:
                    decorators.append(dec_text)

            if cross_file_paths:
                result = await session.run(
                    """
                    MATCH (f1:CodeNode)-[r:RELATES {type: 'CALLS'}]->(f2:CodeNode)
                    WHERE f1.name IN $names AND f2.file_path IN $cross_files
                    RETURN f1.name AS caller, f2.name AS callee,
                           f2.file_path AS callee_file, f2.signature AS callee_sig
                    """,
                    names=function_names,
                    cross_files=cross_file_paths,
                )
                async for record in result:
                    sig = record.get("callee_sig") or ""
                    callee_file = record.get("callee_file", "")
                    cross_file_relations.append(
                        f"{record['caller']} → {record['callee']}({sig}) in {callee_file}"
                    )

        return CodebaseContext(
            queried_names=function_names,
            callers=callers,
            callees=callees,
            siblings=siblings,
            imports=imports,
            parent_class=parent_class,
            inheritance=inheritance,
            decorators=decorators,
            dataflow_paths=dataflow_paths,
            overridden_methods=overridden_methods,
            cross_file_relations=cross_file_relations,
        )

    async def get_callers(self, function_name: str, depth: int = 1) -> list[CallerInfo]:
        if self._driver is None:
            return []
        callers: list[CallerInfo] = []
        async with self._driver.session() as session:
            query = (
                "MATCH (caller:CodeNode)-[r:RELATES {type: 'CALLS'}]->(callee:CodeNode {name: $name}) "
                "RETURN caller.name AS name, caller.file_path AS file_path, "
                "caller.kind AS kind, caller.signature AS signature, "
                "caller.line_start AS line_start, caller.line_end AS line_end "
                "LIMIT 10"
            )
            result = await session.run(query, name=function_name)
            async for record in result:
                callers.append(
                    CallerInfo(
                        name=record["name"],
                        file_path=record["file_path"],
                        kind=record["kind"],
                        signature=record.get("signature"),
                        line_start=record.get("line_start"),
                        line_end=record.get("line_end"),
                    )
                )
        return callers

    async def get_callees(self, function_name: str, depth: int = 1) -> list[CalleeInfo]:
        if self._driver is None:
            return []
        callees: list[CalleeInfo] = []
        async with self._driver.session() as session:
            query = (
                "MATCH (caller:CodeNode {name: $name})-[r:RELATES {type: 'CALLS'}]->(callee:CodeNode) "
                "RETURN callee.name AS name, callee.file_path AS file_path, "
                "callee.signature AS signature, "
                "callee.line_start AS line_start, callee.line_end AS line_end "
                "LIMIT 10"
            )
            result = await session.run(query, name=function_name)
            async for record in result:
                callees.append(
                    CalleeInfo(
                        name=record["name"],
                        file_path=record["file_path"],
                        signature=record.get("signature"),
                        line_start=record.get("line_start"),
                        line_end=record.get("line_end"),
                    )
                )
        return callees

    async def get_symbol_body(self, file_path: str, name: str) -> str | None:
        cached = get_cached_content(file_path)
        if cached is None:
            return None
        lines = cached.splitlines()

        if self._driver is None:
            return None
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (n:CodeNode {name: $name, file_path: $file_path})
                WHERE n.kind IN ['function', 'class']
                RETURN n.line_start AS ls, n.line_end AS le
                LIMIT 1
                """,
                name=name,
                file_path=file_path,
            )
            record = await result.single()
            if record and record["ls"] and record["le"]:
                ls = record["ls"]
                le = record["le"]
                if ls <= len(lines) and le <= len(lines):
                    return "\n".join(lines[ls - 1 : le])
        return None

    async def get_dataflow_paths(self, source: str, sink: str) -> list[DataflowPath]:
        if self._driver is None:
            return []
        paths: list[DataflowPath] = []
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (src:CodeNode)-[r:RELATES {type: 'DATAFLOWS_TO'}]->(snk:CodeNode)
                WHERE src.name CONTAINS $source AND snk.name CONTAINS $sink
                RETURN src.name AS source_name, snk.name AS sink_name,
                       src.file_path AS source_file, snk.file_path AS sink_file,
                       r.source_kind AS source_kind, r.sink_kind AS sink_kind,
                       r.hops AS hops
                """,
                source=source,
                sink=sink,
            )
            async for record in result:
                paths.append(
                    DataflowPath(
                        source_name=record["source_name"],
                        sink_name=record["sink_name"],
                        source_file=record["source_file"],
                        sink_file=record["sink_file"],
                        source_kind=record.get("source_kind", ""),
                        sink_kind=record.get("sink_kind", ""),
                        hops=record.get("hops", []),
                    )
                )
        return paths
