from __future__ import annotations

import structlog

from app.models.enums import Language

logger = structlog.get_logger()


async def build_context(
    code: str,
    language: Language,
    file_path: str | None,
    store: object | None,
) -> str:
    """Query the knowledge graph and return a formatted context block for agents.

    Returns an empty string if the graph store is unavailable or file_path is None,
    ensuring graceful degradation when Graph RAG is disabled.
    """
    if store is None or file_path is None:
        return ""

    from app.graph_rag.store import GraphStore

    if not isinstance(store, GraphStore) or not store.is_connected:
        return ""

    try:
        from app.parsers.tree_sitter_parser import parse_code

        structure = parse_code(code, language)
        function_names = [f.name for f in structure.functions if f.name != "<anonymous>"]
        if not function_names:
            return ""

        ctx = await store.query_context(function_names, file_path)

        lines: list[str] = []

        if ctx.callers:
            lines.append("Called by:")
            for caller in ctx.callers:
                lines.append(f"  - {caller.name} ({caller.kind}) in {caller.file_path}")

        if ctx.callees:
            lines.append("Calls:")
            for callee in ctx.callees:
                lines.append(f"  - {callee.name}")

        if ctx.siblings:
            lines.append(f"Sibling functions in file: {', '.join(ctx.siblings)}")

        if ctx.imports:
            lines.append(f"Module imports: {', '.join(ctx.imports)}")

        if ctx.parent_class:
            lines.append(f"Defined in class: {ctx.parent_class}")

        return "\n".join(lines) if lines else ""

    except Exception as e:
        logger.warning("graph context query failed", file_path=file_path, error=str(e))
        return ""
