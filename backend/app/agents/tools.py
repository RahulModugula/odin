from __future__ import annotations

import structlog
from langchain_core.tools import tool

logger = structlog.get_logger()


@tool
async def search_codebase(query: str, top_k: int = 5) -> str:
    """Search the codebase for code semantically similar to the query.
    Returns matching code snippets with file locations."""
    from app.graph_rag.vector_store import get_vector_store

    store = get_vector_store()
    if store is None:
        return "Vector search unavailable — store not initialized."

    results = store.search(query, top_k=top_k)
    if not results:
        return f"No results found for '{query}'."

    lines = [f"Search results for '{query}':"]
    for i, r in enumerate(results, 1):
        meta = r.get("metadata", {})
        name = meta.get("name", "unknown")
        fp = meta.get("file_path", "unknown")
        ls = meta.get("line_start", "?")
        le = meta.get("line_end", "?")
        sim = r.get("similarity", 0.0)
        code = r.get("code", "")
        sig = meta.get("signature", "")
        lines.append(
            f"\n{i}. {name} in {fp}:{ls}-{le} (similarity: {sim:.2f})\n"
            f"   Signature: {sig}\n"
            f"```\n{code[:500]}\n```"
        )
    return "\n".join(lines)


@tool
async def get_callers(function_name: str, depth: int = 1) -> str:
    """Get functions that call the given function from the code knowledge graph."""
    import app.graph_rag._store_ref as _ref

    store = _ref.store
    if store is None or not store.is_connected:
        return "Graph store unavailable."

    callers = await store.get_callers(function_name, depth)
    if not callers:
        return f"No callers found for '{function_name}'."

    lines = [f"Callers of '{function_name}':"]
    for c in callers:
        sig = c.signature or c.name
        decs = f" ({', '.join(c.decorators)})" if c.decorators else ""
        loc = f" in {c.file_path}"
        if c.line_start and c.line_end:
            loc += f":{c.line_start}-{c.line_end}"
        lines.append(f"  - {sig}{decs}{loc}")
    return "\n".join(lines)


@tool
async def get_callees(function_name: str, depth: int = 1) -> str:
    """Get functions that the given function calls from the code knowledge graph."""
    import app.graph_rag._store_ref as _ref

    store = _ref.store
    if store is None or not store.is_connected:
        return "Graph store unavailable."

    callees = await store.get_callees(function_name, depth)
    if not callees:
        return f"No callees found for '{function_name}'."

    lines = [f"Callees of '{function_name}':"]
    for c in callees:
        sig = c.signature or c.name
        loc = f" in {c.file_path}"
        if c.line_start and c.line_end:
            loc += f":{c.line_start}-{c.line_end}"
        lines.append(f"  - {sig}{loc}")
    return "\n".join(lines)


@tool
async def get_type_info(symbol_name: str) -> str:
    """Get type information for a symbol from the code knowledge graph."""
    import app.graph_rag._store_ref as _ref

    store = _ref.store
    if store is None or not store.is_connected:
        return "Graph store unavailable."

    return f"Type info for '{symbol_name}': not yet available in graph (placeholder)."


@tool
async def read_symbol(file_path: str, name: str) -> str:
    """Read the full function/class body from the indexed codebase."""
    import app.graph_rag._store_ref as _ref

    store = _ref.store
    if store is None or not store.is_connected:
        return "Graph store unavailable."

    body = await store.get_symbol_body(file_path, name)
    if body is None:
        return f"Symbol '{name}' not found in '{file_path}'."

    return f"```python\n{body}\n```"


@tool
async def get_dataflow_paths(source: str, sink: str) -> str:
    """Check if there are cached taint/dataflow paths from source to sink."""
    import app.graph_rag._store_ref as _ref

    store = _ref.store
    if store is None or not store.is_connected:
        return "Graph store unavailable."

    paths = await store.get_dataflow_paths(source, sink)
    if not paths:
        return f"No cached dataflow paths from '{source}' to '{sink}'."

    lines = [f"Cached dataflow paths ({source} → {sink}):"]
    for p in paths:
        hops = f" via {', '.join(p.hops[:5])}" if p.hops else ""
        lines.append(
            f"  - [{p.source_kind}] {p.source_name} ({p.source_file}) → "
            f"[{p.sink_kind}] {p.sink_name} ({p.sink_file}){hops}"
        )
    return "\n".join(lines)


REVIEW_TOOLS = [
    search_codebase,
    get_callers,
    get_callees,
    get_type_info,
    read_symbol,
    get_dataflow_paths,
]
