from __future__ import annotations

import structlog

from app.models.enums import Language

logger = structlog.get_logger()


def _format_caller_with_sig(caller: object) -> str:
    from app.graph_rag.models import CallerInfo

    if not isinstance(caller, CallerInfo):
        return f"  - {caller}"
    parts = [f"  - {caller.name}"]
    if caller.signature:
        parts[0] = f"  - {caller.signature}"
    if caller.decorators:
        for dec in caller.decorators[:3]:
            parts.append(f"    {dec}")
    location = ""
    if caller.file_path:
        location = f"in {caller.file_path}"
    if caller.line_start is not None and caller.line_end is not None:
        location += f":{caller.line_start}-{caller.line_end}"
    if location:
        parts.append(f"    {location.strip()}")
    return "\n".join(parts)


def _format_callee_with_sig(callee: object) -> str:
    from app.graph_rag.models import CalleeInfo

    if not isinstance(callee, CalleeInfo):
        return f"  - {callee}"
    parts = [f"  - {callee.name}"]
    if callee.signature:
        parts[0] = f"  - {callee.signature}"
    location = ""
    if callee.file_path:
        location = f"in {callee.file_path}"
    if callee.line_start is not None and callee.line_end is not None:
        location += f":{callee.line_start}-{callee.line_end}"
    if location:
        parts.append(f"    {location.strip()}")
    return "\n".join(parts)


def _format_dataflow_path(path: object) -> str:
    from app.graph_rag.models import DataflowPath

    if not isinstance(path, DataflowPath):
        return ""
    line = f"  - {path.source_kind}:{path.source_name} → {path.sink_kind}:{path.sink_name}"
    if path.hops:
        line += f" (via {', '.join(path.hops[:5])})"
    return line


def _format_inheritance(info: object) -> str:
    from app.graph_rag.models import InheritanceInfo

    if not isinstance(info, InheritanceInfo):
        return ""
    line = f"  - {info.class_name} extends {info.parent_class}"
    return line


async def build_context(
    code: str,
    language: Language,
    file_path: str | None,
    store: object | None,
    cross_file_paths: list[str] | None = None,
) -> str:
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

        ctx = await store.query_context(function_names, file_path, cross_file_paths)

        lines: list[str] = []

        if ctx.callers:
            lines.append("Called by:")
            for caller in ctx.callers:
                lines.append(_format_caller_with_sig(caller))

        if ctx.callees:
            lines.append("Calls:")
            for callee in ctx.callees:
                lines.append(_format_callee_with_sig(callee))

        if ctx.siblings:
            lines.append(f"Sibling functions in file: {', '.join(ctx.siblings)}")

        if ctx.imports:
            lines.append(f"Module imports: {', '.join(ctx.imports)}")

        if ctx.parent_class:
            lines.append(f"Defined in class: {ctx.parent_class}")

        if ctx.inheritance:
            lines.append("Class hierarchy:")
            for inh in ctx.inheritance:
                lines.append(_format_inheritance(inh))

        if ctx.overridden_methods:
            lines.append(f"Overrides: {', '.join(ctx.overridden_methods)}")

        if ctx.decorators:
            lines.append(f"Decorators: {', '.join(ctx.decorators)}")

        if ctx.dataflow_paths:
            lines.append("Cached taint paths:")
            for dp in ctx.dataflow_paths:
                formatted = _format_dataflow_path(dp)
                if formatted:
                    lines.append(formatted)

        if ctx.cross_file_relations:
            lines.append("Cross-file relationships (PR context):")
            for rel in ctx.cross_file_relations:
                lines.append(f"  - {rel}")

        return "\n".join(lines) if lines else ""

    except Exception as e:
        logger.warning("graph context query failed", file_path=file_path, error=str(e))
        return ""


async def build_pr_context(
    files: dict[str, tuple[str, Language]],
    store: object | None,
) -> str:
    if store is None:
        return ""

    from app.graph_rag.store import GraphStore

    if not isinstance(store, GraphStore) or not store.is_connected:
        return ""

    all_paths = list(files.keys())
    sections: list[str] = []

    for file_path, (code, language) in files.items():
        ctx = await build_context(
            code,
            language,
            file_path,
            store,
            cross_file_paths=[p for p in all_paths if p != file_path],
        )
        if ctx:
            sections.append(f"### {file_path}\n{ctx}")

    return "\n\n".join(sections) if sections else ""
