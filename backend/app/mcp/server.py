"""Odin MCP server — exposes code review tools via Model Context Protocol.

Supports two transports:
  - stdio: for Claude Code / Cursor integration (via app.mcp.stdio_runner)
  - SSE:   mounted on FastAPI at /mcp for remote access
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

import structlog
from mcp.server.fastmcp import Context, FastMCP

from app.agents.graph import review_graph
from app.models.enums import Language
from app.models.state import ReviewState
from app.parsers.languages import supported_languages

logger = structlog.get_logger()

mcp = FastMCP("odin")

_EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".go": Language.GO,
    ".rs": Language.RUST,
    ".java": Language.JAVA,
}


def _detect_language(file_path: str, hint: str = "python") -> Language:
    ext = Path(file_path).suffix.lower()
    if ext in _EXTENSION_MAP:
        return _EXTENSION_MAP[ext]
    try:
        return Language(hint)
    except ValueError:
        return Language.PYTHON


async def _report_progress_safe(
    ctx: Context[Any, Any] | None,
    progress: int,
    total: int,
    message: str,
) -> None:
    """Report progress via MCP Context, gracefully handling stdio transport errors.

    Args:
        ctx: FastMCP Context object (may be None for non-MCP callers)
        progress: Current progress value
        total: Total progress value
        message: Human-readable progress message
    """
    if ctx is None:
        return
    # Gracefully no-op on stdio transport or clients that don't support progress
    with contextlib.suppress(Exception):
        await ctx.report_progress(progress=progress, total=total, message=message)


async def _run_review(
    code: str,
    language: Language,
    file_path: str | None = None,
    ctx: Context[Any, Any] | None = None,
) -> dict[str, Any]:
    """Run a code review with optional progress reporting.

    Args:
        code: The source code to review
        language: Programming language
        file_path: Optional file path for context
        ctx: Optional FastMCP Context for progress reporting
    """
    initial_state: ReviewState = {
        "code": code,
        "language": language.value,
        "ast_summary": "",
        "metrics": None,  # type: ignore[typeddict-item]
        "findings": [],
        "agent_outputs": [],
        "overall_score": 100,
        "summary": "",
        "codebase_context": "",
        "file_path": file_path,
    }

    # Track progress through the review pipeline
    # Total stages: parse_code(1), enrich_context(2), agents(3-5), synthesize(6)
    total_stages = 6
    completed_stages = 0

    # Stream graph execution to report progress after each node
    result: dict[str, Any] = {}
    async for event in review_graph.astream_events(initial_state, version="v1"):
        event_type = event.get("event")
        if event_type == "on_chain_end":
            node_name = event.get("name", "")
            # Report progress after major pipeline nodes
            if node_name == "parse_code":
                completed_stages = 1
                await _report_progress_safe(
                    ctx, completed_stages, total_stages, "Odin reviewing… parsing complete"
                )
            elif node_name == "enrich_context":
                completed_stages = 2
                await _report_progress_safe(
                    ctx, completed_stages, total_stages, "Odin reviewing… context enriched"
                )
            elif node_name in ("quality_agent", "security_agent", "docs_agent"):
                # Track agent completion (3 agents in parallel)
                agent_count = completed_stages - 2  # Count of agents completed
                if agent_count < 3:
                    completed_stages += 1
                    await _report_progress_safe(
                        ctx,
                        completed_stages,
                        total_stages,
                        f"Odin reviewing… {agent_count}/3 agents complete",
                    )
            elif node_name == "synthesize":
                completed_stages = 6
                await _report_progress_safe(
                    ctx, completed_stages, total_stages, "Odin reviewing… synthesizing findings"
                )
                # Get the final result
                result = event["data"]["output"]

    # Fallback: if streaming didn't produce a result, use ainvoke
    if not result:
        result = await review_graph.ainvoke(initial_state)  # type: ignore[arg-type]

    return {
        "overall_score": result["overall_score"],
        "summary": result["summary"],
        "findings": [f.model_dump() for f in result["findings"]],
        "metrics": result["metrics"].model_dump() if result.get("metrics") else {},
    }


@mcp.tool()
async def review_code(
    code: str,
    language: str = "python",
    filename: str | None = None,
    ctx: Context[Any, Any] | None = None,
) -> dict[str, Any]:
    """Run a full multi-agent code review on the provided source code.

    Returns an overall score (0-100), summary, and a list of findings with
    severity, category, title, description, and line numbers.

    Args:
        code: The source code to review.
        language: Programming language (python, javascript, typescript, go).
        filename: Optional filename for Graph RAG context enrichment.
        ctx: FastMCP Context for progress reporting.
    """
    lang = _detect_language(filename or "", hint=language)
    return await _run_review(code, lang, file_path=filename, ctx=ctx)


@mcp.tool()
async def analyze_file(file_path: str, ctx: Context[Any, Any] | None = None) -> dict[str, Any]:
    """Read a file from disk and run a full code review on it.

    Args:
        file_path: Absolute or relative path to the source file.
        ctx: FastMCP Context for progress reporting.
    """
    import asyncio

    path = Path(file_path)
    exists = await asyncio.to_thread(path.exists)
    if not exists:
        return {"error": f"File not found: {file_path}"}
    is_file = await asyncio.to_thread(path.is_file)
    if not is_file:
        return {"error": f"Not a file: {file_path}"}

    code = await asyncio.to_thread(path.read_text, "utf-8", "replace")
    resolved = await asyncio.to_thread(path.resolve)
    lang = _detect_language(file_path)
    return await _run_review(code, lang, file_path=str(resolved), ctx=ctx)


@mcp.tool()
async def get_findings(
    code: str,
    language: str = "python",
    severity: str | None = None,
    ctx: Context[Any, Any] | None = None,
) -> list[dict[str, Any]]:
    """Run a code review and return findings, optionally filtered by severity.

    Args:
        code: The source code to review.
        language: Programming language.
        severity: Filter findings to this severity level (critical, high, medium, low, info).
        ctx: FastMCP Context for progress reporting.
    """
    lang = _detect_language("", hint=language)
    result = await _run_review(code, lang, ctx=ctx)
    findings: list[dict[str, Any]] = result["findings"]

    if severity:
        findings = [f for f in findings if f.get("severity") == severity.lower()]

    return findings


@mcp.tool()
async def query_codebase(
    query: str,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Query the code knowledge graph (or the file AST as fallback) for context.

    Searches for callers, dependencies, and related functions. Falls back to a
    single-file AST scan when the Graph RAG store is not indexed.

    Args:
        query: Name of a function or class to look up (e.g. "process_user_data").
        file_path: Optional file path. Required for AST fallback.
    """
    import asyncio

    import app.graph_rag._store_ref as _store_ref

    store = _store_ref.store
    if store is not None and store.is_connected:
        ctx = await store.query_context(
            function_names=[query],
            file_path=file_path or "",
        )
        return {
            "queried": query,
            "source": "graph_rag",
            "callers": [c.model_dump() for c in ctx.callers],
            "callees": [c.model_dump() for c in ctx.callees],
            "siblings": ctx.siblings,
            "imports": ctx.imports,
            "parent_class": ctx.parent_class,
        }

    if not file_path:
        return {
            "queried": query,
            "source": "none",
            "note": (
                "Graph RAG not indexed and no file_path provided. "
                "Pass file_path for a single-file AST fallback, or enable "
                "ODIN_GRAPH_RAG_ENABLED and index your codebase."
            ),
        }

    path = Path(file_path)
    exists = await asyncio.to_thread(path.exists)
    if not exists:
        return {"queried": query, "source": "none", "error": f"File not found: {file_path}"}

    code = await asyncio.to_thread(path.read_text, "utf-8", "replace")
    lang = _detect_language(file_path)

    try:
        from app.parsers.tree_sitter_parser import parse_code

        structure = parse_code(code, lang)
    except Exception as exc:
        return {"queried": query, "source": "none", "error": f"Parse failed: {exc}"}

    fn = next(
        (f for f in structure.functions if f.name == query),
        None,
    )
    cls = next(
        (c for c in structure.classes if c.name == query),
        None,
    )

    return {
        "queried": query,
        "source": "ast",
        "function": (
            {
                "name": fn.name,
                "line_start": fn.line_start,
                "line_end": fn.line_end,
                "has_docstring": fn.has_docstring,
            }
            if fn
            else None
        ),
        "class": (
            {
                "name": cls.name,
                "line_start": cls.line_start,
                "line_end": cls.line_end,
                "method_count": cls.method_count,
            }
            if cls
            else None
        ),
        "siblings": [f.name for f in structure.functions if f.name != query][:10],
        "imports": structure.imports[:20],
    }


@mcp.tool()
async def review_diff(
    files: dict[str, str],
    changed_lines: dict[str, list[list[int]]] | None = None,
    ctx: Context[Any, Any] | None = None,
) -> dict[str, Any]:
    """Review a set of changed files and return findings, prioritising diff-local issues.

    This is the preferred tool for reviewing a PR or a set of edits made by an AI
    agent — findings on unchanged lines are downgraded so reviewers focus on what
    actually changed.

    Args:
        files: Mapping of {file_path: full_file_contents_after_change}.
        changed_lines: Optional {file_path: [[start, end], ...]} describing which
            line ranges were modified. When provided, findings outside these
            ranges are marked as pre-existing.
        ctx: FastMCP Context for progress reporting.
    """
    if not files:
        return {"findings": [], "summary": "No files provided.", "files_reviewed": 0}

    all_findings: list[dict[str, Any]] = []
    per_file: dict[str, dict[str, Any]] = {}

    for file_path, code in files.items():
        lang = _detect_language(file_path)
        ranges = changed_lines.get(file_path) if changed_lines else None
        ranges_tuples = [(int(r[0]), int(r[1])) for r in ranges] if ranges else []

        initial_state: ReviewState = {
            "code": code,
            "language": lang.value,
            "ast_summary": "",
            "metrics": None,  # type: ignore[typeddict-item]
            "findings": [],
            "agent_outputs": [],
            "overall_score": 100,
            "summary": "",
            "codebase_context": "",
            "file_path": file_path,
        }
        if ranges_tuples:
            initial_state["changed_lines"] = ranges_tuples

        result: dict[str, Any] = await review_graph.ainvoke(initial_state)  # type: ignore[arg-type]
        findings_for_file = [f.model_dump() for f in result["findings"]]
        per_file[file_path] = {
            "score": result["overall_score"],
            "findings": findings_for_file,
        }
        for f in findings_for_file:
            f["file"] = file_path
            all_findings.append(f)

    return {
        "files_reviewed": len(files),
        "findings": all_findings,
        "per_file": per_file,
    }


@mcp.resource("odin://supported-languages")
def supported_languages_resource() -> str:
    """List of programming languages supported by Odin."""
    return ", ".join(supported_languages())
