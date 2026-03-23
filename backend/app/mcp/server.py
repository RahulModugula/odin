"""Odin MCP server — exposes code review tools via Model Context Protocol.

Supports two transports:
  - stdio: for Claude Code / Cursor integration (via app.mcp.stdio_runner)
  - SSE:   mounted on FastAPI at /mcp for remote access
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import structlog
from mcp.server.fastmcp import FastMCP  # type: ignore[import-untyped]

from app.agents.graph import review_graph
from app.config import settings
from app.models.enums import Language
from app.parsers.languages import supported_languages

logger = structlog.get_logger()

mcp = FastMCP("odin", version="0.1.0")

_EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".go": Language.GO,
}


def _detect_language(file_path: str, hint: str = "python") -> Language:
    ext = Path(file_path).suffix.lower()
    if ext in _EXTENSION_MAP:
        return _EXTENSION_MAP[ext]
    try:
        return Language(hint)
    except ValueError:
        return Language.PYTHON


async def _run_review(
    code: str,
    language: Language,
    file_path: str | None = None,
) -> dict[str, Any]:
    initial_state = {
        "code": code,
        "language": language.value,
        "ast_summary": "",
        "metrics": None,
        "findings": [],
        "agent_outputs": [],
        "overall_score": 100,
        "summary": "",
        "codebase_context": "",
        "file_path": file_path,
    }
    result = await review_graph.ainvoke(initial_state)
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
) -> dict[str, Any]:
    """Run a full multi-agent code review on the provided source code.

    Returns an overall score (0-100), summary, and a list of findings with
    severity, category, title, description, and line numbers.

    Args:
        code: The source code to review.
        language: Programming language (python, javascript, typescript, go).
        filename: Optional filename for Graph RAG context enrichment.
    """
    lang = _detect_language(filename or "", hint=language)
    return await _run_review(code, lang, file_path=filename)


@mcp.tool()
async def analyze_file(file_path: str) -> dict[str, Any]:
    """Read a file from disk and run a full code review on it.

    Args:
        file_path: Absolute or relative path to the source file.
    """
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}
    if not path.is_file():
        return {"error": f"Not a file: {file_path}"}

    code = path.read_text(encoding="utf-8", errors="replace")
    lang = _detect_language(file_path)
    return await _run_review(code, lang, file_path=str(path.resolve()))


@mcp.tool()
async def get_findings(
    code: str,
    language: str = "python",
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """Run a code review and return findings, optionally filtered by severity.

    Args:
        code: The source code to review.
        language: Programming language.
        severity: Filter findings to this severity level (critical, high, medium, low, info).
    """
    lang = _detect_language("", hint=language)
    result = await _run_review(code, lang)
    findings = result["findings"]

    if severity:
        findings = [f for f in findings if f.get("severity") == severity.lower()]

    return findings


@mcp.tool()
async def query_codebase(
    query: str,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Query the Graph RAG knowledge graph for context about code patterns.

    Searches the indexed codebase for callers, dependencies, and related functions.

    Args:
        query: Name of a function or class to look up (e.g. "process_user_data").
        file_path: Optional file path to scope the search.
    """
    import app.graph_rag._store_ref as _store_ref

    if _store_ref.store is None or not _store_ref.store.is_connected:
        return {
            "error": "Knowledge graph not available. Index files via POST /api/index or enable ODIN_GRAPH_RAG_ENABLED."
        }

    ctx = await _store_ref.store.query_context(
        function_names=[query],
        file_path=file_path or "",
    )

    return {
        "queried": query,
        "callers": [c.model_dump() for c in ctx.callers],
        "callees": [c.model_dump() for c in ctx.callees],
        "siblings": ctx.siblings,
        "imports": ctx.imports,
        "parent_class": ctx.parent_class,
    }


@mcp.resource("odin://supported-languages")
def supported_languages_resource() -> str:
    """List of programming languages supported by Odin."""
    return ", ".join(supported_languages())
