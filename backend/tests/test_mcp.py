from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_review_code_tool_returns_dict():
    mock_result = {
        "overall_score": 85,
        "summary": "Code looks good.",
        "findings": [],
        "metrics": {
            "lines_of_code": 10,
            "num_functions": 1,
            "num_classes": 0,
            "avg_function_length": 5.0,
            "max_function_length": 5,
            "max_nesting_depth": 1,
            "cyclomatic_complexity": 1,
            "comment_ratio": 0.0,
            "import_count": 0,
        },
    }

    with patch("app.mcp.server._run_review", new=AsyncMock(return_value=mock_result)):
        from app.mcp.server import review_code

        result = await review_code("def foo(): pass", language="python")

    assert result["overall_score"] == 85
    assert "findings" in result


@pytest.mark.asyncio
async def test_analyze_file_missing_returns_error(tmp_path):
    from app.mcp.server import analyze_file

    result = await analyze_file(str(tmp_path / "nonexistent.py"))

    assert "error" in result
    assert "not found" in result["error"].lower()


@pytest.mark.asyncio
async def test_analyze_file_reads_and_reviews(tmp_path):
    code = "def hello(): pass\n"
    f = tmp_path / "hello.py"
    f.write_text(code)

    mock_result = {
        "overall_score": 90,
        "summary": "Clean.",
        "findings": [],
        "metrics": {},
    }

    with patch("app.mcp.server._run_review", new=AsyncMock(return_value=mock_result)):
        from app.mcp.server import analyze_file

        result = await analyze_file(str(f))

    assert result["overall_score"] == 90


@pytest.mark.asyncio
async def test_get_findings_filters_by_severity():
    findings = [
        {"severity": "critical", "title": "SQL injection"},
        {"severity": "low", "title": "Missing docstring"},
    ]
    mock_result = {
        "overall_score": 50,
        "summary": "Issues found.",
        "findings": findings,
        "metrics": {},
    }

    with patch("app.mcp.server._run_review", new=AsyncMock(return_value=mock_result)):
        from app.mcp.server import get_findings

        result = await get_findings("x = 1", severity="critical")

    assert len(result) == 1
    assert result[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_query_codebase_no_store_no_file_returns_note():
    with patch("app.graph_rag._store_ref.store", None):
        from app.mcp.server import query_codebase

        result = await query_codebase("process_data")

    assert result["source"] == "none"
    assert "note" in result


@pytest.mark.asyncio
async def test_query_codebase_no_store_ast_fallback(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text("def target():\n    pass\n\ndef other():\n    pass\n")

    with patch("app.graph_rag._store_ref.store", None):
        from app.mcp.server import query_codebase

        result = await query_codebase("target", file_path=str(f))

    assert result["source"] == "ast"
    assert result["function"]["name"] == "target"
    assert "other" in result["siblings"]


@pytest.mark.asyncio
async def test_review_diff_reviews_multiple_files():
    async def fake_ainvoke(state):
        from app.models.schemas import CodeMetrics

        return {
            "overall_score": 95,
            "findings": [],
            "summary": "OK.",
            "metrics": CodeMetrics(
                lines_of_code=1,
                num_functions=0,
                num_classes=0,
                avg_function_length=0,
                max_function_length=0,
                max_nesting_depth=0,
                cyclomatic_complexity=0,
                comment_ratio=0.0,
                import_count=0,
            ),
            "agent_outputs": [],
        }

    with patch("app.mcp.server.review_graph.ainvoke", new=AsyncMock(side_effect=fake_ainvoke)):
        from app.mcp.server import review_diff

        result = await review_diff(
            files={"a.py": "print(1)", "b.py": "print(2)"},
            changed_lines={"a.py": [[1, 1]]},
        )

    assert result["files_reviewed"] == 2
    assert "a.py" in result["per_file"]
    assert "b.py" in result["per_file"]


@pytest.mark.asyncio
async def test_progress_callback_invoked_per_node():
    """Verify that progress callback is invoked once per pipeline node with correct messages."""
    from unittest.mock import MagicMock

    from app.mcp.server import _run_review
    from app.models.enums import Language

    # Create a mock Context that tracks report_progress calls
    mock_ctx = MagicMock()
    mock_ctx.report_progress = AsyncMock()

    # Mock the review graph to return a valid result
    async def fake_ainvoke(state):
        from app.models.schemas import CodeMetrics

        return {
            "overall_score": 85,
            "summary": "Test review.",
            "findings": [],
            "metrics": CodeMetrics(
                lines_of_code=1,
                num_functions=0,
                num_classes=0,
                avg_function_length=0,
                max_function_length=0,
                max_nesting_depth=0,
                cyclomatic_complexity=0,
                comment_ratio=0.0,
                import_count=0,
            ),
            "agent_outputs": [],
        }

    # Create a fake astream_events that simulates the graph execution
    async def fake_astream_events(state, version):
        # Simulate events for each node
        events = [
            {"event": "on_chain_end", "name": "parse_code"},
            {"event": "on_chain_end", "name": "enrich_context"},
            {"event": "on_chain_end", "name": "quality_agent"},
            {"event": "on_chain_end", "name": "security_agent"},
            {"event": "on_chain_end", "name": "docs_agent"},
            {"event": "on_chain_end", "name": "synthesize", "data": {"output": await fake_ainvoke(state)}},
        ]
        for event in events:
            yield event

    with patch("app.mcp.server.review_graph.astream_events", side_effect=fake_astream_events):
        result = await _run_review("def foo(): pass", Language.PYTHON, ctx=mock_ctx)

    # Verify progress was reported for each major stage
    assert mock_ctx.report_progress.call_count == 6

    # Check the first few progress calls
    calls = mock_ctx.report_progress.call_args_list
    assert calls[0][1]["message"] == "Odin reviewing… parsing complete"
    assert calls[0][1]["progress"] == 1
    assert calls[0][1]["total"] == 6

    assert calls[1][1]["message"] == "Odin reviewing… context enriched"
    assert calls[1][1]["progress"] == 2
    assert calls[1][1]["total"] == 6

    # Check agent progress messages
    assert calls[2][1]["message"] == "Odin reviewing… 0/3 agents complete"
    assert calls[3][1]["message"] == "Odin reviewing… 1/3 agents complete"
    assert calls[4][1]["message"] == "Odin reviewing… 2/3 agents complete"

    # Check final progress message
    assert calls[5][1]["message"] == "Odin reviewing… synthesizing findings"
    assert calls[5][1]["progress"] == 6
    assert calls[5][1]["total"] == 6

    # Verify result is returned correctly
    assert result["overall_score"] == 85


@pytest.mark.asyncio
async def test_progress_callback_noop_without_context():
    """Verify that progress reporting gracefully no-ops when Context is None."""
    from app.mcp.server import _run_review
    from app.models.enums import Language

    # Mock the review graph to return a valid result
    async def fake_ainvoke(state):
        from app.models.schemas import CodeMetrics

        return {
            "overall_score": 85,
            "summary": "Test review.",
            "findings": [],
            "metrics": CodeMetrics(
                lines_of_code=1,
                num_functions=0,
                num_classes=0,
                avg_function_length=0,
                max_function_length=0,
                max_nesting_depth=0,
                cyclomatic_complexity=0,
                comment_ratio=0.0,
                import_count=0,
            ),
            "agent_outputs": [],
        }

    # Create a fake astream_events that simulates the graph execution
    async def fake_astream_events(state, version):
        events = [
            {"event": "on_chain_end", "name": "parse_code"},
            {"event": "on_chain_end", "name": "enrich_context"},
            {"event": "on_chain_end", "name": "quality_agent"},
            {"event": "on_chain_end", "name": "security_agent"},
            {"event": "on_chain_end", "name": "docs_agent"},
            {"event": "on_chain_end", "name": "synthesize", "data": {"output": await fake_ainvoke(state)}},
        ]
        for event in events:
            yield event

    with patch("app.mcp.server.review_graph.astream_events", side_effect=fake_astream_events):
        # Call _run_review without a Context - should not raise errors
        result = await _run_review("def foo(): pass", Language.PYTHON, ctx=None)

    # Verify result is returned correctly even without Context
    assert result["overall_score"] == 85


@pytest.mark.asyncio
async def test_progress_callback_graceful_fallback_on_error():
    """Verify that progress reporting gracefully handles exceptions from Context."""
    from unittest.mock import MagicMock

    from app.mcp.server import _run_review
    from app.models.enums import Language

    # Create a mock Context that raises an exception
    mock_ctx = MagicMock()
    mock_ctx.report_progress = AsyncMock(side_effect=RuntimeError("Transport not supported"))

    # Mock the review graph to return a valid result
    async def fake_ainvoke(state):
        from app.models.schemas import CodeMetrics

        return {
            "overall_score": 85,
            "summary": "Test review.",
            "findings": [],
            "metrics": CodeMetrics(
                lines_of_code=1,
                num_functions=0,
                num_classes=0,
                avg_function_length=0,
                max_function_length=0,
                max_nesting_depth=0,
                cyclomatic_complexity=0,
                comment_ratio=0.0,
                import_count=0,
            ),
            "agent_outputs": [],
        }

    # Create a fake astream_events that simulates the graph execution
    async def fake_astream_events(state, version):
        events = [
            {"event": "on_chain_end", "name": "parse_code"},
            {"event": "on_chain_end", "name": "enrich_context"},
            {"event": "on_chain_end", "name": "quality_agent"},
            {"event": "on_chain_end", "name": "security_agent"},
            {"event": "on_chain_end", "name": "docs_agent"},
            {"event": "on_chain_end", "name": "synthesize", "data": {"output": await fake_ainvoke(state)}},
        ]
        for event in events:
            yield event

    with patch("app.mcp.server.review_graph.astream_events", side_effect=fake_astream_events):
        # Call _run_review with a Context that raises errors - should not raise
        result = await _run_review("def foo(): pass", Language.PYTHON, ctx=mock_ctx)

    # Verify result is returned correctly even when progress reporting fails
    assert result["overall_score"] == 85
    # Verify report_progress was called (errors were caught)
    assert mock_ctx.report_progress.call_count == 6
