import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_review_code_tool_returns_dict():
    mock_result = {
        "overall_score": 85,
        "summary": "Code looks good.",
        "findings": [],
        "metrics": {"lines_of_code": 10, "num_functions": 1, "num_classes": 0,
                    "avg_function_length": 5.0, "max_function_length": 5,
                    "max_nesting_depth": 1, "cyclomatic_complexity": 1,
                    "comment_ratio": 0.0, "import_count": 0},
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
async def test_query_codebase_no_store_returns_error():
    with patch("app.graph_rag._store_ref.store", None):
        from app.mcp.server import query_codebase

        result = await query_codebase("process_data")

    assert "error" in result
