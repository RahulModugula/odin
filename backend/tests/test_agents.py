from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agents.graph import (
    _calculate_score,
    _deduplicate_findings,
    _generate_summary,
    review_graph,
)
from app.models.enums import Category, Severity
from app.models.schemas import CodeMetrics, Finding


def test_graph_compiles() -> None:
    """The review graph should compile without errors."""
    assert review_graph is not None
    nodes = review_graph.get_graph().nodes
    assert "parse_code" in nodes
    assert "quality_agent" in nodes
    assert "security_agent" in nodes
    assert "docs_agent" in nodes
    assert "synthesize" in nodes


def test_dedup_same_line_same_category() -> None:
    """Two findings on same line with same category should be deduped."""
    findings = [
        Finding(
            severity=Severity.HIGH,
            category=Category.QUALITY,
            title="Bad naming",
            description="Variable x is poorly named",
            line_start=5,
            line_end=5,
            confidence=0.7,
        ),
        Finding(
            severity=Severity.MEDIUM,
            category=Category.QUALITY,
            title="Poor variable name",
            description="Variable x should be renamed",
            line_start=5,
            line_end=5,
            confidence=0.9,
        ),
    ]
    result = _deduplicate_findings(findings)
    assert len(result) == 1
    assert result[0].confidence == 0.9


def test_dedup_same_line_different_category() -> None:
    """Two findings on same line but different categories should both remain."""
    findings = [
        Finding(
            severity=Severity.HIGH,
            category=Category.QUALITY,
            title="Bad naming",
            description="Variable x is poorly named",
            line_start=5,
            line_end=5,
            confidence=0.8,
        ),
        Finding(
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            title="Hardcoded secret",
            description="API key exposed",
            line_start=5,
            line_end=5,
            confidence=0.95,
        ),
    ]
    result = _deduplicate_findings(findings)
    assert len(result) == 2


def test_score_no_findings() -> None:
    """No findings should result in a perfect score."""
    metrics = CodeMetrics(
        lines_of_code=50,
        num_functions=3,
        num_classes=1,
        avg_function_length=10.0,
        max_function_length=15,
        max_nesting_depth=2,
        cyclomatic_complexity=5,
        comment_ratio=0.2,
        import_count=3,
    )
    score = _calculate_score([], metrics)
    # 100 + 5 (comment_ratio) + 5 (nesting) + 5 (func_length) = 115, clamped to 100
    assert score == 100


def test_score_critical_findings() -> None:
    """Critical findings should heavily penalize the score."""
    findings = [
        Finding(
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            title="SQL injection",
            description="...",
            confidence=0.9,
        )
        for _ in range(5)
    ]
    score = _calculate_score(findings, None)
    assert score == 0  # 100 - 5*20 = 0


def test_score_mixed_findings() -> None:
    """Mixed severity findings should produce intermediate score."""
    findings = [
        Finding(
            severity=Severity.HIGH,
            category=Category.QUALITY,
            title="a",
            description="a",
            confidence=0.8,
        ),
        Finding(
            severity=Severity.MEDIUM,
            category=Category.QUALITY,
            title="b",
            description="b",
            confidence=0.8,
        ),
        Finding(
            severity=Severity.LOW,
            category=Category.DOCUMENTATION,
            title="c",
            description="c",
            confidence=0.8,
        ),
    ]
    score = _calculate_score(findings, None)
    assert score == 100 - 10 - 5 - 2  # 83


def test_summary_no_findings() -> None:
    summary = _generate_summary([], 100)
    assert "no issues" in summary.lower()


def test_summary_with_critical() -> None:
    findings = [
        Finding(
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            title="x",
            description="x",
            confidence=0.9,
        ),
    ]
    summary = _generate_summary(findings, 30)
    assert "1" in summary
    assert "critical" in summary.lower()


@pytest.mark.asyncio
async def test_quality_agent_handles_error() -> None:
    """Agent should return empty findings on LLM failure."""
    from app.agents.quality_agent import run_quality_agent

    state = {
        "code": "def foo(): pass",
        "language": "python",
        "ast_summary": "Lines of code: 1\nFunctions: 1",
        "metrics": None,
    }

    with patch("app.agents.quality_agent.get_llm") as mock_get_llm:
        mock_instance = MagicMock()
        mock_get_llm.return_value = mock_instance
        mock_structured = AsyncMock(side_effect=Exception("API error"))
        mock_instance.with_structured_output.return_value = mock_structured

        result = await run_quality_agent(state)
        assert result["findings"] == []
        assert result["agent_outputs"][0].agent_name == "quality"
