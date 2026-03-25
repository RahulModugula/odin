"""Tests for the webhook processor: language detection, file filtering, and aggregation."""

from unittest.mock import AsyncMock, patch

import pytest

from app.models.enums import Category, Language, Severity
from app.models.schemas import CodeMetrics, Finding, ReviewResult
from app.services.webhook_processor import (
    _build_inline_comments,
    _build_review_body,
    detect_language,
    process_pr_webhook,
    should_skip_file,
)

# ── Language detection ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("app/main.py", Language.PYTHON),
        ("src/index.js", Language.JAVASCRIPT),
        ("src/App.jsx", Language.JAVASCRIPT),
        ("src/App.tsx", Language.TYPESCRIPT),
        ("src/types.ts", Language.TYPESCRIPT),
        ("server/main.go", Language.GO),
        ("README.md", None),
        ("Dockerfile", None),
        ("data.json", None),
    ],
)
def test_detect_language(filename: str, expected: Language | None) -> None:
    assert detect_language(filename) == expected


# ── File filtering ───────────────────────────────────────────────────────────


def test_skip_removed_files() -> None:
    assert should_skip_file("app/main.py", "removed") is True


def test_skip_renamed_files() -> None:
    assert should_skip_file("app/main.py", "renamed") is True


def test_skip_unsupported_extension() -> None:
    assert should_skip_file("main.rb", "modified") is True


@pytest.mark.parametrize(
    "filename",
    [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "go.sum",
        "Cargo.lock",
        "go.mod",
    ],
)
def test_skip_lock_files(filename: str) -> None:
    assert should_skip_file(filename, "modified") is True


def test_skip_minified_js() -> None:
    assert should_skip_file("dist/bundle.min.js", "modified") is True


def test_skip_vendor_path() -> None:
    assert should_skip_file("vendor/lib/util.py", "added") is True


def test_skip_node_modules_path() -> None:
    assert should_skip_file("node_modules/react/index.js", "added") is True


def test_does_not_skip_valid_python() -> None:
    assert should_skip_file("app/main.py", "modified") is False


def test_does_not_skip_valid_typescript_added() -> None:
    assert should_skip_file("src/hooks/useAuth.ts", "added") is False


# ── Comment building ─────────────────────────────────────────────────────────


def _make_metrics() -> CodeMetrics:
    return CodeMetrics(
        lines_of_code=50,
        num_functions=3,
        num_classes=1,
        avg_function_length=10.0,
        max_function_length=20,
        max_nesting_depth=2,
        cyclomatic_complexity=5,
        comment_ratio=0.1,
        import_count=3,
    )


def _make_finding(severity: Severity = Severity.HIGH, line_start: int | None = 10) -> Finding:
    return Finding(
        severity=severity,
        category=Category.SECURITY,
        title="Test issue",
        description="Something bad here.",
        line_start=line_start,
        line_end=line_start,
        suggestion="Fix it like this.",
        confidence=0.9,
    )


def test_inline_comments_include_line_findings() -> None:
    result = ReviewResult(
        metrics=_make_metrics(),
        findings=[_make_finding(line_start=42)],
        overall_score=80,
        summary="ok",
        language=Language.PYTHON,
    )
    comments = _build_inline_comments("src/auth.py", result)
    assert len(comments) == 1
    assert comments[0]["path"] == "src/auth.py"
    assert comments[0]["line"] == 42
    assert comments[0]["side"] == "RIGHT"
    assert "SECURITY" in comments[0]["body"]
    assert "Fix it like this" in comments[0]["body"]


def test_inline_comments_exclude_no_line_findings() -> None:
    result = ReviewResult(
        metrics=_make_metrics(),
        findings=[_make_finding(line_start=None)],
        overall_score=90,
        summary="ok",
        language=Language.PYTHON,
    )
    comments = _build_inline_comments("src/utils.py", result)
    assert len(comments) == 0


def test_inline_comments_sorted_by_severity() -> None:
    result = ReviewResult(
        metrics=_make_metrics(),
        findings=[
            _make_finding(Severity.LOW, line_start=5),
            _make_finding(Severity.CRITICAL, line_start=10),
            _make_finding(Severity.HIGH, line_start=15),
        ],
        overall_score=60,
        summary="bad",
        language=Language.PYTHON,
    )
    comments = _build_inline_comments("main.py", result)
    bodies = [c["body"] for c in comments]
    assert "CRITICAL" in bodies[0]
    assert "HIGH" in bodies[1]
    assert "LOW" in bodies[2]


# ── Review body building ─────────────────────────────────────────────────────


def test_review_body_contains_table() -> None:
    result = ReviewResult(
        metrics=_make_metrics(),
        findings=[_make_finding()],
        overall_score=75,
        summary="ok",
        language=Language.PYTHON,
    )
    body = _build_review_body([("src/auth.py", result)])
    assert "| File | Score | Critical | High | Medium | Low |" in body
    assert "`src/auth.py`" in body
    assert "75/100" in body


def test_review_body_handles_failed_file() -> None:
    body = _build_review_body([("broken.py", None)])
    # Failed files render with em-dashes in the score/count columns
    assert "`broken.py`" in body
    assert "—" in body


def test_review_body_no_line_findings_go_to_general_section() -> None:
    result = ReviewResult(
        metrics=_make_metrics(),
        findings=[_make_finding(line_start=None)],
        overall_score=85,
        summary="",
        language=Language.TYPESCRIPT,
    )
    body = _build_review_body([("src/app.ts", result)])
    assert "General Findings" in body
    assert "Test issue" in body


def test_review_body_includes_odin_attribution() -> None:
    body = _build_review_body([])
    assert "Odin" in body


# ── process_pr_webhook early exits ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_process_pr_webhook_no_token_skips_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.services.webhook_processor.settings.github_token", "")

    with patch("app.services.webhook_processor.get_pr_files", new_callable=AsyncMock) as mock_files:
        await process_pr_webhook("alice", "repo", 1, "sha123")

    mock_files.assert_not_called()


@pytest.mark.asyncio
async def test_process_pr_webhook_no_qualifying_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.services.webhook_processor.settings.github_token", "ghp_test")

    pr_files = [{"filename": "yarn.lock", "status": "modified", "changes": 5}]

    with (
        patch(
            "app.services.webhook_processor.get_pr_files",
            new_callable=AsyncMock,
            return_value=pr_files,
        ),
        patch(
            "app.services.webhook_processor.get_pr_details",
            new_callable=AsyncMock,
            return_value={"title": "test", "body": ""},
        ),
        patch(
            "app.services.webhook_processor.create_pr_review", new_callable=AsyncMock
        ) as mock_post,
    ):
        await process_pr_webhook("alice", "repo", 1, "sha123")

    # Should post an "no files" review
    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args.kwargs
    assert "No files" in call_kwargs["body"] or "No files" in str(mock_post.call_args)
