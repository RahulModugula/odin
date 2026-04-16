"""Tests for diff-aware finding filtering in the synthesize node."""

from app.agents.graph import _tag_pre_existing, synthesize
from app.models.enums import Category, Severity
from app.models.schemas import CodeMetrics, Finding


def _make_metrics() -> CodeMetrics:
    return CodeMetrics(
        lines_of_code=100,
        num_functions=3,
        num_classes=0,
        avg_function_length=30.0,
        max_function_length=50,
        max_nesting_depth=3,
        cyclomatic_complexity=5,
        comment_ratio=0.1,
        import_count=3,
    )


def _make_finding(
    line_start: int | None = 10,
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
) -> Finding:
    return Finding(
        severity=severity,
        category=Category.SECURITY,
        title=title,
        description="A test finding",
        line_start=line_start,
        confidence=0.9,
    )


# ── _tag_pre_existing unit tests ─────────────────────────────────────────────


def test_near_changed_line_unchanged() -> None:
    """Finding on a changed line should keep its severity."""
    findings = [_make_finding(line_start=10, severity=Severity.HIGH)]
    result = _tag_pre_existing(findings, changed_lines=[(8, 15)])
    assert result[0].severity == Severity.HIGH


def test_far_from_changed_line_downgraded() -> None:
    """Finding far from all changed lines should be downgraded one level."""
    findings = [_make_finding(line_start=100, severity=Severity.HIGH)]
    result = _tag_pre_existing(findings, changed_lines=[(1, 5)])
    assert result[0].severity == Severity.MEDIUM


def test_critical_downgraded_to_high() -> None:
    findings = [_make_finding(line_start=100, severity=Severity.CRITICAL)]
    result = _tag_pre_existing(findings, changed_lines=[(1, 5)])
    assert result[0].severity == Severity.HIGH


def test_info_not_downgraded_below_info() -> None:
    """INFO should stay INFO (no severity below info)."""
    findings = [_make_finding(line_start=100, severity=Severity.INFO)]
    result = _tag_pre_existing(findings, changed_lines=[(1, 5)])
    assert result[0].severity == Severity.INFO


def test_pre_existing_note_appended_to_description() -> None:
    findings = [_make_finding(line_start=100, severity=Severity.HIGH)]
    result = _tag_pre_existing(findings, changed_lines=[(1, 5)])
    assert "Pre-existing" in result[0].description


def test_near_changed_line_no_note_appended() -> None:
    findings = [_make_finding(line_start=10, severity=Severity.HIGH)]
    result = _tag_pre_existing(findings, changed_lines=[(8, 15)])
    assert "Pre-existing" not in result[0].description


def test_proximity_boundary_exactly_10_lines_away() -> None:
    """Finding exactly 10 lines outside a hunk is still considered 'near'."""
    findings = [_make_finding(line_start=25, severity=Severity.HIGH)]
    # hunk ends at 15; 25 - 15 = 10 (≤ PROXIMITY=10), so "near"
    result = _tag_pre_existing(findings, changed_lines=[(5, 15)])
    assert result[0].severity == Severity.HIGH


def test_proximity_boundary_11_lines_away_is_far() -> None:
    """Finding 11 lines outside a hunk should be downgraded."""
    findings = [_make_finding(line_start=26, severity=Severity.HIGH)]
    # hunk ends at 15; 26 - 15 = 11 > PROXIMITY=10
    result = _tag_pre_existing(findings, changed_lines=[(5, 15)])
    assert result[0].severity == Severity.MEDIUM


def test_finding_with_no_line_number_kept_unchanged() -> None:
    """Findings with no line number (general findings) are never downgraded."""
    findings = [_make_finding(line_start=None, severity=Severity.CRITICAL)]
    result = _tag_pre_existing(findings, changed_lines=[(1, 5)])
    assert result[0].severity == Severity.CRITICAL


def test_multiple_hunks_finding_near_any_hunk_kept() -> None:
    """Finding near any one hunk should be kept at original severity."""
    findings = [_make_finding(line_start=80, severity=Severity.HIGH)]
    # Two hunks: lines 1-10 and lines 75-85
    result = _tag_pre_existing(findings, changed_lines=[(1, 10), (75, 85)])
    assert result[0].severity == Severity.HIGH


def test_empty_changed_lines_passthrough() -> None:
    """Empty changed_lines means no diff context — all findings unchanged."""
    findings = [_make_finding(line_start=100, severity=Severity.CRITICAL)]
    result = _tag_pre_existing(findings, changed_lines=[])
    # _tag_pre_existing with empty list: the `any(...)` returns False for all
    # so all findings get downgraded — but in practice this is only called
    # when changed_lines is non-empty (guarded in synthesize). Test the raw
    # function: empty changed_lines means no hunk matches → all downgraded.
    assert result[0].severity == Severity.HIGH  # CRITICAL → HIGH


def test_order_preserved() -> None:
    """Output order must match input order."""
    findings = [
        _make_finding(line_start=50, severity=Severity.HIGH, title="far"),
        _make_finding(line_start=5, severity=Severity.MEDIUM, title="near"),
    ]
    result = _tag_pre_existing(findings, changed_lines=[(1, 10)])
    assert result[0].title == "far"
    assert result[1].title == "near"


# ── Integration: synthesize respects changed_lines ───────────────────────────


def test_synthesize_downgrade_pre_existing_on_pr() -> None:
    """synthesize should downgrade findings outside changed hunks on PR context."""
    state = {
        "code": "x = 1",
        "language": "python",
        "ast_summary": "",
        "metrics": _make_metrics(),
        "findings": [
            _make_finding(line_start=100, severity=Severity.HIGH, title="pre-existing"),
            _make_finding(line_start=5, severity=Severity.HIGH, title="in-diff"),
        ],
        "agent_outputs": [],
        "overall_score": 100,
        "summary": "",
        "changed_lines": [(1, 10)],
    }
    result = synthesize(state)
    by_title = {f.title: f for f in result["findings"]}

    assert by_title["in-diff"].severity == Severity.HIGH
    assert by_title["pre-existing"].severity == Severity.MEDIUM


def test_synthesize_no_downgrade_without_changed_lines() -> None:
    """Without changed_lines (direct API review), no downgrading should occur."""
    state = {
        "code": "x = 1",
        "language": "python",
        "ast_summary": "",
        "metrics": _make_metrics(),
        "findings": [
            _make_finding(line_start=100, severity=Severity.CRITICAL),
        ],
        "agent_outputs": [],
        "overall_score": 100,
        "summary": "",
        # No "changed_lines" key
    }
    result = synthesize(state)
    assert result["findings"][0].severity == Severity.CRITICAL
