from app.models.enums import Category, Severity
from app.models.schemas import CodeMetrics, Finding
from app.agents.graph import _calculate_score, synthesize


def _make_metrics(
    comment_ratio: float = 0.1,
    max_nesting_depth: int = 5,
    avg_function_length: float = 40.0,
) -> CodeMetrics:
    return CodeMetrics(
        lines_of_code=100,
        num_functions=5,
        num_classes=1,
        avg_function_length=avg_function_length,
        max_function_length=50,
        max_nesting_depth=max_nesting_depth,
        cyclomatic_complexity=10,
        comment_ratio=comment_ratio,
        import_count=5,
    )


def _make_finding(
    severity: Severity = Severity.MEDIUM,
    category: Category = Category.QUALITY,
    line_start: int | None = None,
) -> Finding:
    return Finding(
        severity=severity,
        category=category,
        title=f"Test {severity} finding",
        description="Test description",
        line_start=line_start,
        confidence=0.8,
    )


def test_findings_sorted_by_severity_critical_first() -> None:
    """Synthesize should sort findings with critical first, then high, medium, etc."""
    state = {
        "code": "x = 1",
        "language": "python",
        "ast_summary": "",
        "metrics": _make_metrics(),
        "findings": [
            _make_finding(Severity.LOW, line_start=10),
            _make_finding(Severity.CRITICAL, line_start=5),
            _make_finding(Severity.MEDIUM, line_start=1),
            _make_finding(Severity.HIGH, line_start=20),
            _make_finding(Severity.INFO, line_start=15),
        ],
        "agent_outputs": [],
        "overall_score": 100,
        "summary": "",
    }

    result = synthesize(state)
    severities = [f.severity for f in result["findings"]]
    assert severities == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]


def test_score_clamped_at_zero() -> None:
    """Score should never go below 0 even with many critical findings."""
    findings = [_make_finding(Severity.CRITICAL) for _ in range(10)]
    score = _calculate_score(findings, None)
    assert score == 0


def test_score_clamped_at_100() -> None:
    """Score should never exceed 100 even with all bonuses and no findings."""
    metrics = _make_metrics(
        comment_ratio=0.25,
        max_nesting_depth=2,
        avg_function_length=10.0,
    )
    score = _calculate_score([], metrics)
    # 100 + 5 + 5 + 5 = 115, clamped to 100
    assert score == 100


def test_bonus_points_for_good_comment_ratio() -> None:
    """Good comment ratio (>0.15) should earn bonus points."""
    metrics_good = _make_metrics(comment_ratio=0.20)
    metrics_bad = _make_metrics(comment_ratio=0.05)

    # With one medium finding to avoid clamping at 100
    findings = [_make_finding(Severity.HIGH)]

    score_good = _calculate_score(findings, metrics_good)
    score_bad = _calculate_score(findings, metrics_bad)

    assert score_good > score_bad


def test_bonus_points_for_low_nesting() -> None:
    """Low nesting depth (<=3) should earn bonus points."""
    metrics_good = _make_metrics(max_nesting_depth=2)
    metrics_bad = _make_metrics(max_nesting_depth=6)

    findings = [_make_finding(Severity.HIGH)]

    score_good = _calculate_score(findings, metrics_good)
    score_bad = _calculate_score(findings, metrics_bad)

    assert score_good > score_bad


def test_bonus_points_for_short_functions() -> None:
    """Short average function length (<30) should earn bonus points."""
    metrics_good = _make_metrics(avg_function_length=15.0)
    metrics_bad = _make_metrics(avg_function_length=50.0)

    findings = [_make_finding(Severity.HIGH)]

    score_good = _calculate_score(findings, metrics_good)
    score_bad = _calculate_score(findings, metrics_bad)

    assert score_good > score_bad
