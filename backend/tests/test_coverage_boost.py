from app.services.provider_registry import (
    ProviderConfig,
    get_active_provider,
    get_provider,
    list_providers,
)
from app.services.quality_gate import QualityGateConfig, evaluate
from app.observability.logging import bind_request_id, clear_request_context
from app.observability.metrics import reviews_total, review_duration_seconds, reviews_in_progress
from app.models.enums import Category, Language, Severity
from app.models.schemas import CodeMetrics, Finding, ReviewResult


def _make_result(score: int, severities: list[str]) -> ReviewResult:
    findings = [
        Finding(
            severity=Severity(s),
            category=Category.SECURITY,
            title=f"issue_{i}",
            description="test",
        )
        for i, s in enumerate(severities)
    ]
    return ReviewResult(
        metrics=CodeMetrics(
            lines_of_code=10,
            num_functions=1,
            num_classes=0,
            avg_function_length=10.0,
            max_function_length=10,
            max_nesting_depth=1,
            cyclomatic_complexity=1,
            comment_ratio=0.1,
            import_count=1,
        ),
        findings=findings,
        overall_score=score,
        language=Language.PYTHON,
    )


class TestProviderRegistry:
    def test_list_providers_returns_all(self):
        providers = list_providers()
        assert len(providers) >= 4
        names = {p.name for p in providers}
        assert "lmstudio" in names
        assert "openrouter" in names
        assert "openai" in names
        assert "ollama" in names

    def test_get_provider_known(self):
        p = get_provider("lmstudio")
        assert p is not None
        assert p.base_url == "http://localhost:1234/v1"
        assert p.model == "local-model"

    def test_get_provider_unknown(self):
        assert get_provider("nonexistent") is None

    def test_get_active_provider(self):
        p = get_active_provider()
        assert isinstance(p, ProviderConfig)
        assert p.name

    def test_provider_config_fields(self):
        p = get_provider("openrouter")
        assert p is not None
        assert p.api_key == ""
        assert "BYOK" in p.description


class TestQualityGate:
    def test_empty_results_pass(self):
        result = evaluate([], QualityGateConfig())
        assert result.passed
        assert result.score == 100

    def test_score_below_min_fails(self):
        r = _make_result(50, [])
        result = evaluate([r], QualityGateConfig(min_score=70))
        assert not result.passed
        assert any("Score" in reason for reason in result.reasons)

    def test_too_many_critical_fails(self):
        r = _make_result(90, ["critical", "critical"])
        result = evaluate([r], QualityGateConfig(max_critical=1))
        assert not result.passed
        assert any("critical" in reason for reason in result.reasons)

    def test_too_many_high_fails(self):
        r = _make_result(90, ["high", "high", "high"])
        result = evaluate([r], QualityGateConfig(max_high=2))
        assert not result.passed
        assert any("high" in reason for reason in result.reasons)

    def test_all_pass(self):
        r = _make_result(95, ["low"])
        result = evaluate([r], QualityGateConfig(min_score=70, max_critical=0, max_high=5))
        assert result.passed
        assert result.score == 95

    def test_avg_score_across_results(self):
        r1 = _make_result(80, [])
        r2 = _make_result(50, [])
        result = evaluate([r1, r2], QualityGateConfig(min_score=70))
        assert not result.passed
        assert result.score == 65


class TestSetupLogging:
    def test_bind_and_clear_request_context(self):
        bind_request_id("test-123")
        clear_request_context()


class TestMetrics:
    def test_metrics_constants_exist(self):
        assert reviews_total is not None
        assert review_duration_seconds is not None
        assert reviews_in_progress is not None
