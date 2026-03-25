"""Quality gate evaluation — pass/fail criteria for PR reviews."""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.schemas import ReviewResult


@dataclass
class QualityGateConfig:
    min_score: int = 0  # 0 = disabled
    max_critical: int = -1  # -1 = no limit
    max_high: int = -1
    block_on_fail: bool = False  # if True, post as REQUEST_CHANGES


@dataclass
class QualityGateResult:
    passed: bool
    score: int
    reasons: list[str] = field(default_factory=list)


def evaluate(results: list["ReviewResult"], config: QualityGateConfig) -> QualityGateResult:
    """Evaluate quality gate against a list of per-file results."""
    if not results:
        return QualityGateResult(passed=True, score=100, reasons=[])

    total_score = sum(r.overall_score for r in results) // len(results)
    critical_count = sum(1 for r in results for f in r.findings if f.severity.value == "critical")
    high_count = sum(1 for r in results for f in r.findings if f.severity.value == "high")

    reasons = []
    passed = True

    if config.min_score > 0 and total_score < config.min_score:
        reasons.append(f"Score {total_score} is below minimum {config.min_score}")
        passed = False

    if config.max_critical >= 0 and critical_count > config.max_critical:
        reasons.append(f"{critical_count} critical finding(s) (max: {config.max_critical})")
        passed = False

    if config.max_high >= 0 and high_count > config.max_high:
        reasons.append(f"{high_count} high finding(s) (max: {config.max_high})")
        passed = False

    return QualityGateResult(passed=passed, score=total_score, reasons=reasons)
