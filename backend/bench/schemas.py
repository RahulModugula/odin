"""Shared schemas for the Odin benchmark harness."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class SampleLabel(StrEnum):
    """Ground-truth label for a benchmark sample."""
    VULNERABLE = "vulnerable"
    CLEAN = "clean"


class SeverityLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ToolFinding:
    """Normalized finding from any tool — tool-specific output mapped to this."""
    tool: str
    rule_id: str | None
    title: str
    severity: SeverityLevel
    line_start: int | None
    line_end: int | None
    category: str  # security | quality | style | performance
    confidence: float  # 0.0–1.0; use 1.0 for deterministic rules
    raw: dict = field(default_factory=dict)  # original tool output


@dataclass
class SampleResult:
    """Result of running one tool against one sample."""
    tool: str
    dataset: str
    sample_id: str
    language: str
    label: SampleLabel           # ground truth
    findings: list[ToolFinding]
    # Classification against ground truth
    true_positive: bool = False  # tool flagged a vuln sample correctly
    false_positive: bool = False # tool flagged a clean sample incorrectly
    true_negative: bool = False  # tool correctly skipped a clean sample
    false_negative: bool = False # tool missed a vuln sample
    latency_ms: float = 0.0
    error: str | None = None


@dataclass
class DatasetMetrics:
    """Aggregate metrics for one (tool, dataset) pair."""
    tool: str
    dataset: str
    n_samples: int
    n_vuln: int
    n_clean: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    fp_rate: float       # FP / (FP + TN) — the headline metric
    avg_latency_ms: float

    @classmethod
    def from_results(cls, tool: str, dataset: str, results: list[SampleResult]) -> DatasetMetrics:
        n = len(results)
        n_vuln = sum(1 for r in results if r.label == SampleLabel.VULNERABLE)
        n_clean = sum(1 for r in results if r.label == SampleLabel.CLEAN)
        tp = sum(1 for r in results if r.true_positive)
        fp = sum(1 for r in results if r.false_positive)
        tn = sum(1 for r in results if r.true_negative)
        fn = sum(1 for r in results if r.false_negative)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        avg_latency = sum(r.latency_ms for r in results) / n if n else 0.0
        return cls(
            tool=tool, dataset=dataset, n_samples=n, n_vuln=n_vuln, n_clean=n_clean,
            tp=tp, fp=fp, tn=tn, fn=fn, precision=round(precision, 3),
            recall=round(recall, 3), f1=round(f1, 3), fp_rate=round(fp_rate, 3),
            avg_latency_ms=round(avg_latency, 1),
        )


@dataclass
class BenchmarkReport:
    """Full report for one benchmark run."""
    run_id: str
    timestamp: str
    commit_sha: str
    odin_version: str
    datasets: list[str]
    tools: list[str]
    metrics: list[DatasetMetrics]
    sample_results: list[SampleResult] = field(default_factory=list)
