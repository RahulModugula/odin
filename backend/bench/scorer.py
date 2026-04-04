"""Scoring logic: classify tool output against ground truth and compute metrics."""

from __future__ import annotations

from bench.schemas import (
    SampleLabel,
    SampleResult,
)
from bench.tools.common import BenchSample, ToolFinding, ToolRunner

# A sample is "flagged" if the tool produced at least one finding above this severity threshold.
_FINDING_THRESHOLD_CONFIDENCE = 0.0  # include all findings by default


def classify(
    sample: BenchSample,
    findings: list[ToolFinding],
    tool: str,
    latency_ms: float,
    min_confidence: float = _FINDING_THRESHOLD_CONFIDENCE,
) -> SampleResult:
    """Classify a tool's output for one sample against its ground-truth label."""
    relevant = [f for f in findings if f.confidence >= min_confidence]
    flagged = len(relevant) > 0

    if sample.label == SampleLabel.VULNERABLE:
        tp = flagged
        fn = not flagged
        fp = False
        tn = False
    else:  # CLEAN
        fp = flagged
        tn = not flagged
        tp = False
        fn = False

    return SampleResult(
        tool=tool,
        dataset=sample.dataset,
        sample_id=sample.id,
        language=sample.language,
        label=sample.label,
        findings=relevant,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        latency_ms=latency_ms,
    )


def run_tool_on_dataset(
    runner: ToolRunner,
    samples: list[BenchSample],
    min_confidence: float = _FINDING_THRESHOLD_CONFIDENCE,
) -> list[SampleResult]:
    """Run a tool against all samples in a dataset and classify results."""
    results = []
    for sample in samples:
        try:
            findings, latency_ms = runner.run(sample)
        except Exception as exc:
            results.append(SampleResult(
                tool=runner.name,
                dataset=sample.dataset,
                sample_id=sample.id,
                language=sample.language,
                label=sample.label,
                findings=[],
                error=str(exc),
            ))
            continue
        result = classify(sample, findings, runner.name, latency_ms, min_confidence)
        results.append(result)
    return results
