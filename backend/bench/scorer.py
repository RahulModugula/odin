"""Scoring logic: classify tool output against ground truth and compute metrics.

Matching criterion
------------------
The scorer uses **sample-level matching**: a vulnerable sample is counted as a
true positive if the tool produces *any* finding (above the confidence
threshold) on that sample, regardless of the finding's line range, category,
or rule ID.

This is appropriate for the SWE-bench and SecVulEval datasets because each
sample is a small, self-contained code snippet (typically 5–15 lines) where
the entire snippet *is* the buggy code.  There is no "unrelated code" for a
tool to accidentally flag.

Caveat: a tool that flags a tangential quality or style issue (e.g. "missing
docstring") on a snippet whose ground-truth bug is a logic error will still
receive credit.  The recall number therefore measures "did the tool fire on
*anything* in the snippet?" rather than "did the tool correctly identify the
*specific* bug?".  This is documented in the leaderboard methodology section.

The ``matches`` function below encapsulates the criterion so it can be
tightened (e.g. to require line-range overlap) in the future without
modifying the surrounding orchestration code.
"""

from __future__ import annotations

from bench.schemas import (
    SampleLabel,
    SampleResult,
)
from bench.tools.common import BenchSample, ToolFinding, ToolRunner

# A sample is "flagged" if the tool produced at least one finding above this severity threshold.
_FINDING_THRESHOLD_CONFIDENCE = 0.0  # include all findings by default


def matches(
    sample: BenchSample,
    finding: ToolFinding,
) -> bool:
    """Determine whether a single finding counts as a hit on *sample*.

    Current criterion — **sample-level**: any finding on a vulnerable sample
    is considered a match.  Line-range overlap is *not* required because the
    benchmark samples are self-contained snippets where the entire code is the
    bug context.

    To tighten the criterion (e.g. require that the finding's line range
    overlaps the ground-truth buggy lines), modify this function.  The rest
    of the scoring pipeline calls ``matches`` and will pick up the change
    automatically.
    """
    # Sample-level: any finding is a match.  The sample's ``notes`` field
    # contains the ground-truth description (including ``# BUG:`` markers in
    # the code), but we do not require the finding to overlap those lines
    # because the snippets are too small for line-level precision to be
    # meaningful.
    _ = sample, finding  # acknowledge parameters — criterion is unconditional
    return True


def classify(
    sample: BenchSample,
    findings: list[ToolFinding],
    tool: str,
    latency_ms: float,
    min_confidence: float = _FINDING_THRESHOLD_CONFIDENCE,
) -> SampleResult:
    """Classify a tool's output for one sample against its ground-truth label.

    A vulnerable sample is a true positive if **at least one** finding above
    the confidence threshold passes the ``matches`` check.  A clean sample is
    a false positive under the same condition.
    """
    relevant = [f for f in findings if f.confidence >= min_confidence]
    matching = [f for f in relevant if matches(sample, f)]
    flagged = len(matching) > 0

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
            results.append(
                SampleResult(
                    tool=runner.name,
                    dataset=sample.dataset,
                    sample_id=sample.id,
                    language=sample.language,
                    label=sample.label,
                    findings=[],
                    error=str(exc),
                )
            )
            continue
        result = classify(sample, findings, runner.name, latency_ms, min_confidence)
        results.append(result)
    return results
