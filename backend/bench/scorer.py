"""Scoring logic: classify tool output against ground truth and compute metrics.

Matching criterion
------------------
The scorer uses **line-localized matching**: a vulnerable sample is counted as
a true positive only if the tool produces a finding whose reported line range
overlaps a ground-truth bug marker (``# BUG:`` / ``// VULNERABLE:``) in the
sample.  A finding that fires elsewhere in the snippet — a tangential "magic
number", "missing docstring", or "line too long" — does **not** count.

This replaces the earlier *sample-level* criterion, under which any finding
anywhere in a snippet was credited.  That criterion inflated recall into a
measure of rule *breadth* ("did the tool print anything?") rather than
vulnerability *detection* ("did the tool flag the actual bug?"), and produced
numbers — 100% on SWE-bench, 86% on SecVulEval — that do not survive scrutiny.
The line-localized criterion is the honest one and is what every headline
number in ``leaderboard.md`` is now computed under.

Clean samples carry no markers, so the false-positive definition is unchanged:
any finding on a clean sample is still a false positive.  See ``matches`` for
the two fail-open fallbacks.
"""

from __future__ import annotations

import re
from dataclasses import replace

from bench.schemas import (
    SampleLabel,
    SampleResult,
    ToolFinding,
)
from bench.tools.common import BenchSample, ToolRunner

# A sample is "flagged" if the tool produced at least one finding above this severity threshold.
_FINDING_THRESHOLD_CONFIDENCE = 0.0  # include all findings by default

# Ground-truth markers embedded in the vulnerable samples.  A marker on line M
# flags either the trailing code on line M or the statement on the line
# immediately below it (comment-above style), so the accepted window is [M, M+1].
_MARKER_RE = re.compile(r"(?:#|//)\s*(?:BUG|VULNERABLE)\b", re.IGNORECASE)
_MARKER_SPAN = 1  # lines below the marker that still count as the same bug


def _ground_truth_windows(code: str) -> list[tuple[int, int]]:
    """Return 1-indexed inclusive (start, end) line windows around each
    ground-truth bug marker in *code*."""
    windows: list[tuple[int, int]] = []
    for lineno, line in enumerate(code.splitlines(), start=1):
        if _MARKER_RE.search(line):
            windows.append((lineno, lineno + _MARKER_SPAN))
    return windows


def strip_markers(code: str) -> str:
    """Remove ground-truth ``# BUG:`` / ``// VULNERABLE:`` annotations from
    *code* while preserving line numbers.

    This is **contamination control**.  The markers are scoring metadata, not
    part of the program under review.  If the raw marker text reaches the tool,
    a rule that flags ``TODO``/``FIXME``/``BUG`` comments (Odin's CL001, among
    others) will "detect" the planted comment on the exact bug line — turning
    recall into a measure of *"did the tool grep for the word BUG we inserted?"*
    Empirically this alone produced Odin's fake 100% on SWE-bench.

    Everything before the marker on its line is kept (so a trailing annotation
    like ``x = f(y)  # BUG: ...`` leaves ``x = f(y)`` intact); a whole-line
    marker collapses to a blank line so downstream line numbers are unchanged
    and still align with ``_ground_truth_windows`` computed on the original.
    """
    out: list[str] = []
    for line in code.splitlines():
        m = _MARKER_RE.search(line)
        out.append(line[: m.start()].rstrip() if m else line)
    return "\n".join(out)


def matches(
    sample: BenchSample,
    finding: ToolFinding,
) -> bool:
    """Determine whether a single finding counts as a hit on *sample*.

    Criterion — **line-localized**: the finding's reported line range must
    overlap a window around a ground-truth ``# BUG:`` / ``// VULNERABLE:``
    marker.  A finding on an unrelated line does not count.

    Two fail-open fallbacks (both also apply to clean samples, keeping the
    false-positive rate identical to the previous scorer):

    * **No markers in the sample** → any finding matches.  Clean samples never
      carry markers, so this preserves the FP definition; a markerless
      vulnerable sample is not silently zeroed out.
    * **Finding has no line range** → cannot be localized, so it does *not*
      match when markers are present (the tool failed to point at the bug).
    """
    windows = _ground_truth_windows(sample.code)
    if not windows:
        return True

    if finding.line_start is None:
        return False
    f_start = finding.line_start
    f_end = finding.line_end if finding.line_end is not None else finding.line_start
    return any(f_start <= w_end and f_end >= w_start for w_start, w_end in windows)


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
        # Strip ground-truth markers before the tool sees the code, but classify
        # against the original sample so _ground_truth_windows still has them.
        clean_sample = replace(sample, code=strip_markers(sample.code))
        try:
            findings, latency_ms = runner.run(clean_sample)
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
