"""Odin dataflow tool runner — intra-procedural taint tracker (no LLM required).

This runner measures the static-analysis layer of the dataflow pipeline:
the IntraProceduralTaintTracker finds source→sink candidate paths without
any LLM triage. A sample is marked as detected if the tracker emits at least
one TaintCandidate.

This gives a recall floor: the LLM triage stage can only confirm candidates
the tracker finds, so tracker recall ≤ full-pipeline recall.
"""

from __future__ import annotations

import time

from bench.schemas import SeverityLevel, ToolFinding
from bench.tools.common import BenchSample, ToolRunner

_SINK_SEVERITY = {
    "code_exec": SeverityLevel.CRITICAL,
    "shell_exec": SeverityLevel.CRITICAL,
    "sql_query": SeverityLevel.HIGH,
    "dom_write": SeverityLevel.HIGH,
    "path_traversal": SeverityLevel.HIGH,
    "ssrf_fetch": SeverityLevel.HIGH,
    "template_render": SeverityLevel.CRITICAL,
    "deserialized": SeverityLevel.HIGH,
}


class OdinDataflowRunner(ToolRunner):
    """Runs Odin's intra-procedural taint tracker (no LLM, no server required)."""

    name = "odin-dataflow"

    def __init__(self) -> None:
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            from app.dataflow.registry import (
                sanitizer_registry,
                sink_registry,
                source_registry,
            )

            self._src = source_registry
            self._snk = sink_registry
            self._san = sanitizer_registry
            self._initialized = True

    def is_available(self) -> bool:
        try:
            self._ensure_initialized()
            return True
        except Exception:
            return False

    def run(self, sample: BenchSample) -> tuple[list[ToolFinding], float]:
        self._ensure_initialized()

        from app.dataflow.tracker import IntraProceduralTaintTracker
        from app.models.enums import Language

        start = time.perf_counter()
        findings: list[ToolFinding] = []
        try:
            lang = Language(sample.language)
            tracker = IntraProceduralTaintTracker(self._src, self._snk, self._san, lang)
            candidates = tracker.analyze(sample.code)

            for c in candidates:
                severity = _SINK_SEVERITY.get(c.sink.kind.value, SeverityLevel.HIGH)
                findings.append(
                    ToolFinding(
                        tool=self.name,
                        rule_id=f"taint:{c.source.kind.value}→{c.sink.kind.value}",
                        title=f"Taint flow: {c.source.kind.value} → {c.sink.kind.value}",
                        severity=severity,
                        line_start=c.sink_location[0],
                        line_end=c.sink_location[0],
                        category="security",
                        confidence=0.7,  # pre-LLM-triage confidence
                        raw={
                            "candidate_id": c.candidate_id,
                            "source_sig": c.source.signature,
                            "sink_sig": c.sink.signature,
                            "hops": len(c.hops),
                        },
                    )
                )
        except Exception:
            pass

        elapsed_ms = (time.perf_counter() - start) * 1000
        return findings, elapsed_ms
