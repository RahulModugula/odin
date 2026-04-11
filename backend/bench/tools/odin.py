"""Odin tool runner — runs Odin's rules-only pipeline against benchmark samples."""

from __future__ import annotations

import time

from bench.schemas import SeverityLevel, ToolFinding
from bench.tools.common import BenchSample, ToolRunner

_SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
}


class OdinRulesRunner(ToolRunner):
    """Runs Odin's deterministic rule engine (no LLM required)."""

    name = "odin-rules"

    def __init__(self) -> None:
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            from app.rules.engine import rule_engine
            from app.rules.registry import register_all

            if not rule_engine.is_initialized():
                register_all()
            self._initialized = True

    def is_available(self) -> bool:
        try:
            self._ensure_initialized()
            return True
        except Exception:
            return False

    def run(self, sample: BenchSample) -> tuple[list[ToolFinding], float]:
        self._ensure_initialized()

        from app.models.enums import Language
        from app.rules.engine import rule_engine

        start = time.perf_counter()
        try:
            lang = Language(sample.language)
            raw = rule_engine.check_all(sample.code, lang)
        except Exception:
            raw = []
        elapsed_ms = (time.perf_counter() - start) * 1000

        findings = [
            ToolFinding(
                tool=self.name,
                rule_id=getattr(f, "source", None) or "rule",
                title=f.title,
                severity=_SEVERITY_MAP.get(str(f.severity).lower(), SeverityLevel.MEDIUM),
                line_start=f.line_start,
                line_end=f.line_end,
                category=str(f.category.value) if hasattr(f.category, "value") else str(f.category),
                confidence=f.confidence,
                raw=f.model_dump() if hasattr(f, "model_dump") else {},
            )
            for f in raw
        ]
        return findings, elapsed_ms
