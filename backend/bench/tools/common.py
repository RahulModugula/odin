"""Normalized tool output schema and base runner interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from bench.schemas import SampleLabel, ToolFinding


@dataclass
class BenchSample:
    """A single sample to run through a tool."""
    id: str
    language: str
    code: str
    label: SampleLabel
    dataset: str
    notes: str = ""


class ToolRunner(ABC):
    """Base class for all tool runners."""

    name: str  # e.g. "odin", "semgrep", "codeql"

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the tool is installed and ready to use."""
        ...

    @abstractmethod
    def run(self, sample: BenchSample) -> tuple[list[ToolFinding], float]:
        """Run the tool against one sample.

        Returns:
            (findings, latency_ms)
        """
        ...

    def run_batch(self, samples: list[BenchSample]) -> dict[str, tuple[list[ToolFinding], float]]:
        """Run the tool against multiple samples. Returns {sample_id: (findings, latency_ms)}."""
        return {s.id: self.run(s) for s in samples}
