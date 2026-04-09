"""Qodo PR-Agent adapter — calls the Qodo (formerly CodiumAI) API.

Requires: QODO_API_KEY environment variable.
Currently a stub — fill in when Qodo API access is available.
"""

from __future__ import annotations

import os

from bench.schemas import ToolFinding
from bench.tools.common import BenchSample, ToolRunner


class QodoRunner(ToolRunner):
    name = "qodo"

    def is_available(self) -> bool:
        return bool(os.environ.get("QODO_API_KEY"))

    def run(self, sample: BenchSample) -> tuple[list[ToolFinding], float]:
        # TODO: implement when API access is available
        return [], 0.0
