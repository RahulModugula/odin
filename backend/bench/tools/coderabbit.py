"""CodeRabbit adapter — calls the CodeRabbit API to review code samples.

Requires: CODERABBIT_API_KEY environment variable.
Currently a stub — fill in when CodeRabbit API access is available.
"""

from __future__ import annotations

import os

from bench.schemas import ToolFinding
from bench.tools.common import BenchSample, ToolRunner


class CodeRabbitRunner(ToolRunner):
    name = "coderabbit"

    def is_available(self) -> bool:
        return bool(os.environ.get("CODERABBIT_API_KEY"))

    def run(self, sample: BenchSample) -> tuple[list[ToolFinding], float]:
        # TODO: implement when API access is available
        return [], 0.0
