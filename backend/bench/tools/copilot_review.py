"""GitHub Copilot Review adapter — calls the Copilot code review API.

Requires: COPILOT_REVIEW_TOKEN environment variable.
Currently a stub — fill in when API access is available.
"""

from __future__ import annotations

import os

from bench.schemas import ToolFinding
from bench.tools.common import BenchSample, ToolRunner


class CopilotReviewRunner(ToolRunner):
    name = "copilot-review"

    def is_available(self) -> bool:
        return bool(os.environ.get("COPILOT_REVIEW_TOKEN"))

    def run(self, sample: BenchSample) -> tuple[list[ToolFinding], float]:
        # TODO: implement when API access is available
        return [], 0.0
