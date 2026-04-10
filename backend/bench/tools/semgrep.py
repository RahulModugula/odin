"""Semgrep tool runner — shells out to `semgrep` CLI and parses JSON output."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from bench.schemas import SeverityLevel, ToolFinding
from bench.tools.common import BenchSample, ToolRunner

_LANG_TO_EXT = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "rust": ".rs",
    "java": ".java",
}

_SEVERITY_MAP = {
    "ERROR": SeverityLevel.CRITICAL,
    "WARNING": SeverityLevel.HIGH,
    "INFO": SeverityLevel.MEDIUM,
    "NOTE": SeverityLevel.LOW,
}


class SemgrepRunner(ToolRunner):
    """Runs `semgrep --config auto` against a code sample.

    Requires: semgrep installed (pip install semgrep or brew install semgrep)
    """

    name = "semgrep"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def run(self, sample: BenchSample) -> tuple[list[ToolFinding], float]:
        ext = _LANG_TO_EXT.get(sample.language, ".txt")

        with tempfile.NamedTemporaryFile(suffix=ext, mode="w", encoding="utf-8", delete=False) as f:
            f.write(sample.code)
            tmp_path = Path(f.name)

        start = time.perf_counter()
        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "--config", "auto",
                    "--json",
                    "--no-git-ignore",
                    "--quiet",
                    str(tmp_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

            if result.returncode not in (0, 1):
                return [], elapsed_ms

            data = json.loads(result.stdout or "{}")
            findings = []
            for r in data.get("results", []):
                sev_raw = r.get("extra", {}).get("severity", "INFO").upper()
                findings.append(ToolFinding(
                    tool=self.name,
                    rule_id=r.get("check_id"),
                    title=r.get("extra", {}).get("message", r.get("check_id", "")),
                    severity=_SEVERITY_MAP.get(sev_raw, SeverityLevel.MEDIUM),
                    line_start=r.get("start", {}).get("line"),
                    line_end=r.get("end", {}).get("line"),
                    category="security",
                    confidence=1.0,
                    raw=r,
                ))
            return findings, elapsed_ms

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            elapsed_ms = (time.perf_counter() - start) * 1000
            return [], elapsed_ms
        finally:
            tmp_path.unlink(missing_ok=True)
