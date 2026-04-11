"""CodeQL tool runner — shells out to `codeql` CLI and parses SARIF output."""

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

# CodeQL language identifiers (used in `database create --language`)
_LANG_TO_CODEQL_LANG = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",  # CodeQL uses javascript extractor for TS
    "go": "go",
    "java": "java",
    "rust": None,  # CodeQL doesn't support Rust yet
}

# CodeQL query packs per language
_LANG_TO_PACK = {
    "python": "codeql/python-queries",
    "javascript": "codeql/javascript-queries",
    "typescript": "codeql/javascript-queries",
    "go": "codeql/go-queries",
    "java": "codeql/java-queries",
    "rust": None,  # CodeQL doesn't support Rust yet — skip gracefully
}

# SARIF severity → SeverityLevel
# CodeQL emits severity in result.properties["problem.severity"] or rule metadata
_SEVERITY_MAP = {
    "error": SeverityLevel.CRITICAL,
    "warning": SeverityLevel.HIGH,
    "recommendation": SeverityLevel.MEDIUM,
    "note": SeverityLevel.MEDIUM,
}


def _parse_sarif(sarif_data: dict, tool_name: str) -> list[ToolFinding]:
    """Extract ToolFinding objects from a SARIF document."""
    findings: list[ToolFinding] = []

    runs = sarif_data.get("runs", [])
    if not runs:
        return findings

    run = runs[0]

    # Build a rule-id → severity index from the run's tool rules
    rule_severity: dict[str, SeverityLevel] = {}
    tool_component = run.get("tool", {}).get("driver", {})
    for rule in tool_component.get("rules", []):
        rid = rule.get("id", "")
        # Severity lives under properties["problem.severity"] in CodeQL SARIF
        props = rule.get("properties", {})
        raw_sev = props.get("problem.severity", "warning").lower()
        rule_severity[rid] = _SEVERITY_MAP.get(raw_sev, SeverityLevel.HIGH)

    for result in run.get("results", []):
        rule_id: str | None = result.get("ruleId")
        message = result.get("message", {}).get("text", rule_id or "")

        # Prefer per-result severity when present; fall back to rule-level
        result_props = result.get("properties", {})
        raw_sev = result_props.get("problem.severity", "").lower()
        if raw_sev and raw_sev in _SEVERITY_MAP:
            severity = _SEVERITY_MAP[raw_sev]
        elif rule_id and rule_id in rule_severity:
            severity = rule_severity[rule_id]
        else:
            # CodeQL's top-level "level" field: error / warning / note
            level = result.get("level", "warning").lower()
            severity = _SEVERITY_MAP.get(level, SeverityLevel.HIGH)

        # Location
        line_start: int | None = None
        line_end: int | None = None
        locations = result.get("locations", [])
        if locations:
            phys = locations[0].get("physicalLocation", {})
            region = phys.get("region", {})
            line_start = region.get("startLine")
            line_end = region.get("endLine", line_start)

        findings.append(
            ToolFinding(
                tool=tool_name,
                rule_id=rule_id,
                title=message,
                severity=severity,
                line_start=line_start,
                line_end=line_end,
                category="security",
                confidence=1.0,
                raw=result,
            )
        )

    return findings


class CodeQLRunner(ToolRunner):
    """Runs CodeQL against a code sample via `codeql database create` + `database analyze`.

    Requires:
      - `codeql` CLI in PATH (https://github.com/github/codeql-cli-binaries)
      - Appropriate language query packs downloaded

    CodeQL does not support Rust; samples in that language are skipped gracefully.
    """

    name = "codeql"

    def is_available(self) -> bool:
        return shutil.which("codeql") is not None

    def run(self, sample: BenchSample) -> tuple[list[ToolFinding], float]:
        codeql_lang = _LANG_TO_CODEQL_LANG.get(sample.language)
        query_pack = _LANG_TO_PACK.get(sample.language)

        # Gracefully skip unsupported languages (e.g. Rust)
        if codeql_lang is None or query_pack is None:
            return [], 0.0

        ext = _LANG_TO_EXT.get(sample.language, ".txt")
        start = time.perf_counter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # CodeQL requires a source directory — write sample code there
            src_dir = tmp_path / "src"
            src_dir.mkdir()
            src_file = src_dir / f"sample{ext}"
            src_file.write_text(sample.code, encoding="utf-8")

            db_dir = tmp_path / "db"
            sarif_out = tmp_path / "results.sarif"

            try:
                # Step 1: create CodeQL database from source directory
                db_result = subprocess.run(
                    [
                        "codeql",
                        "database",
                        "create",
                        str(db_dir),
                        f"--language={codeql_lang}",
                        f"--source-root={src_dir}",
                        "--overwrite",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                if db_result.returncode != 0:
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    return [], elapsed_ms

                # Step 2: analyze using the appropriate query pack
                analyze_result = subprocess.run(
                    [
                        "codeql",
                        "database",
                        "analyze",
                        str(db_dir),
                        query_pack,
                        "--format=sarif-latest",
                        f"--output={sarif_out}",
                        "--no-print-diagnostics-summary",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000

                if analyze_result.returncode != 0:
                    return [], elapsed_ms

                if not sarif_out.exists():
                    return [], elapsed_ms

                sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
                findings = _parse_sarif(sarif_data, self.name)
                return findings, elapsed_ms

            except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
                elapsed_ms = (time.perf_counter() - start) * 1000
                return [], elapsed_ms
