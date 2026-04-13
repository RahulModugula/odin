"""Greptile API benchmark runner.

Greptile (https://www.greptile.com) offers semantic code search and AI-powered
code review via their API. Their native use case is querying across an indexed
repository, but their /query endpoint also accepts inline code context — which
is what we use here for snippet-level evaluation.

Authentication:
  Set GREPTILE_API_KEY in your environment. Optionally set GREPTILE_GITHUB_TOKEN
  for requests that require a GitHub identity header (Greptile's API passes it
  through to GitHub for auth purposes).

Methodology note:
  Snippet-only evaluation under-uses Greptile's full power (repo-wide context),
  so results here are a *floor* on their real-world performance. We disclose
  this in the methodology section. The honest comparison is Odin vs Greptile on
  the same isolated snippet — not a full-repo review.

API reference: https://docs.greptile.com/api-reference/query (v2)
"""

from __future__ import annotations

import json
import os
import time

from bench.schemas import SeverityLevel, ToolFinding
from bench.tools.common import BenchSample, ToolRunner

_API_BASE = "https://api.greptile.com/v2"

# Map Greptile severity keywords to our SeverityLevel enum
_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
    "informational": SeverityLevel.INFO,
}

_SYSTEM_PROMPT = """\
You are a senior security engineer reviewing a code snippet for vulnerabilities.
Analyse the code carefully. For each issue found, respond with a JSON array of
objects with these fields:
  - rule_id: short identifier (e.g. "sqli", "xss", "hardcoded-secret")
  - title: one-sentence description of the issue
  - severity: one of critical / high / medium / low / info
  - line_start: line number where the issue starts (1-indexed, or null)
  - line_end: line number where the issue ends (or null)
  - category: one of security / quality / style / performance

If there are no issues, respond with an empty array: []
Respond with ONLY the JSON array — no prose, no markdown fences.
"""


def _extract_findings(response_text: str, tool_name: str) -> list[ToolFinding]:
    """Parse Greptile's response text into ToolFinding objects.

    Greptile returns free-form text; we ask it to emit JSON and parse that.
    Falls back gracefully if the model doesn't comply.
    """
    text = response_text.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop first and last line (``` / ```json / ```)
        text = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])

    try:
        items = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Heuristic: if any security-related keyword appears in the response,
        # treat it as a finding with unknown details.
        security_keywords = [
            "injection", "vulnerability", "insecure", "exploit", "attack",
            "overflow", "traversal", "ssrf", "xss", "rce",
        ]
        if any(kw in response_text.lower() for kw in security_keywords):
            return [
                ToolFinding(
                    tool=tool_name,
                    rule_id="greptile-finding",
                    title=response_text[:200],
                    severity=SeverityLevel.HIGH,
                    line_start=None,
                    line_end=None,
                    category="security",
                    confidence=0.5,
                    raw={"raw_response": response_text},
                )
            ]
        return []

    if not isinstance(items, list):
        return []

    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_sev = str(item.get("severity", "medium")).lower()
        severity = _SEVERITY_MAP.get(raw_sev, SeverityLevel.MEDIUM)
        findings.append(
            ToolFinding(
                tool=tool_name,
                rule_id=item.get("rule_id") or "greptile-finding",
                title=item.get("title", "Issue detected"),
                severity=severity,
                line_start=item.get("line_start"),
                line_end=item.get("line_end"),
                category=item.get("category", "security"),
                confidence=0.7,  # AI-based — moderate confidence
                raw=item,
            )
        )
    return findings


class GreptileRunner(ToolRunner):
    """Calls the Greptile /v2/query endpoint with the code snippet as inline context.

    Limitation: Greptile is optimised for whole-repository analysis. Snippet-only
    results are a floor estimate. See module docstring for full methodology note.
    """

    name = "greptile"

    def is_available(self) -> bool:
        return bool(os.environ.get("GREPTILE_API_KEY"))

    def run(self, sample: BenchSample) -> tuple[list[ToolFinding], float]:
        import httpx

        api_key = os.environ.get("GREPTILE_API_KEY", "")
        github_token = os.environ.get("GREPTILE_GITHUB_TOKEN", "")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if github_token:
            headers["X-Github-Token"] = github_token

        # Build the query: inline the code as context with no indexed repo
        query_payload = {
            "messages": [
                {
                    "id": "system-1",
                    "content": _SYSTEM_PROMPT,
                    "role": "system",
                },
                {
                    "id": "user-1",
                    "content": (
                        f"Language: {sample.language}\n\n"
                        f"```{sample.language}\n{sample.code}\n```"
                    ),
                    "role": "user",
                },
            ],
            # No repositories list — snippet-only mode
            "repositories": [],
            "sessionId": sample.id,
            "stream": False,
        }

        start = time.perf_counter()
        try:
            with httpx.Client(timeout=60.0) as client:
                resp = client.post(
                    f"{_API_BASE}/query",
                    headers=headers,
                    json=query_payload,
                )
            elapsed_ms = (time.perf_counter() - start) * 1000

            if resp.status_code != 200:
                return [], elapsed_ms

            data = resp.json()
            # Greptile returns {"message": "<response text>", ...}
            response_text = data.get("message", "")
            findings = _extract_findings(response_text, self.name)
            return findings, elapsed_ms

        except Exception:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return [], elapsed_ms
