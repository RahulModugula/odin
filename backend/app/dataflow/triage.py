"""LLM triage stage: reason about exploitability of taint candidates.

Architecture: QLCoder (ICSE 2025) — LLM evaluates pre-screened candidates
with structured JSON output, dramatically cutting false positives vs single-shot review.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from app.dataflow.schemas import TaintCandidate, TriageVerdict

logger = logging.getLogger(__name__)

# Only triage candidates with LLM if confidence floor is met
TRIAGE_CONFIDENCE_FLOOR = 0.6

_TRIAGE_PROMPT_TEMPLATE = """\
You are a security vulnerability analyst. Your task is to determine whether the following
potential taint flow represents a real, exploitable vulnerability.

TAINT FLOW SUMMARY
==================
Language: {language}
Source: {source_kind} via `{source_pattern}`
Sink: {sink_kind} via `{sink_pattern}`
Function: {function_name}

CODE CONTEXT (annotated — >> marks source/sink lines)
====================================================
{snippet}

TASK
====
Determine if this taint path is exploitable. Consider:
1. Can an attacker control the SOURCE value?
2. Does the tainted value reach the SINK without meaningful sanitization?
3. What is the realistic exploit scenario?
4. What is the appropriate sanitizer/fix?

Respond with ONLY valid JSON in this exact schema:
{{
  "exploitable": true | false,
  "confidence": 0.0-1.0,
  "exploit_scenario": "an attacker can ... to achieve ...",
  "suggested_sanitizer": "use ... to sanitize",
  "reasoning": "step-by-step reasoning"
}}
"""


def _build_prompt(candidate: TaintCandidate) -> str:
    return _TRIAGE_PROMPT_TEMPLATE.format(
        language=candidate.language.value,
        source_kind=candidate.source.kind.value,
        source_pattern=candidate.source.call_pattern or candidate.source.attr_pattern or "unknown",
        sink_kind=candidate.sink.kind.value,
        sink_pattern=candidate.sink.call_pattern,
        function_name=candidate.function_name or "unknown",
        snippet=candidate.snippet,
    )


def _parse_verdict(candidate_id: str, raw: str) -> TriageVerdict | None:
    """Parse LLM JSON output into a TriageVerdict."""
    try:
        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
        data: dict[str, Any] = json.loads(text)
        return TriageVerdict(
            candidate_id=candidate_id,
            exploitable=bool(data.get("exploitable", False)),
            confidence=min(1.0, max(0.0, float(data.get("confidence", 0.5)))),
            exploit_scenario=str(data.get("exploit_scenario", "")),
            suggested_sanitizer=str(data.get("suggested_sanitizer", "")),
            reasoning=str(data.get("reasoning", "")),
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        logger.warning("Failed to parse triage verdict for %s: %s", candidate_id, exc)
        return None


async def triage_candidate(candidate: TaintCandidate, llm: Any) -> TriageVerdict:
    """Ask the LLM to judge one TaintCandidate. Returns a TriageVerdict."""
    prompt = _build_prompt(candidate)
    try:
        response = await llm.ainvoke(prompt)
        raw = response.content if hasattr(response, "content") else str(response)
        verdict = _parse_verdict(candidate.candidate_id, raw)
        if verdict:
            return verdict
    except Exception as exc:
        logger.warning("LLM triage failed for candidate %s: %s", candidate.candidate_id, exc)

    # Fallback: conservative verdict (don't suppress — surface as LOW)
    return TriageVerdict(
        candidate_id=candidate.candidate_id,
        exploitable=True,
        confidence=0.4,
        exploit_scenario="Taint path detected — manual review recommended.",
        suggested_sanitizer="Validate and sanitize all user-controlled input.",
        reasoning="LLM triage unavailable; conservative verdict applied.",
    )


async def triage_all(
    candidates: list[TaintCandidate],
    llm: Any,
    max_concurrency: int = 4,
) -> list[TriageVerdict]:
    """Triage all candidates with bounded concurrency.

    Args:
        candidates: List of taint candidates to evaluate.
        llm: LangChain-compatible LLM instance.
        max_concurrency: Max simultaneous LLM calls.

    Returns:
        List of TriageVerdicts, one per candidate.
    """
    if not candidates:
        return []

    semaphore = asyncio.Semaphore(max_concurrency)

    async def bounded_triage(c: TaintCandidate) -> TriageVerdict:
        async with semaphore:
            return await triage_candidate(c, llm)

    return list(await asyncio.gather(*[bounded_triage(c) for c in candidates]))
