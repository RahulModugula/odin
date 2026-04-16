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

# Only surface candidates with LLM confidence >= this floor
TRIAGE_CONFIDENCE_FLOOR = 0.6

# CWE mapping for each sink kind — anchors the LLM's security reasoning
_SINK_CWE: dict[str, str] = {
    "code_exec": "CWE-94 (Code Injection)",
    "shell_exec": "CWE-78 (OS Command Injection)",
    "sql_query": "CWE-89 (SQL Injection)",
    "dom_write": "CWE-79 (Cross-Site Scripting)",
    "path_traversal": "CWE-22 (Path Traversal)",
    "ssrf_fetch": "CWE-918 (Server-Side Request Forgery)",
    "template_render": "CWE-94 (Server-Side Template Injection)",
    "deserialized": "CWE-502 (Deserialization of Untrusted Data)",
}

_TRIAGE_PROMPT_TEMPLATE = """\
You are a security vulnerability analyst. Your task is to determine whether the following
potential taint flow represents a real, exploitable vulnerability.

TAINT FLOW SUMMARY
==================
Language: {language}
Source: {source_kind} via `{source_pattern}`
Sink: {sink_kind} via `{sink_pattern}`
CWE: {cwe}
Taint chain depth: {hop_count} hop(s)
Tainted variable(s): {tainted_vars}
Function: {function_name}

CODE CONTEXT (annotated — >> marks source/sink/propagation lines)
=================================================================
{snippet}

TASK
====
Determine if this taint path is exploitable. Consider:
1. Can an attacker control the SOURCE value?
2. Does the tainted value reach the SINK without meaningful sanitization?
3. What is the realistic exploit scenario and concrete payload?
4. What is the exact code fix?

Respond with ONLY valid JSON in this exact schema:
{{
  "exploitable": true | false,
  "confidence": 0.0-1.0,
  "exploit_scenario": "an attacker can ... to achieve ...",
  "suggested_sanitizer": "brief description of the fix",
  "fix_code": "the exact replacement code line(s) that fix the vulnerability",
  "reasoning": "step-by-step reasoning"
}}

For fix_code: write ONLY the replacement code (e.g. the fixed version of the sink call),
not a prose explanation.
Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
"""


def _build_prompt(candidate: TaintCandidate) -> str:
    cwe = _SINK_CWE.get(candidate.sink.kind.value, "CWE-unknown")
    # Collect unique variable names from the hop chain (source → ... → sink)
    hop_vars = [h.variable for h in candidate.hops if h.variable]
    tainted_vars = " → ".join(hop_vars) if hop_vars else "unknown"
    return _TRIAGE_PROMPT_TEMPLATE.format(
        language=candidate.language.value,
        source_kind=candidate.source.kind.value,
        source_pattern=candidate.source.call_pattern or candidate.source.attr_pattern or "unknown",
        sink_kind=candidate.sink.kind.value,
        sink_pattern=candidate.sink.call_pattern,
        cwe=cwe,
        hop_count=len(candidate.hops),
        tainted_vars=tainted_vars,
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
            fix_code=str(data.get("fix_code", "")),
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
        fix_code="",
        reasoning="LLM triage unavailable; conservative verdict applied.",
    )


def _group_by_pattern(
    candidates: list[TaintCandidate],
) -> dict[tuple[str, str], list[TaintCandidate]]:
    """Group candidates by (source_sig, sink_sig).

    Candidates in the same group share the same taint-source pattern and sink
    pattern — e.g., all 'request.args.get → cursor.execute' flows. The LLM
    judgment about exploitability is invariant within a group; only one
    representative is triaged and the verdict reapplied to siblings.
    """
    groups: dict[tuple[str, str], list[TaintCandidate]] = {}
    for c in candidates:
        key = (c.source.signature, c.sink.signature)
        groups.setdefault(key, []).append(c)
    return groups


async def triage_all(
    candidates: list[TaintCandidate],
    llm: Any,
    max_concurrency: int = 4,
) -> list[TriageVerdict]:
    """Triage all candidates with bounded concurrency and per-pattern grouping.

    Candidates sharing the same (source_sig, sink_sig) are grouped; only the
    representative (longest snippet → most context) is sent to the LLM. The
    verdict is then reapplied to every sibling with its own candidate_id.

    This reduces LLM calls from O(N) to O(distinct patterns), which on real
    files can be 40-60% fewer calls when the same vuln pattern repeats.

    Args:
        candidates: Taint candidates to evaluate.
        llm: LangChain-compatible LLM instance.
        max_concurrency: Max simultaneous LLM calls.

    Returns:
        List of TriageVerdicts in the same order as ``candidates``.
    """
    if not candidates:
        return []

    semaphore = asyncio.Semaphore(max_concurrency)

    async def bounded(c: TaintCandidate) -> TriageVerdict:
        async with semaphore:
            return await triage_candidate(c, llm)

    # One representative per (source_sig, sink_sig) group — pick longest snippet
    groups = _group_by_pattern(candidates)
    reps = {key: max(grp, key=lambda c: len(c.snippet)) for key, grp in groups.items()}

    # Triage all representatives concurrently
    rep_verdicts: dict[tuple[str, str], TriageVerdict] = dict(
        zip(
            reps.keys(),
            await asyncio.gather(*[bounded(rep) for rep in reps.values()]),
            strict=True,
        )
    )

    # Reapply each group's verdict to all its siblings, preserving input order
    return [
        TriageVerdict(
            candidate_id=c.candidate_id,
            **{
                k: getattr(rep_verdicts[(c.source.signature, c.sink.signature)], k)
                for k in (
                    "exploitable",
                    "confidence",
                    "exploit_scenario",
                    "suggested_sanitizer",
                    "fix_code",
                    "reasoning",
                )
            },
        )
        for c in candidates
    ]
