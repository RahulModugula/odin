"""LLM triage stage: reason about exploitability of taint candidates.

Architecture: QLCoder (ICSE 2025) — LLM evaluates pre-screened candidates
with structured JSON output, dramatically cutting false positives vs single-shot review.

Enhanced with Corrective RAG: low-confidence verdicts trigger additional
context fetching and re-triage (CRAG-inspired self-evaluation loop).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from app.dataflow.schemas import TaintCandidate, TriageVerdict

logger = logging.getLogger(__name__)

TRIAGE_CONFIDENCE_FLOOR = 0.6
CRAG_CONFIDENCE_THRESHOLD = 0.6
CRAG_MAX_RETRIAGE_ITERATIONS = 2

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
{extra_context}
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
  "reasoning": "step-by-step reasoning",
  "needs_more_context": true | false
}}

For fix_code: write ONLY the replacement code (e.g. the fixed version of the sink call),
not a prose explanation.
Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
"""


def _build_prompt(
    candidate: TaintCandidate,
    extra_context: str = "",
) -> str:
    cwe = _SINK_CWE.get(candidate.sink.kind.value, "CWE-unknown")
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
        extra_context=extra_context,
    )


def _parse_verdict(candidate_id: str, raw: str) -> TriageVerdict | None:
    try:
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
            needs_more_context=bool(data.get("needs_more_context", False)),
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        logger.warning("Failed to parse triage verdict for %s: %s", candidate_id, exc)
        return None


async def _fetch_callee_context(candidate: TaintCandidate) -> str:
    try:
        import app.graph_rag._store_ref as _ref

        store = _ref.store
        if store is None or not store.is_connected:
            return ""

        func_name = candidate.function_name
        if not func_name:
            return ""

        callees = await store.get_callees(func_name, depth=1)
        if not callees:
            return ""

        lines = ["\nCALLEE IMPLEMENTATIONS (fetched for additional context):\n"]
        for callee in callees[:3]:
            body = await store.get_symbol_body(callee.file_path, callee.name)
            if body:
                sig = callee.signature or callee.name
                lines.append(f"--- {sig} in {callee.file_path} ---")
                lines.append(body[:500])
                lines.append("")

        return "\n".join(lines)
    except Exception as e:
        logger.debug("crag context fetch failed", error=str(e))
        return ""


async def triage_candidate(candidate: TaintCandidate, llm: Any) -> TriageVerdict:
    prompt = _build_prompt(candidate)
    try:
        response = await llm.ainvoke(prompt)
        raw = response.content if hasattr(response, "content") else str(response)
        verdict = _parse_verdict(candidate.candidate_id, raw)
        if verdict:
            verdict = await _crag_retriage(candidate, verdict, llm)
            return verdict
    except Exception as exc:
        logger.warning("LLM triage failed for candidate %s: %s", candidate.candidate_id, exc)

    return TriageVerdict(
        candidate_id=candidate.candidate_id,
        exploitable=True,
        confidence=0.4,
        exploit_scenario="Taint path detected — manual review recommended.",
        suggested_sanitizer="Validate and sanitize all user-controlled input.",
        fix_code="",
        reasoning="LLM triage unavailable; conservative verdict applied.",
        needs_more_context=False,
    )


async def _crag_retriage(
    candidate: TaintCandidate,
    initial_verdict: TriageVerdict,
    llm: Any,
) -> TriageVerdict:
    if (
        not initial_verdict.needs_more_context
        and initial_verdict.confidence >= CRAG_CONFIDENCE_THRESHOLD
    ):
        return initial_verdict

    verdict = initial_verdict
    for iteration in range(CRAG_MAX_RETRIAGE_ITERATIONS):
        if verdict.confidence >= CRAG_CONFIDENCE_THRESHOLD and not verdict.needs_more_context:
            break

        extra_context = await _fetch_callee_context(candidate)
        if not extra_context:
            break

        logger.debug(
            "crag retriage",
            candidate_id=candidate.candidate_id,
            iteration=iteration + 1,
            confidence=verdict.confidence,
        )

        prompt = _build_prompt(candidate, extra_context)
        try:
            response = await llm.ainvoke(prompt)
            raw = response.content if hasattr(response, "content") else str(response)
            new_verdict = _parse_verdict(candidate.candidate_id, raw)
            if new_verdict:
                verdict = new_verdict
        except Exception as exc:
            logger.warning("crag retriage failed: %s", exc)
            break

    return verdict


def _group_by_pattern(
    candidates: list[TaintCandidate],
) -> dict[tuple[str, str], list[TaintCandidate]]:
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
    if not candidates:
        return []

    semaphore = asyncio.Semaphore(max_concurrency)

    async def bounded(c: TaintCandidate) -> TriageVerdict:
        async with semaphore:
            return await triage_candidate(c, llm)

    groups = _group_by_pattern(candidates)
    reps = {key: max(grp, key=lambda c: len(c.snippet)) for key, grp in groups.items()}

    rep_verdicts: dict[tuple[str, str], TriageVerdict] = dict(
        zip(
            reps.keys(),
            await asyncio.gather(*[bounded(rep) for rep in reps.values()]),
            strict=True,
        )
    )

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
                    "needs_more_context",
                )
            },
        )
        for c in candidates
    ]
