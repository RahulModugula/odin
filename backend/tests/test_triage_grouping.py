"""Tests for candidate grouping in triage_all().

Spec §2.4: group by (source_sig, sink_sig), triage one representative per group,
reapply the verdict to all siblings.  This cuts LLM calls from O(N) to
O(distinct patterns) — typically 40-60% fewer calls on real files.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from app.dataflow.schemas import SinkKind, SourceKind, TaintCandidate, TriageVerdict
from app.dataflow.triage import triage_all

# ── Helpers ───────────────────────────────────────────────────────────────────


def _verdict_json(exploitable: bool = True, confidence: float = 0.85) -> str:
    return (
        f'{{"exploitable": {str(exploitable).lower()}, "confidence": {confidence}, '
        f'"exploit_scenario": "attacker can inject", '
        f'"suggested_sanitizer": "use parameterized queries", '
        f'"reasoning": "taint flows unsanitized"}}'
    )


def _make_llm(response_json: str) -> MagicMock:
    """Build a mock LLM whose ainvoke always returns the given JSON."""
    resp = MagicMock()
    resp.content = response_json
    llm = MagicMock()
    llm.ainvoke = AsyncMock(return_value=resp)
    return llm


def _make_candidate(
    candidate_id: str,
    source_sig: str = "src_aaa",
    sink_sig: str = "snk_bbb",
    snippet: str = "x" * 50,
) -> TaintCandidate:
    """Build a minimal TaintCandidate stub for grouping tests."""
    from app.models.enums import Language

    source = MagicMock()
    source.signature = source_sig
    source.kind = SourceKind.HTTP_PARAM
    source.call_pattern = "request.args.get"
    source.attr_pattern = None

    sink = MagicMock()
    sink.signature = sink_sig
    sink.kind = SinkKind.SQL_QUERY
    sink.call_pattern = ".execute("

    candidate = MagicMock(spec=TaintCandidate)
    candidate.candidate_id = candidate_id
    candidate.source = source
    candidate.sink = sink
    candidate.hops = []
    candidate.snippet = snippet
    candidate.language = Language.PYTHON
    candidate.function_name = "test_func"
    return candidate


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_grouping_reduces_llm_calls() -> None:
    """5 candidates with identical source/sink pattern → 1 LLM call."""
    candidates = [
        _make_candidate(f"cand-{i}", source_sig="src-A", sink_sig="snk-B")
        for i in range(5)
    ]
    llm = _make_llm(_verdict_json())
    verdicts = asyncio.get_event_loop().run_until_complete(triage_all(candidates, llm))
    assert llm.ainvoke.call_count == 1, (
        f"Expected 1 LLM call for 5 same-pattern candidates, got {llm.ainvoke.call_count}"
    )
    assert len(verdicts) == 5


def test_grouping_verdict_applied_to_all_siblings() -> None:
    """All 3 siblings must carry the representative's exploitable/confidence values."""
    candidates = [
        _make_candidate(f"cand-{i}", source_sig="src-A", sink_sig="snk-B")
        for i in range(3)
    ]
    llm = _make_llm(_verdict_json(exploitable=True, confidence=0.91))
    verdicts = asyncio.get_event_loop().run_until_complete(triage_all(candidates, llm))
    assert all(v.exploitable for v in verdicts)
    assert all(abs(v.confidence - 0.91) < 0.001 for v in verdicts)


def test_grouping_candidate_ids_preserved() -> None:
    """Each returned verdict must carry its own candidate_id, not the representative's."""
    candidates = [
        _make_candidate(f"id-{i}", source_sig="src-A", sink_sig="snk-B")
        for i in range(4)
    ]
    llm = _make_llm(_verdict_json())
    verdicts = asyncio.get_event_loop().run_until_complete(triage_all(candidates, llm))
    result_ids = {v.candidate_id for v in verdicts}
    expected_ids = {f"id-{i}" for i in range(4)}
    assert result_ids == expected_ids


def test_distinct_groups_get_distinct_llm_calls() -> None:
    """3 candidates of pattern A + 2 of pattern B → exactly 2 LLM calls."""
    group_a = [
        _make_candidate(f"a-{i}", source_sig="src-A", sink_sig="snk-A") for i in range(3)
    ]
    group_b = [
        _make_candidate(f"b-{i}", source_sig="src-B", sink_sig="snk-B") for i in range(2)
    ]
    llm = _make_llm(_verdict_json())
    verdicts = asyncio.get_event_loop().run_until_complete(triage_all(group_a + group_b, llm))
    assert llm.ainvoke.call_count == 2
    assert len(verdicts) == 5


def test_representative_is_longest_snippet() -> None:
    """The candidate with the longest snippet must be sent to the LLM."""
    short = _make_candidate("short", snippet="x" * 20)
    long_ = _make_candidate("long", snippet="y" * 200)
    medium = _make_candidate("med", snippet="z" * 100)

    captured: list[str] = []

    async def capture(prompt: str) -> MagicMock:
        captured.append(prompt)
        resp = MagicMock()
        resp.content = _verdict_json()
        return resp

    llm = MagicMock()
    llm.ainvoke = capture

    asyncio.get_event_loop().run_until_complete(triage_all([short, long_, medium], llm))
    assert len(captured) == 1, "Expected exactly 1 LLM call for 3 same-pattern candidates"
    # The longest snippet (200 'y' chars) must appear in the prompt sent to the LLM
    assert "y" * 200 in captured[0], "Representative must be the candidate with longest snippet"


def test_triage_all_empty_input() -> None:
    """Empty candidate list must return [] without calling the LLM."""
    llm = _make_llm(_verdict_json())
    verdicts = asyncio.get_event_loop().run_until_complete(triage_all([], llm))
    assert verdicts == []
    llm.ainvoke.assert_not_called()


def test_grouping_preserves_original_order() -> None:
    """Returned verdicts must be in the same order as the input candidates."""
    # Interleave two patterns so order within a group is non-trivial
    candidates = [
        _make_candidate(f"c-{i}", source_sig=f"src-{i % 2}", sink_sig="snk-X")
        for i in range(6)
    ]
    llm = _make_llm(_verdict_json())
    verdicts = asyncio.get_event_loop().run_until_complete(triage_all(candidates, llm))
    for i, (c, v) in enumerate(zip(candidates, verdicts)):
        assert v.candidate_id == c.candidate_id, (
            f"Order mismatch at index {i}: expected {c.candidate_id}, got {v.candidate_id}"
        )


def test_single_candidate_still_works() -> None:
    """A single candidate must be triaged normally with 1 LLM call."""
    candidates = [_make_candidate("only-one")]
    llm = _make_llm(_verdict_json(exploitable=False, confidence=0.3))
    verdicts = asyncio.get_event_loop().run_until_complete(triage_all(candidates, llm))
    assert len(verdicts) == 1
    assert verdicts[0].candidate_id == "only-one"
    assert not verdicts[0].exploitable
    llm.ainvoke.assert_called_once()
