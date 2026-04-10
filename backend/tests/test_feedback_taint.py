"""Tests for taint-pair suppression in FeedbackService.

Verifies that:
1. Taint pairs are not suppressed until the FP threshold is reached
2. After threshold, is_taint_pair_suppressed returns True
3. filter_taint_candidates removes suppressed pairs pre-triage
4. General finding suppressions are not affected by taint-pair FPs
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from app.services.feedback import _TAINT_PAIR_FP_THRESHOLD, FeedbackService

# ── Minimal stubs so we don't need Redis running ─────────────────────────────


class _FakeRedis:
    """Minimal in-memory Redis substitute."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._lists: dict[str, list[bytes]] = {}

    async def lpush(self, key: str, value: str) -> None:
        self._lists.setdefault(key, [])
        self._lists[key].insert(0, value.encode() if isinstance(value, str) else value)

    async def ltrim(self, key: str, start: int, end: int) -> None:
        lst = self._lists.get(key, [])
        self._lists[key] = lst[start : end + 1]

    async def lrange(self, key: str, start: int, end: int) -> list[bytes]:
        lst = self._lists.get(key, [])
        if end == -1:
            return lst[start:]
        return lst[start : end + 1]

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = value

    async def exists(self, key: str) -> int:
        return 1 if key in self._store else 0

    async def scan_iter(self, pattern: str):
        # Not needed for taint tests — yield nothing
        return
        yield  # make it an async generator


@dataclass
class _FakeSourceSpec:
    signature: str
    kind: MagicMock = None
    call_pattern: str = "request.args.get"
    attr_pattern: str | None = None


@dataclass
class _FakeSinkSpec:
    signature: str
    kind: MagicMock = None
    call_pattern: str = "cursor.execute"


@dataclass
class _FakeCandidate:
    source: _FakeSourceSpec
    sink: _FakeSinkSpec
    candidate_id: str = "cand-001"


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def redis() -> _FakeRedis:
    return _FakeRedis()


@pytest.fixture
def svc(redis: _FakeRedis) -> FeedbackService:
    return FeedbackService(redis)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_taint_pair_not_suppressed_initially(svc: FeedbackService) -> None:
    assert not await svc.is_taint_pair_suppressed("src-sig-aaa", "snk-sig-bbb")


@pytest.mark.asyncio
async def test_taint_pair_suppressed_after_threshold(svc: FeedbackService) -> None:
    src, snk = "src-sig-aaa", "snk-sig-bbb"

    for i in range(_TAINT_PAIR_FP_THRESHOLD):
        assert not await svc.is_taint_pair_suppressed(src, snk), (
            f"should not be suppressed after {i} reports"
        )
        await svc.record_taint_false_positive(src, snk, "python", f"cand-{i}")

    # After reaching threshold, the pair is suppressed
    assert await svc.is_taint_pair_suppressed(src, snk)


@pytest.mark.asyncio
async def test_taint_pair_suppression_is_specific(svc: FeedbackService) -> None:
    """Suppressing one pair must not suppress different pairs."""
    src_a, snk_a = "src-aaa", "snk-bbb"
    src_b, snk_b = "src-ccc", "snk-ddd"

    for i in range(_TAINT_PAIR_FP_THRESHOLD):
        await svc.record_taint_false_positive(src_a, snk_a, "python", f"cand-{i}")

    assert await svc.is_taint_pair_suppressed(src_a, snk_a)
    assert not await svc.is_taint_pair_suppressed(src_b, snk_b)


@pytest.mark.asyncio
async def test_filter_taint_candidates_removes_suppressed(svc: FeedbackService) -> None:
    src_sig, snk_sig = "src-111", "snk-222"

    # Suppress the pair
    for i in range(_TAINT_PAIR_FP_THRESHOLD):
        await svc.record_taint_false_positive(src_sig, snk_sig, "python", f"c-{i}")

    suppressed_candidate = _FakeCandidate(
        source=_FakeSourceSpec(signature=src_sig),
        sink=_FakeSinkSpec(signature=snk_sig),
        candidate_id="suppressed",
    )
    clean_candidate = _FakeCandidate(
        source=_FakeSourceSpec(signature="src-other"),
        sink=_FakeSinkSpec(signature="snk-other"),
        candidate_id="clean",
    )

    result = await svc.filter_taint_candidates([suppressed_candidate, clean_candidate])
    assert len(result) == 1
    assert result[0].candidate_id == "clean"


@pytest.mark.asyncio
async def test_filter_taint_candidates_passes_all_if_none_suppressed(svc: FeedbackService) -> None:
    candidates = [
        _FakeCandidate(
            source=_FakeSourceSpec(signature=f"src-{i}"),
            sink=_FakeSinkSpec(signature=f"snk-{i}"),
            candidate_id=f"cand-{i}",
        )
        for i in range(5)
    ]
    result = await svc.filter_taint_candidates(candidates)
    assert len(result) == 5


@pytest.mark.asyncio
async def test_general_suppression_unaffected_by_taint_fps(svc: FeedbackService) -> None:
    """Taint FP recording must not pollute the general suppression namespace."""
    for i in range(_TAINT_PAIR_FP_THRESHOLD):
        await svc.record_taint_false_positive("src-x", "snk-y", "python", f"c-{i}")

    # General suppression check should not find anything for unrelated category
    assert not await svc.is_suppressed("security", "SQL injection", "python")
