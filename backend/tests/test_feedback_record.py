"""Tests for FeedbackService.record() and suppression listing."""

from __future__ import annotations

import fnmatch

import pytest

from app.services.feedback import FeedbackService


class _FakeRedis:
    """In-memory Redis stub with scan_iter support."""

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

    async def scan_iter(self, pattern: str):  # type: ignore[return]
        glob_pattern = pattern.replace("*", "*")  # identity — already glob
        for key in list(self._store.keys()):
            if fnmatch.fnmatch(key, glob_pattern):
                yield key.encode()


@pytest.fixture
def fake_redis() -> _FakeRedis:
    return _FakeRedis()


@pytest.fixture
def svc(fake_redis: _FakeRedis) -> FeedbackService:
    return FeedbackService(fake_redis)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_record_helpful_does_not_suppress(svc: FeedbackService) -> None:
    """'helpful' votes should not trigger suppression."""
    for _ in range(10):
        await svc.record("fid-1", "helpful", "security", "SQL injection", "python")
    assert not await svc.is_suppressed("security", "SQL injection", "python")


@pytest.mark.asyncio
async def test_record_false_positive_triggers_suppression(svc: FeedbackService) -> None:
    """3+ false_positive votes on the same finding fingerprint should suppress it."""
    from app.config import settings

    threshold = settings.feedback_general_threshold
    for i in range(threshold):
        await svc.record(f"fid-{i}", "false_positive", "security", "SQL injection", "python")

    assert await svc.is_suppressed("security", "SQL injection", "python")


@pytest.mark.asyncio
async def test_record_below_threshold_no_suppression(svc: FeedbackService) -> None:
    """Fewer than threshold FP votes should not suppress."""
    from app.config import settings

    threshold = settings.feedback_general_threshold
    for i in range(threshold - 1):
        await svc.record(f"fid-{i}", "false_positive", "security", "XSS", "javascript")

    assert not await svc.is_suppressed("security", "XSS", "javascript")


@pytest.mark.asyncio
async def test_get_suppressions_empty(svc: FeedbackService) -> None:
    result = await svc.get_suppressions()
    assert result == []


@pytest.mark.asyncio
async def test_get_suppressions_after_threshold(svc: FeedbackService) -> None:
    from app.config import settings

    for i in range(settings.feedback_general_threshold):
        await svc.record(f"fid-{i}", "false_positive", "security", "SSRF", "python")

    suppressions = await svc.get_suppressions()
    assert len(suppressions) == 1


@pytest.mark.asyncio
async def test_get_taint_suppressions_empty(svc: FeedbackService) -> None:
    result = await svc.get_taint_suppressions()
    assert result == []


@pytest.mark.asyncio
async def test_get_taint_suppressions_after_threshold(svc: FeedbackService) -> None:
    from app.services.feedback import _TAINT_PAIR_FP_THRESHOLD

    for i in range(_TAINT_PAIR_FP_THRESHOLD):
        await svc.record_taint_false_positive("src-abc", "snk-xyz", "python", f"c-{i}")

    taint_suppressions = await svc.get_taint_suppressions()
    assert len(taint_suppressions) == 1
    assert "src-abc:snk-xyz" in taint_suppressions[0]
