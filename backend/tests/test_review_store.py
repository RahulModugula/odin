"""Tests for ReviewStore — covers save/get/list_recent/delete."""

from __future__ import annotations

import pytest

from app.services.review_store import ReviewStore


class _FakeRedis:
    """In-memory Redis stub for ReviewStore."""

    def __init__(self) -> None:
        self._kv: dict[str, str] = {}
        self._zsets: dict[str, dict[str, float]] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._kv[key] = value

    async def get(self, key: str) -> bytes | None:
        val = self._kv.get(key)
        return val.encode() if val is not None else None

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self._zsets.setdefault(key, {}).update(mapping)

    async def expire(self, key: str, ttl: int) -> None:
        pass  # not needed for tests

    async def zrevrange(self, key: str, start: int, end: int) -> list[bytes]:
        zset = self._zsets.get(key, {})
        sorted_ids = sorted(zset, key=lambda k: zset[k], reverse=True)
        if end == -1:
            return [s.encode() for s in sorted_ids[start:]]
        return [s.encode() for s in sorted_ids[start : end + 1]]

    async def delete(self, *keys: str) -> None:
        for key in keys:
            self._kv.pop(key, None)

    async def zrem(self, key: str, *members: str) -> None:
        zset = self._zsets.get(key, {})
        for m in members:
            zset.pop(m, None)


@pytest.fixture
def fake_redis() -> _FakeRedis:
    return _FakeRedis()


@pytest.fixture
def store(fake_redis: _FakeRedis) -> ReviewStore:
    return ReviewStore(fake_redis)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_save_and_get(store: ReviewStore) -> None:
    data = {"overall_score": 85, "findings": [], "summary": "looks good"}
    await store.save("rev-001", data)
    result = await store.get("rev-001")
    assert result is not None
    assert result["overall_score"] == 85
    assert result["summary"] == "looks good"
    assert "saved_at" in result  # timestamp added by save()


@pytest.mark.asyncio
async def test_get_missing_returns_none(store: ReviewStore) -> None:
    result = await store.get("nonexistent-id")
    assert result is None


@pytest.mark.asyncio
async def test_list_recent_ordered(store: ReviewStore) -> None:
    for i in range(3):
        await store.save(f"rev-{i}", {"score": i})
    results = await store.list_recent(limit=10)
    assert len(results) == 3
    # Most recently saved is first (zrevrange sorts by timestamp desc)
    scores = [r["score"] for r in results]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_list_recent_limit(store: ReviewStore) -> None:
    for i in range(5):
        await store.save(f"rev-{i}", {"idx": i})
    results = await store.list_recent(limit=2)
    assert len(results) == 2


@pytest.mark.asyncio
async def test_list_recent_offset(store: ReviewStore) -> None:
    for i in range(4):
        await store.save(f"rev-{i}", {"idx": i})
    all_results = await store.list_recent(limit=10)
    offset_results = await store.list_recent(limit=10, offset=2)
    assert len(offset_results) == 2
    assert offset_results == all_results[2:]


@pytest.mark.asyncio
async def test_delete(store: ReviewStore) -> None:
    await store.save("rev-del", {"score": 50})
    assert await store.get("rev-del") is not None
    await store.delete("rev-del")
    assert await store.get("rev-del") is None
    # Index should no longer include it
    results = await store.list_recent(limit=10)
    assert len(results) == 0
