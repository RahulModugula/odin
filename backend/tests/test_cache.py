from unittest.mock import AsyncMock

import pytest

from app.models.enums import Language
from app.models.schemas import CodeMetrics, ReviewResult
from app.services.cache import CacheService


def _make_metrics() -> CodeMetrics:
    return CodeMetrics(
        lines_of_code=10,
        num_functions=1,
        num_classes=0,
        avg_function_length=5.0,
        max_function_length=5,
        max_nesting_depth=1,
        cyclomatic_complexity=1,
        comment_ratio=0.1,
        import_count=1,
    )


def _make_result() -> ReviewResult:
    return ReviewResult(
        metrics=_make_metrics(),
        findings=[],
        overall_score=95,
        summary="Looks good",
        language=Language.PYTHON,
    )


@pytest.mark.asyncio
async def test_cache_miss_returns_none() -> None:
    """Cache miss should return None."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    cache = CacheService(redis=mock_redis)
    result = await cache.get("def foo(): pass", "python")

    assert result is None
    mock_redis.get.assert_called_once()


@pytest.mark.asyncio
async def test_cache_hit_returns_cached_result() -> None:
    """Cache hit should return the cached ReviewResult with cached=True."""
    original = _make_result()
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=original.model_dump_json().encode())

    cache = CacheService(redis=mock_redis)
    result = await cache.get("def foo(): pass", "python")

    assert result is not None
    assert result.cached is True
    assert result.overall_score == 95
    assert result.language == Language.PYTHON


@pytest.mark.asyncio
async def test_cache_set_stores_result() -> None:
    """Cache set should store the serialized result with TTL."""
    mock_redis = AsyncMock()
    mock_redis.set = AsyncMock()

    cache = CacheService(redis=mock_redis)
    result = _make_result()
    await cache.set("def foo(): pass", "python", result)

    mock_redis.set.assert_called_once()
    call_args = mock_redis.set.call_args
    assert call_args.kwargs.get("ex") == 3600 or call_args[2] == 3600


def test_cache_key_is_deterministic() -> None:
    """Same code and language should produce the same cache key."""
    mock_redis = AsyncMock()
    cache = CacheService(redis=mock_redis)

    key1 = cache._make_key("def foo(): pass", "python")
    key2 = cache._make_key("def foo(): pass", "python")
    key3 = cache._make_key("def bar(): pass", "python")

    assert key1 == key2
    assert key1 != key3
    assert key1.startswith("review:")
