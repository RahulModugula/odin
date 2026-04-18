"""Tests for the public demo endpoint: size caps + rate limiting + enable flag."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.demo import (
    DEMO_MAX_LOC,
    DEMO_RATE_LIMIT,
    DEMO_RATE_WINDOW,
    demo_router,
)


class FakeRedis:
    """Minimal redis stub that implements the three methods _check_rate_limit uses."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.ttls: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def expire(self, key: str, seconds: int) -> bool:
        self.ttls[key] = seconds
        return True

    async def ttl(self, key: str) -> int:
        return self.ttls.get(key, -1)

    async def get(self, key: str) -> bytes | None:
        if key not in self.counts:
            return None
        return str(self.counts[key]).encode()


@pytest.fixture
def demo_app() -> FastAPI:
    """Minimal FastAPI app that mounts only the demo router."""
    a = FastAPI()
    a.include_router(demo_router, prefix="/api")
    a.state.redis = FakeRedis()
    return a


def test_demo_rejects_oversized_line_count(demo_app: FastAPI) -> None:
    client = TestClient(demo_app)
    code = "x = 1\n" * (DEMO_MAX_LOC + 1)
    resp = client.post("/api/demo/review", json={"code": code, "language": "python"})
    assert resp.status_code == 413
    body = resp.json()
    assert body["detail"]["error"] == "too_large"
    assert body["detail"]["line_count"] > DEMO_MAX_LOC


def test_demo_rate_limit_enforced(demo_app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> None:
    """After DEMO_RATE_LIMIT successful requests, the next one returns 429."""

    # Stub out the LangGraph invocation so we don't exercise the real pipeline.
    async def _empty_stream(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        if False:
            yield  # pragma: no cover — generator signature only

    monkeypatch.setattr("app.api.demo.review_graph.astream_events", _empty_stream)

    client = TestClient(demo_app)
    for i in range(DEMO_RATE_LIMIT):
        resp = client.post(
            "/api/demo/review",
            json={"code": "x = 1", "language": "python"},
        )
        assert resp.status_code == 200, f"request {i + 1} should succeed"

    # Next one is over budget
    resp = client.post("/api/demo/review", json={"code": "x = 1", "language": "python"})
    assert resp.status_code == 429
    body = resp.json()
    assert body["detail"]["error"] == "rate_limited"
    assert "Retry-After" in resp.headers
    assert resp.headers["X-RateLimit-Remaining"] == "0"


def test_demo_limits_endpoint(demo_app: FastAPI) -> None:
    client = TestClient(demo_app)
    resp = client.get("/api/demo/limits")
    assert resp.status_code == 200
    body = resp.json()
    assert body["rate_limit"] == DEMO_RATE_LIMIT
    assert body["rate_window_seconds"] == DEMO_RATE_WINDOW
    assert body["max_loc"] == DEMO_MAX_LOC
    assert body["remaining"] == DEMO_RATE_LIMIT


def test_demo_not_mounted_by_default() -> None:
    """Without DEMO_ENABLED, the router must not be reachable from the production app."""
    from app.main import app as production_app

    tc = TestClient(production_app)
    resp = tc.get("/api/demo/limits")
    assert resp.status_code == 404


def test_demo_rate_limit_degrades_gracefully_without_redis() -> None:
    """When Redis is unavailable we fall back to allow (no 429)."""
    a = FastAPI()
    a.include_router(demo_router, prefix="/api")
    a.state.redis = None

    # Stub out the graph so the test doesn't hit real LLMs.
    async def _empty_stream(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        if False:
            yield

    import app.api.demo as demo_mod

    orig = demo_mod.review_graph
    demo_mod.review_graph = AsyncMock()  # type: ignore[assignment]
    demo_mod.review_graph.astream_events = _empty_stream  # type: ignore[attr-defined]
    try:
        client = TestClient(a)
        # Should succeed — even many times — without redis
        for _ in range(DEMO_RATE_LIMIT + 2):
            resp = client.post(
                "/api/demo/review",
                json={"code": "x = 1", "language": "python"},
            )
            assert resp.status_code == 200
    finally:
        demo_mod.review_graph = orig  # type: ignore[assignment]
