"""Public, no-auth demo endpoint at /api/demo/review.

Goal: let HN/Reddit visitors paste a code snippet and see Odin's review stream in
under 10 seconds, without forcing them to install anything. Rate-limited per IP.

Constraints enforced here (not trusted from the client):
    * request body (code) must be <= DEMO_MAX_BYTES
    * code must be <= DEMO_MAX_LOC lines
    * IP can make at most DEMO_RATE_LIMIT requests per DEMO_RATE_WINDOW seconds

Deploy separately from the authenticated backend (Render/Fly free tier is fine).
Set ``DEMO_ENABLED=true`` and ``DEMO_RATE_WINDOW=3600`` via env.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.agents.graph import review_graph
from app.config import settings
from app.models.enums import Language
from app.models.state import ReviewState

logger = structlog.get_logger()

demo_router = APIRouter()


# ── Demo limits (tune via env; defaults keep a free-tier host solvent) ────────

DEMO_MAX_BYTES: int = 50_000
DEMO_MAX_LOC: int = 500
DEMO_RATE_LIMIT: int = 5  # requests per window
DEMO_RATE_WINDOW: int = 3600  # 1 hour


class DemoReviewRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=DEMO_MAX_BYTES)
    language: Language = Language.PYTHON


# ── Rate limiting (Redis INCR + TTL) ──────────────────────────────────────────


def _client_ip(request: Request) -> str:
    """Best-effort client IP. Honors X-Forwarded-For if the server sits behind a proxy."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        # Take the left-most (original client) entry
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _check_rate_limit(request: Request) -> tuple[int, int]:
    """Enforce per-IP rate limit. Returns (remaining, reset_seconds).

    Raises HTTPException(429) when the IP has exceeded DEMO_RATE_LIMIT.
    Falls back to "allow" when Redis is unavailable (graceful degradation in dev).
    """
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        return DEMO_RATE_LIMIT, DEMO_RATE_WINDOW

    ip = _client_ip(request)
    key = f"demo:ratelimit:{ip}"

    try:
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, DEMO_RATE_WINDOW)
        ttl = await redis.ttl(key)
    except Exception as exc:
        logger.warning("demo rate-limit check failed", error=str(exc))
        return DEMO_RATE_LIMIT, DEMO_RATE_WINDOW

    remaining = max(0, DEMO_RATE_LIMIT - int(count))
    reset_seconds = max(0, int(ttl))
    if count > DEMO_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limited",
                "message": (
                    f"Demo limit is {DEMO_RATE_LIMIT} reviews per hour. "
                    f"Run Odin locally with `uvx odin-review review` — no rate limit."
                ),
                "reset_seconds": reset_seconds,
            },
            headers={
                "Retry-After": str(reset_seconds or DEMO_RATE_WINDOW),
                "X-RateLimit-Limit": str(DEMO_RATE_LIMIT),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_seconds),
            },
        )
    return remaining, reset_seconds


# ── Endpoint ──────────────────────────────────────────────────────────────────


@demo_router.post("/demo/review")
async def demo_review(
    request: Request,
    payload: DemoReviewRequest,
) -> StreamingResponse:
    """No-auth, rate-limited, size-capped streaming review for the public demo page.

    Returns Server-Sent Events identical to /api/review/stream so the same
    frontend code can render them.
    """
    loc = payload.code.count("\n") + 1
    if loc > DEMO_MAX_LOC:
        raise HTTPException(
            status_code=413,
            detail={
                "error": "too_large",
                "message": (
                    f"Demo caps snippets at {DEMO_MAX_LOC} lines (you sent {loc}). "
                    f"Run Odin locally with `uvx odin-review review` for full files."
                ),
                "line_count": loc,
                "max": DEMO_MAX_LOC,
            },
        )

    remaining, reset_seconds = await _check_rate_limit(request)

    review_id = str(uuid.uuid4())
    ip = _client_ip(request)
    logger.info(
        "demo review started",
        review_id=review_id,
        language=payload.language.value,
        loc=loc,
        client_ip=ip,
        remaining=remaining,
    )

    async def event_stream() -> AsyncIterator[str]:
        stream_state: ReviewState = {
            "code": payload.code,
            "language": payload.language.value,
            "ast_summary": "",
            "metrics": None,  # type: ignore[typeddict-item]
            "findings": [],
            "agent_outputs": [],
            "overall_score": 100,
            "summary": "",
            "codebase_context": "",
            "file_path": None,
        }

        start = time.perf_counter()
        yield "data: " + json.dumps({"type": "demo_start", "review_id": review_id}) + "\n\n"

        try:
            async for event in review_graph.astream_events(
                stream_state, config={"callbacks": []}, version="v2"
            ):
                kind = event.get("event", "")
                name = event.get("name", "")
                if kind != "on_chain_end":
                    continue

                data_obj: dict[str, Any] = event.get("data", {}).get("output", {}) or {}

                agent_names = (
                    "quality_agent",
                    "security_agent",
                    "docs_agent",
                    "dataflow_triage",
                    "run_rules",
                )
                if name in agent_names:
                    for finding in data_obj.get("findings", []):
                        f = finding.model_dump() if hasattr(finding, "model_dump") else finding
                        event_data = json.dumps({"type": "finding", "agent": name, "data": f})
                        yield f"data: {event_data}\n\n"
                elif name == "synthesize":
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    yield (
                        "data: "
                        + json.dumps(
                            {
                                "type": "complete",
                                "review_id": review_id,
                                "overall_score": data_obj.get("overall_score", 0),
                                "summary": data_obj.get("summary", ""),
                                "total_time_ms": round(elapsed_ms, 2),
                                "rate_limit": {
                                    "remaining": max(0, remaining - 1),
                                    "reset_seconds": reset_seconds,
                                },
                            }
                        )
                        + "\n\n"
                    )
        except Exception as exc:
            logger.exception("demo stream failed", review_id=review_id, error=str(exc))
            yield "data: " + json.dumps({"type": "error", "message": str(exc)[:200]}) + "\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-RateLimit-Limit": str(DEMO_RATE_LIMIT),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_seconds),
            "X-Review-ID": review_id,
        },
    )


@demo_router.get("/demo/limits")
async def demo_limits(request: Request) -> dict[str, object]:
    """Return current limits + remaining quota for this IP.

    Lets the frontend show "X/5 remaining, reset in Y min" without consuming quota.
    """
    redis = getattr(request.app.state, "redis", None)
    remaining = DEMO_RATE_LIMIT
    reset_seconds = 0
    if redis is not None:
        ip = _client_ip(request)
        try:
            count = int(await redis.get(f"demo:ratelimit:{ip}") or 0)
            ttl = int(await redis.ttl(f"demo:ratelimit:{ip}") or 0)
            remaining = max(0, DEMO_RATE_LIMIT - count)
            reset_seconds = max(0, ttl)
        except Exception:
            pass
    return {
        "max_bytes": DEMO_MAX_BYTES,
        "max_loc": DEMO_MAX_LOC,
        "rate_limit": DEMO_RATE_LIMIT,
        "rate_window_seconds": DEMO_RATE_WINDOW,
        "remaining": remaining,
        "reset_seconds": reset_seconds,
        "environment": settings.environment,
    }
