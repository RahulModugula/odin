from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from app.agents.graph import review_graph
from app.agents.llm import test_provider
from app.config import settings
from app.models.enums import Language
from app.models.schemas import ReviewRequest, ReviewResult
from app.models.state import ReviewState
from app.observability.tracing import create_langfuse_handler
from app.parsers.languages import supported_languages
from app.services.provider_registry import get_active_provider, list_providers

logger = structlog.get_logger()
router = APIRouter()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "version": "0.1.0",
        "supported_languages": supported_languages(),
    }


# ---------------------------------------------------------------------------
# Settings / provider endpoints
# ---------------------------------------------------------------------------


@router.get("/settings")
async def get_settings() -> dict[str, object]:
    """Return current provider configuration (API keys are never exposed)."""
    provider = get_active_provider()
    return {
        "provider": provider.name,
        "base_url": provider.base_url,
        "model": provider.model,
        "description": provider.description,
    }


@router.get("/settings/providers")
async def get_providers() -> list[dict[str, object]]:
    """List all preset provider configurations."""
    return [
        {
            "name": p.name,
            "base_url": p.base_url,
            "model": p.model,
            "description": p.description,
        }
        for p in list_providers()
    ]


@router.post("/settings/providers/{name}/test")
async def test_named_provider(name: str) -> dict[str, object]:
    """Test connectivity with a named provider."""
    ok = await test_provider(name)
    return {"provider": name, "ok": ok}


# ---------------------------------------------------------------------------
# Cache helpers (graceful Redis access)
# ---------------------------------------------------------------------------


async def _try_cache_get(code: str, language: str) -> ReviewResult | None:
    """Return a cached ReviewResult if Redis is available, else None."""
    try:
        from redis.asyncio import Redis

        from app.config import settings
        from app.services.cache import CacheService

        redis: Redis = Redis.from_url(settings.redis_url, decode_responses=False)
        cache = CacheService(redis)
        result = await cache.get(code, language)
        await redis.aclose()
        return result
    except Exception:
        return None


async def _try_cache_set(code: str, language: str, result: ReviewResult) -> None:
    """Store a ReviewResult in Redis if available; fail silently."""
    try:
        from redis.asyncio import Redis

        from app.config import settings
        from app.services.cache import CacheService

        redis: Redis = Redis.from_url(settings.redis_url, decode_responses=False)
        cache = CacheService(redis)
        cache.ttl = settings.review_store_ttl
        await cache.set(code, language, result)
        await redis.aclose()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Review (non-streaming)
# ---------------------------------------------------------------------------


@router.post("/review")
async def create_review(request: ReviewRequest) -> JSONResponse:
    start = time.perf_counter()
    review_id = str(uuid.uuid4())

    # --- cache check ---
    cached = await _try_cache_get(request.code, request.language.value)
    if cached is not None:
        cached.id = review_id
        cached.cached = True
        return JSONResponse(
            content=cached.model_dump(mode="json"),
            headers={"X-Review-ID": review_id, "X-Cache": "HIT"},
        )

    initial_state: ReviewState = {
        "code": request.code,
        "language": request.language.value,
        "ast_summary": "",
        "metrics": None,  # type: ignore[typeddict-item]
        "findings": [],
        "agent_outputs": [],
        "overall_score": 100,
        "summary": "",
        "codebase_context": "",
        "file_path": request.filename,
    }

    handler = create_langfuse_handler(
        trace_id=review_id,
        metadata={"language": request.language.value},
    )
    callbacks = [handler] if handler is not None else []
    result: dict[str, Any] = await review_graph.ainvoke(
        initial_state, config={"callbacks": callbacks}
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    findings = result["findings"]
    if settings.min_confidence > 0:
        findings = [f for f in findings if f.confidence >= settings.min_confidence]

    review_result = ReviewResult(
        id=review_id,
        metrics=result["metrics"],
        findings=findings,
        overall_score=result["overall_score"],
        summary=result["summary"],
        agent_outputs=result.get("agent_outputs", []),
        language=request.language,
        total_time_ms=round(elapsed_ms, 2),
    )

    # --- cache store ---
    await _try_cache_set(request.code, request.language.value, review_result)

    return JSONResponse(
        content=review_result.model_dump(mode="json"),
        headers={"X-Review-ID": review_id, "X-Cache": "MISS"},
    )


# ---------------------------------------------------------------------------
# Review (streaming SSE)
# ---------------------------------------------------------------------------


@router.post("/review/stream")
async def stream_review(request: ReviewRequest) -> StreamingResponse:
    review_id = str(uuid.uuid4())

    async def event_stream() -> AsyncIterator[str]:
        stream_state: ReviewState = {
            "code": request.code,
            "language": request.language.value,
            "ast_summary": "",
            "metrics": None,  # type: ignore[typeddict-item]
            "findings": [],
            "agent_outputs": [],
            "overall_score": 100,
            "summary": "",
            "codebase_context": "",
            "file_path": request.filename,
        }

        start = time.perf_counter()

        handler = create_langfuse_handler(
            trace_id=review_id,
            metadata={"language": request.language.value, "stream": True},
        )
        callbacks = [handler] if handler is not None else []

        final_output: dict[str, Any] = {}

        async for event in review_graph.astream_events(
            stream_state, config={"callbacks": callbacks}, version="v2"
        ):
            kind = event.get("event", "")
            name = event.get("name", "")

            _agent_names = ("quality_agent", "security_agent", "docs_agent")
            if kind == "on_chain_start" and name in _agent_names:
                sse_data = json.dumps({"type": "agent_start", "agent": name})
                yield f"data: {sse_data}\n\n"

            elif kind == "on_chain_end" and name in _agent_names:
                output: dict[str, Any] = event.get("data", {}).get("output", {})
                findings = output.get("findings", [])
                for finding in findings:
                    finding_data = (
                        finding.model_dump() if hasattr(finding, "model_dump") else finding
                    )  # noqa: E501
                    sse_data = json.dumps({"type": "finding", "agent": name, "data": finding_data})
                    yield f"data: {sse_data}\n\n"

                sse_data = json.dumps(
                    {
                        "type": "agent_complete",
                        "agent": name,
                        "findings_count": len(findings),
                    }
                )
                yield f"data: {sse_data}\n\n"

            elif kind == "on_chain_end" and name == "synthesize":
                output = event.get("data", {}).get("output", {})
                elapsed_ms = (time.perf_counter() - start) * 1000

                complete_data = {
                    "type": "complete",
                    "review_id": review_id,
                    "overall_score": output.get("overall_score", 0),
                    "summary": output.get("summary", ""),
                    "total_time_ms": round(elapsed_ms, 2),
                }
                final_output = output
                sse_data = json.dumps(complete_data)
                yield f"data: {sse_data}\n\n"

        # Best-effort cache store after streaming completes
        if final_output:
            try:
                metrics = final_output.get("metrics")
                if metrics is not None:
                    cached_result = ReviewResult(
                        id=review_id,
                        metrics=metrics,
                        findings=final_output.get("findings", []),
                        overall_score=final_output.get("overall_score", 0),
                        summary=final_output.get("summary", ""),
                        agent_outputs=final_output.get("agent_outputs", []),
                        language=request.language,
                        total_time_ms=0.0,
                    )
                    await _try_cache_set(request.code, request.language.value, cached_result)
            except Exception:
                pass

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Review-ID": review_id,
        },
    )


# ---------------------------------------------------------------------------
# Index (Graph RAG)
# ---------------------------------------------------------------------------


class IndexRequest(BaseModel):
    code: str
    language: Language = Language.PYTHON
    file_path: str


@router.post("/index")
async def index_file(request: IndexRequest) -> dict[str, object]:
    """Index a file into the knowledge graph for Graph RAG context."""
    import app.graph_rag._store_ref as _store_ref

    if _store_ref.store is None:
        raise HTTPException(
            status_code=503,
            detail="Graph RAG is not enabled. Set ODIN_GRAPH_RAG_ENABLED=true.",
        )

    await _store_ref.store.index_file(request.code, request.language, request.file_path)
    return {"status": "indexed", "file_path": request.file_path}


# ── Review history endpoints ─────────────────────────────────────────────────


def _get_review_store(req: Request):  # type: ignore[return]
    """Get ReviewStore from app state if Redis is available."""
    redis = getattr(req.app.state, "redis", None)
    if redis is None:
        raise HTTPException(status_code=503, detail="Redis is not available")
    from app.services.review_store import ReviewStore

    return ReviewStore(redis)


@router.get("/reviews")
async def list_reviews(
    limit: int = 20,
    offset: int = 0,
    req: Request = None,  # type: ignore[assignment]
) -> dict[str, object]:
    """List recent PR reviews."""
    store = _get_review_store(req)
    reviews = await store.list_recent(limit=limit, offset=offset)
    return {"reviews": reviews, "count": len(reviews)}


@router.get("/reviews/{review_id}")
async def get_review(
    review_id: str,
    req: Request = None,  # type: ignore[assignment]
) -> dict[str, object]:
    """Get a specific review by ID."""
    store = _get_review_store(req)
    data = await store.get(review_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"Review '{review_id}' not found")
    return data  # type: ignore[return-value]


# ── Feedback endpoint ────────────────────────────────────────────────────────


class FeedbackRequest(BaseModel):
    finding_id: str
    action: str  # "helpful" | "not_helpful" | "false_positive"
    category: str
    title: str
    language: str = "python"


@router.post("/feedback")
async def submit_feedback(
    request: FeedbackRequest,
    req: Request = None,  # type: ignore[assignment]
) -> dict[str, object]:
    """Record user feedback on a finding."""
    redis = getattr(req.app.state, "redis", None) if req else None
    if redis is None:
        raise HTTPException(status_code=503, detail="Redis is not available")

    from app.services.feedback import FeedbackService

    service = FeedbackService(redis)
    await service.record(
        finding_id=request.finding_id,
        action=request.action,
        category=request.category,
        title=request.title,
        language=request.language,
    )
    return {"status": "recorded", "finding_id": request.finding_id, "action": request.action}
