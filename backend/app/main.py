from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import app.graph_rag._store_ref as _store_ref
import app.services._feedback_ref as _feedback_ref
from app.api.routes import router
from app.api.webhook import webhook_router
from app.config import settings
from app.observability.metrics import metrics_endpoint
from app.observability.tracing import flush_langfuse

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.log_level.upper())
        ),
    )
    logger.info("odin starting up")

    # Initialise Redis connection (graceful — failure is non-fatal)
    try:
        from redis.asyncio import Redis

        redis: Redis = Redis.from_url(settings.redis_url, decode_responses=False)
        await redis.ping()
        app.state.redis = redis
        logger.info("redis connected", url=settings.redis_url)

        # Wire FeedbackService into the module-level ref so LangGraph nodes
        # can access it without FastAPI DI (mirrors _store_ref pattern)
        from app.services.feedback import FeedbackService
        _feedback_ref.service = FeedbackService(redis)
    except Exception as exc:
        app.state.redis = None
        logger.warning("redis unavailable — cache disabled", error=str(exc))

    if settings.graph_rag_enabled:
        from app.graph_rag.store import GraphStore

        auth: tuple[str, str] | None = None
        if settings.memgraph_auth:
            user, _, password = settings.memgraph_auth.partition(":")
            auth = (user, password)

        graph_store = GraphStore(uri=settings.memgraph_uri, auth=auth)
        await graph_store.connect()
        _store_ref.store = graph_store
        app.state.graph_store = graph_store

    yield

    # Teardown
    redis_conn = getattr(app.state, "redis", None)
    if redis_conn is not None:
        await redis_conn.aclose()

    if settings.graph_rag_enabled and _store_ref.store is not None:
        await _store_ref.store.close()
        _store_ref.store = None

    flush_langfuse()
    logger.info("odin shutting down")


app = FastAPI(
    title="odin",
    description="AI-powered multi-agent code review",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response  # type: ignore[no-any-return]


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("unhandled exception", error=str(exc), type=type(exc).__name__)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


app.include_router(router, prefix="/api")
app.include_router(webhook_router, prefix="/api")

# Expose Prometheus metrics
app.add_route("/metrics", metrics_endpoint)  # type: ignore[arg-type]

if settings.mcp_enabled:
    try:
        from app.mcp.server import mcp

        app.mount("/mcp", mcp.sse_app())
        logger.info("mcp server mounted at /mcp")
    except Exception as e:
        logger.warning("mcp server failed to mount", error=str(e))
