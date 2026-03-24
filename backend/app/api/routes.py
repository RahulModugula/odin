import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.agents.graph import review_graph
from app.models.enums import Language
from app.models.schemas import ReviewRequest, ReviewResult
from app.models.state import ReviewState
from app.observability.tracing import create_langfuse_handler
from app.parsers.languages import supported_languages

logger = structlog.get_logger()
router = APIRouter()


@router.get("/health")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "version": "0.1.0",
        "supported_languages": supported_languages(),
    }


@router.post("/review", response_model=ReviewResult)
async def create_review(request: ReviewRequest) -> ReviewResult:
    start = time.perf_counter()
    review_id = str(uuid.uuid4())

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

    return ReviewResult(
        id=review_id,
        metrics=result["metrics"],
        findings=result["findings"],
        overall_score=result["overall_score"],
        summary=result["summary"],
        agent_outputs=result.get("agent_outputs", []),
        language=request.language,
        total_time_ms=round(elapsed_ms, 2),
    )


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
                sse_data = json.dumps(complete_data)
                yield f"data: {sse_data}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Review-ID": review_id,
        },
    )


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
