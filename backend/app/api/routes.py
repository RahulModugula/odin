import time

from fastapi import APIRouter

from app.models.schemas import ReviewRequest, ReviewResult
from app.parsers.tree_sitter_parser import parse_code
from app.parsers.languages import supported_languages

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

    structure = parse_code(request.code, request.language)

    elapsed_ms = (time.perf_counter() - start) * 1000

    return ReviewResult(
        metrics=structure.metrics,
        findings=[],
        overall_score=100,
        summary="Parsing complete. Agent analysis not yet available.",
        language=request.language,
        total_time_ms=round(elapsed_ms, 2),
    )
