"""GitHub webhook endpoint with HMAC-SHA256 signature verification."""

import hashlib
import hmac

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel

from app.config import settings
from app.services.webhook_processor import process_pr_webhook

logger = structlog.get_logger()

webhook_router = APIRouter()

HANDLED_ACTIONS = {"opened", "synchronize", "reopened"}


# ── Pydantic models for the incoming GitHub webhook payload ─────────────────


class _PullRequestHead(BaseModel):
    sha: str


class _PullRequestData(BaseModel):
    number: int
    head: _PullRequestHead


class _Repository(BaseModel):
    full_name: str  # "owner/repo"


class _WebhookPayload(BaseModel):
    action: str
    pull_request: _PullRequestData
    repository: _Repository


# ── Signature verification ──────────────────────────────────────────────────


def verify_github_signature(payload: bytes, sig_header: str | None, secret: str) -> bool:
    """Return True if the X-Hub-Signature-256 header matches the computed HMAC.

    Uses hmac.compare_digest for constant-time comparison to prevent
    timing side-channel attacks.
    """
    if not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig_header)


# ── Endpoint ────────────────────────────────────────────────────────────────


@webhook_router.post("/webhook/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict[str, str]:
    """Receive GitHub pull_request webhook events and trigger async code review.

    Returns 200 immediately; the actual review runs as a background task.
    HMAC-SHA256 signature verification is performed before any processing.
    """
    # Read raw bytes BEFORE any JSON parsing — HMAC must be computed on the
    # exact bytes GitHub sent, not a re-serialized version.
    payload_bytes = await request.body()

    sig_header = request.headers.get("X-Hub-Signature-256")
    if not verify_github_signature(payload_bytes, sig_header, settings.github_webhook_secret):
        logger.warning(
            "webhook signature verification failed",
            has_header=sig_header is not None,
        )
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event_type = request.headers.get("X-GitHub-Event", "")
    if event_type != "pull_request":
        return {"status": "ignored", "reason": f"event '{event_type}' not handled"}

    data = _WebhookPayload.model_validate_json(payload_bytes)

    if data.action not in HANDLED_ACTIONS:
        return {"status": "ignored", "reason": f"action '{data.action}' not handled"}

    owner, _, repo = data.repository.full_name.partition("/")
    pull_number = data.pull_request.number
    head_sha = data.pull_request.head.sha

    logger.info(
        "webhook accepted",
        repo=data.repository.full_name,
        pr=pull_number,
        action=data.action,
        sha=head_sha[:8],
    )

    # Enqueue background task — response is returned immediately
    background_tasks.add_task(
        process_pr_webhook,
        owner=owner,
        repo=repo,
        pull_number=pull_number,
        head_sha=head_sha,
    )

    return {"status": "accepted"}
