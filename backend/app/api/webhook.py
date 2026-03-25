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


class _IssueCommentPayload(BaseModel):
    action: str
    issue: dict
    comment: dict
    repository: _Repository


# ── Signature verification ──────────────────────────────────────────────────


def verify_github_signature(payload: bytes, sig_header: str | None, secret: str) -> bool:
    """Return True if the X-Hub-Signature-256 header matches the computed HMAC.

    Uses hmac.compare_digest for constant-time comparison to prevent
    timing side-channel attacks.
    """
    if not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)


# ── Bot comment handling ─────────────────────────────────────────────────────


async def _handle_bot_comment(
    owner: str,
    repo: str,
    issue_number: int,
    comment_body: str,
    is_pull_request: bool,
) -> None:
    """Handle @odin / @odin-bot mentions in PR comments."""
    from app.services.github_client import post_issue_comment

    body_lower = comment_body.lower()

    # Re-review command
    if "review" in body_lower:
        if not is_pull_request:
            await post_issue_comment(
                owner,
                repo,
                issue_number,
                "Sorry, I can only review pull requests, not plain issues.",
            )
            return

        await post_issue_comment(
            owner,
            repo,
            issue_number,
            "Starting a fresh review — I'll post the results shortly.",
        )
        # Fetch the PR head SHA and kick off a new review
        try:
            # Fetch SHA directly from the pulls endpoint (get_pr_details doesn't return it)
            import httpx

            from app.services.github_client import GITHUB_API_BASE, _auth_headers

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{issue_number}",
                    headers=_auth_headers(),
                )
            head_sha = resp.json().get("head", {}).get("sha", "")
            if head_sha:
                await process_pr_webhook(owner, repo, issue_number, head_sha)
        except Exception as exc:
            logger.error("re-review triggered by bot comment failed", error=str(exc))
            await post_issue_comment(
                owner,
                repo,
                issue_number,
                "Sorry, I ran into an error while trying to re-review this PR.",
            )
        return

    # Generic question — give a brief helpful reply
    await post_issue_comment(
        owner,
        repo,
        issue_number,
        (
            "Hi! I'm Odin, an AI code review bot. "
            "You can mention `@odin review` to trigger a fresh code review on this PR."
        ),
    )


# ── Endpoint ────────────────────────────────────────────────────────────────


@webhook_router.post("/webhook/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict[str, str]:
    """Receive GitHub webhook events and trigger async code review.

    Handles pull_request and issue_comment event types.
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

    # ── pull_request events ──────────────────────────────────────────────────
    if event_type == "pull_request":
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

        background_tasks.add_task(
            process_pr_webhook,
            owner=owner,
            repo=repo,
            pull_number=pull_number,
            head_sha=head_sha,
        )

        return {"status": "accepted"}

    # ── issue_comment events (PR comments) ───────────────────────────────────
    if event_type == "issue_comment":
        import json as _json

        raw = _json.loads(payload_bytes)
        action = raw.get("action", "")

        # Only act on newly created comments
        if action != "created":
            return {"status": "ignored", "reason": f"comment action '{action}' not handled"}

        comment_body: str = raw.get("comment", {}).get("body", "")
        # Check for @odin or @odin-bot mention
        if "@odin" not in comment_body.lower():
            return {"status": "ignored", "reason": "no @odin mention"}

        owner_repo: str = raw.get("repository", {}).get("full_name", "")
        owner, _, repo = owner_repo.partition("/")
        issue_number: int = raw.get("issue", {}).get("number", 0)
        is_pull_request: bool = "pull_request" in raw.get("issue", {})

        logger.info(
            "bot mention detected",
            repo=owner_repo,
            issue=issue_number,
            is_pr=is_pull_request,
        )

        background_tasks.add_task(
            _handle_bot_comment,
            owner=owner,
            repo=repo,
            issue_number=issue_number,
            comment_body=comment_body,
            is_pull_request=is_pull_request,
        )

        return {"status": "accepted"}

    return {"status": "ignored", "reason": f"event '{event_type}' not handled"}
