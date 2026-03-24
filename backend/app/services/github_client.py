"""Async GitHub REST API client for Odin's webhook integration."""

import base64

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()

GITHUB_API_BASE = "https://api.github.com"
GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


class GithubClientError(Exception):
    """Raised for non-retryable GitHub API errors (4xx excluding 429)."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"GitHub API error {status_code}: {message}")


class GithubRateLimitError(Exception):
    """Raised when GitHub returns 429 Too Many Requests."""

    def __init__(self, retry_after: int | None) -> None:
        self.retry_after = retry_after
        super().__init__(f"GitHub rate limit hit. Retry-After: {retry_after}s")


def _auth_headers() -> dict[str, str]:
    return {**GITHUB_HEADERS, "Authorization": f"Bearer {settings.github_token}"}


def _handle_error_response(response: httpx.Response) -> None:
    """Raise appropriate exception for non-2xx responses."""
    if response.status_code == 429:
        retry_after_raw = response.headers.get("Retry-After")
        retry_after = int(retry_after_raw) if retry_after_raw and retry_after_raw.isdigit() else None
        raise GithubRateLimitError(retry_after=retry_after)
    if response.status_code >= 400:
        try:
            detail = response.json().get("message", response.text)
        except Exception:
            detail = response.text
        raise GithubClientError(status_code=response.status_code, message=detail)


async def get_pr_files(owner: str, repo: str, pull_number: int) -> list[dict]:  # type: ignore[type-arg]
    """Fetch the list of files changed in a pull request.

    Handles pagination automatically (GitHub caps at 300 files per page).
    Returns a list of file dicts with keys: filename, status, additions,
    deletions, changes, raw_url, patch (optional).
    """
    files: list[dict] = []  # type: ignore[type-arg]
    page = 1

    async with httpx.AsyncClient() as client:
        while True:
            url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{pull_number}/files"
            response = await client.get(
                url,
                headers=_auth_headers(),
                params={"per_page": 100, "page": page},
            )
            _handle_error_response(response)
            page_files = response.json()
            if not page_files:
                break
            files.extend(page_files)
            # If we got fewer than 100, no more pages
            if len(page_files) < 100:
                break
            page += 1

    logger.debug("fetched pr files", owner=owner, repo=repo, pr=pull_number, count=len(files))
    return files


async def get_file_content(owner: str, repo: str, ref: str, path: str) -> str | None:
    """Fetch the text content of a file at a given git ref.

    Returns None if the file is too large, not found, or binary.
    Content is decoded from base64 as returned by the GitHub contents API.
    """
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}"

    async with httpx.AsyncClient() as client:
        response = await client.get(
            url,
            headers=_auth_headers(),
            params={"ref": ref},
        )

        if response.status_code == 404:
            logger.debug("file not found", path=path, ref=ref)
            return None

        _handle_error_response(response)
        data = response.json()

    # GitHub returns size in bytes; skip if too large before decoding
    file_size = data.get("size", 0)
    if file_size > settings.webhook_max_file_bytes:
        logger.debug("skipping large file", path=path, size=file_size)
        return None

    # GitHub encodes file content as base64 with newlines
    raw_content = data.get("content", "")
    encoding = data.get("encoding", "base64")
    if encoding != "base64":
        logger.warning("unexpected file encoding", path=path, encoding=encoding)
        return None

    try:
        decoded = base64.b64decode(raw_content).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        logger.debug("skipping binary or non-utf8 file", path=path)
        return None

    return decoded


async def create_pr_review(
    owner: str,
    repo: str,
    pull_number: int,
    commit_sha: str,
    body: str,
    comments: list[dict],  # type: ignore[type-arg]
) -> dict:  # type: ignore[type-arg]
    """Post a PR review with optional inline comments.

    Uses event="COMMENT" so Odin never blocks merges or auto-approves.
    Each comment in the list must have: path, line, side, body.
    """
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{pull_number}/reviews"
    payload: dict = {  # type: ignore[type-arg]
        "commit_id": commit_sha,
        "body": body,
        "event": "COMMENT",
        "comments": comments,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=_auth_headers(), json=payload)

    if response.status_code == 422:
        # Log the full response for debugging invalid line numbers or commit SHA
        logger.error(
            "github rejected review payload (422)",
            repo=f"{owner}/{repo}",
            pr=pull_number,
            response=response.text,
        )
        _handle_error_response(response)

    _handle_error_response(response)
    logger.info("posted pr review", repo=f"{owner}/{repo}", pr=pull_number)
    return response.json()  # type: ignore[no-any-return]
