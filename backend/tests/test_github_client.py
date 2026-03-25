"""Tests for the GitHub REST API client using respx to mock httpx."""

import base64

import pytest
import respx
from httpx import Response

from app.services.github_client import (
    GithubClientError,
    GithubRateLimitError,
    create_pr_review,
    get_file_content,
    get_pr_files,
)

OWNER, REPO, PR = "alice", "myrepo", 42
REF = "abc123"
GITHUB_BASE = "https://api.github.com"


# ── get_pr_files ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_pr_files_success() -> None:
    files = [{"filename": "src/main.py", "status": "modified", "changes": 10}]
    with respx.mock:
        respx.get(f"{GITHUB_BASE}/repos/{OWNER}/{REPO}/pulls/{PR}/files").mock(
            return_value=Response(200, json=files)
        )
        result = await get_pr_files(OWNER, REPO, PR)

    assert result == files


@pytest.mark.asyncio
async def test_get_pr_files_pagination() -> None:
    page1 = [{"filename": f"file{i}.py", "status": "modified", "changes": 1} for i in range(100)]
    page2 = [{"filename": "last.py", "status": "modified", "changes": 1}]

    with respx.mock:
        respx.get(f"{GITHUB_BASE}/repos/{OWNER}/{REPO}/pulls/{PR}/files").mock(
            side_effect=[
                Response(200, json=page1),
                Response(200, json=page2),
            ]
        )
        result = await get_pr_files(OWNER, REPO, PR)

    assert len(result) == 101


@pytest.mark.asyncio
async def test_get_pr_files_raises_on_401() -> None:
    with respx.mock:
        respx.get(f"{GITHUB_BASE}/repos/{OWNER}/{REPO}/pulls/{PR}/files").mock(
            return_value=Response(401, json={"message": "Bad credentials"})
        )
        with pytest.raises(GithubClientError) as exc_info:
            await get_pr_files(OWNER, REPO, PR)

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_get_pr_files_raises_on_rate_limit() -> None:
    with respx.mock:
        respx.get(f"{GITHUB_BASE}/repos/{OWNER}/{REPO}/pulls/{PR}/files").mock(
            return_value=Response(429, headers={"Retry-After": "60"}, json={})
        )
        with pytest.raises(GithubRateLimitError) as exc_info:
            await get_pr_files(OWNER, REPO, PR)

    assert exc_info.value.retry_after == 60


# ── get_file_content ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_file_content_decodes_base64() -> None:
    source = "def hello():\n    pass\n"
    encoded = base64.b64encode(source.encode()).decode()

    with respx.mock:
        respx.get(f"{GITHUB_BASE}/repos/{OWNER}/{REPO}/contents/src/main.py").mock(
            return_value=Response(200, json={
                "content": encoded,
                "encoding": "base64",
                "size": len(source),
            })
        )
        result = await get_file_content(OWNER, REPO, REF, "src/main.py")

    assert result == source


@pytest.mark.asyncio
async def test_get_file_content_returns_none_for_404() -> None:
    with respx.mock:
        respx.get(f"{GITHUB_BASE}/repos/{OWNER}/{REPO}/contents/missing.py").mock(
            return_value=Response(404, json={"message": "Not Found"})
        )
        result = await get_file_content(OWNER, REPO, REF, "missing.py")

    assert result is None


@pytest.mark.asyncio
async def test_get_file_content_skips_large_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.services.github_client.settings.webhook_max_file_bytes", 100)
    encoded = base64.b64encode(b"x" * 200).decode()

    with respx.mock:
        respx.get(f"{GITHUB_BASE}/repos/{OWNER}/{REPO}/contents/big.py").mock(
            return_value=Response(200, json={
                "content": encoded,
                "encoding": "base64",
                "size": 200,  # exceeds 100-byte limit
            })
        )
        result = await get_file_content(OWNER, REPO, REF, "big.py")

    assert result is None


@pytest.mark.asyncio
async def test_get_file_content_skips_binary_files() -> None:
    binary_encoded = base64.b64encode(b"\x89PNG\r\n\x1a\n\x00\x00").decode()

    with respx.mock:
        respx.get(f"{GITHUB_BASE}/repos/{OWNER}/{REPO}/contents/image.py").mock(
            return_value=Response(200, json={
                "content": binary_encoded,
                "encoding": "base64",
                "size": 10,
            })
        )
        result = await get_file_content(OWNER, REPO, REF, "image.py")

    assert result is None


# ── create_pr_review ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_pr_review_posts_correct_payload() -> None:
    expected_response = {"id": 1, "state": "commented"}

    with respx.mock:
        route = respx.post(f"{GITHUB_BASE}/repos/{OWNER}/{REPO}/pulls/{PR}/reviews").mock(
            return_value=Response(200, json=expected_response)
        )
        result = await create_pr_review(
            OWNER, REPO, PR,
            commit_sha="abc123",
            body="## Odin Review",
            comments=[{"path": "main.py", "line": 10, "side": "RIGHT", "body": "issue"}],
        )

    assert result == expected_response
    request_body = route.calls.last.request
    import json
    payload = json.loads(request_body.content)
    assert payload["event"] == "COMMENT"
    assert payload["commit_id"] == "abc123"
    assert len(payload["comments"]) == 1


@pytest.mark.asyncio
async def test_create_pr_review_raises_on_403() -> None:
    with respx.mock:
        respx.post(f"{GITHUB_BASE}/repos/{OWNER}/{REPO}/pulls/{PR}/reviews").mock(
            return_value=Response(403, json={"message": "Forbidden"})
        )
        with pytest.raises(GithubClientError) as exc_info:
            await create_pr_review(OWNER, REPO, PR, "sha", "body", [])

    assert exc_info.value.status_code == 403
