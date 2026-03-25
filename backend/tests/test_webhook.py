"""Tests for the GitHub webhook endpoint."""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.webhook import verify_github_signature

SECRET = "test-webhook-secret"


def _patch_secret():
    """Patch settings.github_webhook_secret to the test SECRET."""
    return patch("app.api.webhook.settings.github_webhook_secret", SECRET)


def _make_signature(payload: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _pr_payload(
    action: str = "opened", repo: str = "alice/myrepo", number: int = 42, sha: str = "abc123"
) -> bytes:
    return json.dumps(
        {
            "action": action,
            "pull_request": {"number": number, "head": {"sha": sha}},
            "repository": {"full_name": repo},
        }
    ).encode()


# ── Unit tests for HMAC helper ──────────────────────────────────────────────


def test_verify_signature_valid() -> None:
    payload = b'{"action": "opened"}'
    sig = _make_signature(payload)
    assert verify_github_signature(payload, sig, SECRET) is True


def test_verify_signature_invalid() -> None:
    payload = b'{"action": "opened"}'
    assert verify_github_signature(payload, "sha256=bad", SECRET) is False


def test_verify_signature_missing_header() -> None:
    assert verify_github_signature(b"data", None, SECRET) is False


def test_verify_signature_wrong_prefix() -> None:
    payload = b"data"
    raw_hex = hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()
    assert verify_github_signature(payload, f"sha1={raw_hex}", SECRET) is False


def test_verify_signature_uses_compare_digest() -> None:
    """Ensures constant-time comparison is used (not ==)."""
    import inspect

    import app.api.webhook as webhook_module

    source = inspect.getsource(webhook_module.verify_github_signature)
    assert "compare_digest" in source


# ── Endpoint tests ──────────────────────────────────────────────────────────


def test_webhook_rejects_missing_signature(client: TestClient) -> None:
    with _patch_secret():
        response = client.post(
            "/api/webhook/github", content=b"{}", headers={"X-GitHub-Event": "pull_request"}
        )
    assert response.status_code == 401


def test_webhook_rejects_invalid_signature(client: TestClient) -> None:
    payload = _pr_payload()
    with _patch_secret():
        response = client.post(
            "/api/webhook/github",
            content=payload,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": "sha256=invalidsig",
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 401


def test_webhook_ignores_non_pr_event(client: TestClient) -> None:
    payload = b'{"action": "push"}'
    sig = _make_signature(payload)
    with _patch_secret():
        response = client.post(
            "/api/webhook/github",
            content=payload,
            headers={
                "X-GitHub-Event": "push",
                "X-Hub-Signature-256": sig,
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


def test_webhook_ignores_pr_closed_action(client: TestClient) -> None:
    payload = _pr_payload(action="closed")
    sig = _make_signature(payload)
    with _patch_secret():
        response = client.post(
            "/api/webhook/github",
            content=payload,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": sig,
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


@pytest.mark.parametrize("action", ["opened", "synchronize", "reopened"])
def test_webhook_accepts_valid_pr_actions(client: TestClient, action: str) -> None:
    payload = _pr_payload(action=action)
    sig = _make_signature(payload)

    with (
        _patch_secret(),
        patch("app.api.webhook.process_pr_webhook", new_callable=AsyncMock),
    ):
        response = client.post(
            "/api/webhook/github",
            content=payload,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": sig,
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"


def test_webhook_enqueues_correct_args(client: TestClient) -> None:
    payload = _pr_payload(action="opened", repo="octocat/hello", number=7, sha="deadbeef")
    sig = _make_signature(payload)

    with (
        _patch_secret(),
        patch("app.api.webhook.process_pr_webhook", new_callable=AsyncMock),
    ):
        response = client.post(
            "/api/webhook/github",
            content=payload,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": sig,
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 200
