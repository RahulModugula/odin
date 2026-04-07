"""Tests for the GitHub App one-click install flow."""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.github_app import _installations, _make_jwt


# ── Helpers ──────────────────────────────────────────────────────────────────


def _app_sig(payload: bytes, secret: str = "test-app-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _patch_app_configured(
    app_id: str = "12345",
    client_id: str = "Iv1.abc123",
    client_secret: str = "secret",
    private_key: str = "",
    webhook_secret: str = "test-app-secret",
):
    """Context manager that patches all GitHub App settings fields."""
    return patch.multiple(
        "app.api.github_app.settings",
        github_app_id=app_id,
        github_app_client_id=client_id,
        github_app_client_secret=client_secret,
        github_app_private_key=private_key,
        github_app_webhook_secret=webhook_secret,
    )


# ── Install redirect ─────────────────────────────────────────────────────────


def test_install_redirect_returns_302_when_configured(client: TestClient) -> None:
    """GET /api/github/app/install should redirect when GitHub App is configured."""
    with _patch_app_configured():
        response = client.get("/api/github/app/install", follow_redirects=False)
    assert response.status_code == 302
    assert "github.com/apps/" in response.headers["location"]


def test_install_redirect_returns_503_when_not_configured(client: TestClient) -> None:
    """GET /api/github/app/install returns 503 when ODIN_GITHUB_APP_ID is unset."""
    with patch("app.api.github_app.settings.github_app_id", ""):
        response = client.get("/api/github/app/install")
    assert response.status_code == 503
    body = response.json()
    assert "ODIN_GITHUB_APP_ID" in body["detail"]


def test_install_redirect_url_contains_client_id(client: TestClient) -> None:
    """The redirect URL should embed the app's client_id slug."""
    with _patch_app_configured(client_id="Iv1.myspecialapp"):
        response = client.get("/api/github/app/install", follow_redirects=False)
    assert "Iv1.myspecialapp" in response.headers["location"]


# ── OAuth callback ───────────────────────────────────────────────────────────


def test_callback_stores_installation_and_returns_200(client: TestClient) -> None:
    """GET /api/github/app/callback should store the installation and return 200."""
    _installations.clear()

    import httpx
    import respx

    with (
        _patch_app_configured(),
        patch("app.api.github_app._make_jwt", return_value="fake-jwt"),
        respx.mock(base_url="https://api.github.com") as mock_api,
    ):
        mock_api.get("/app/installations/99").mock(
            return_value=httpx.Response(
                200,
                json={"account": {"login": "octocat", "type": "User"}},
            )
        )
        response = client.get(
            "/api/github/app/callback",
            params={"installation_id": 99, "setup_action": "install"},
        )

    assert response.status_code == 200
    assert "octocat" in response.text or "99" in response.text


def test_callback_missing_installation_id_returns_400(client: TestClient) -> None:
    """Callback without installation_id should return 400."""
    with _patch_app_configured():
        response = client.get("/api/github/app/callback")
    assert response.status_code == 400


def test_callback_stores_record_in_memory(client: TestClient) -> None:
    """After a successful callback the record should appear in _installations."""
    _installations.clear()

    # Patch at module level so the async context manager resolves correctly
    import httpx
    import respx

    with (
        _patch_app_configured(),
        patch("app.api.github_app._make_jwt", return_value="fake-jwt"),
        respx.mock(base_url="https://api.github.com") as mock_api,
    ):
        mock_api.get("/app/installations/42").mock(
            return_value=httpx.Response(
                200,
                json={"account": {"login": "myorg", "type": "Organization"}},
            )
        )
        client.get(
            "/api/github/app/callback",
            params={"installation_id": 42, "setup_action": "install"},
        )

    assert 42 in _installations
    record = _installations[42]
    assert record["installation_id"] == 42
    assert record["account_login"] == "myorg"


# ── Installations list ───────────────────────────────────────────────────────


def test_installations_list_returns_json(client: TestClient) -> None:
    """GET /api/github/app/installations should return JSON with installations key."""
    _installations.clear()
    _installations[1] = {
        "installation_id": 1,
        "account_login": "alice",
        "account_type": "User",
        "repos": ["alice/repo"],
        "setup_action": "install",
        "installed_at": "2026-04-05T12:00:00+00:00",
    }

    with _patch_app_configured():
        response = client.get("/api/github/app/installations")

    assert response.status_code == 200
    data = response.json()
    assert "installations" in data
    assert len(data["installations"]) == 1
    assert data["installations"][0]["account_login"] == "alice"


def test_installations_list_returns_503_when_not_configured(client: TestClient) -> None:
    """Installations list returns 503 when the app is not configured."""
    with patch("app.api.github_app.settings.github_app_id", ""):
        response = client.get("/api/github/app/installations")
    assert response.status_code == 503


# ── App webhook ──────────────────────────────────────────────────────────────


def test_app_webhook_rejects_bad_signature(client: TestClient) -> None:
    """App webhook endpoint rejects requests with an invalid signature."""
    payload = json.dumps({"action": "created"}).encode()
    with _patch_app_configured():
        response = client.post(
            "/api/github/app/webhook",
            content=payload,
            headers={
                "X-GitHub-Event": "installation",
                "X-Hub-Signature-256": "sha256=badsig",
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 401


def test_app_webhook_accepts_valid_installation_event(client: TestClient) -> None:
    """App webhook accepts a correctly signed installation event."""
    _installations.clear()
    payload = json.dumps({
        "action": "created",
        "installation": {
            "id": 77,
            "account": {"login": "testorg", "type": "Organization"},
        },
        "repositories": [],
    }).encode()
    sig = _app_sig(payload)

    with _patch_app_configured():
        response = client.post(
            "/api/github/app/webhook",
            content=payload,
            headers={
                "X-GitHub-Event": "installation",
                "X-Hub-Signature-256": sig,
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"


def test_app_webhook_ignores_unknown_events(client: TestClient) -> None:
    """Unknown events are gracefully ignored (not rejected)."""
    payload = json.dumps({"action": "labeled"}).encode()
    sig = _app_sig(payload)

    with _patch_app_configured():
        response = client.post(
            "/api/github/app/webhook",
            content=payload,
            headers={
                "X-GitHub-Event": "issues",
                "X-Hub-Signature-256": sig,
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


# ── Landing page ─────────────────────────────────────────────────────────────


def test_landing_page_returns_html(client: TestClient) -> None:
    """GET /api/github/ returns the HTML landing page."""
    response = client.get("/api/github/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Odin" in response.text


def test_landing_page_shows_install_button_when_configured(client: TestClient) -> None:
    """Landing page contains the install link when the app is configured."""
    with _patch_app_configured(client_id="Iv1.myapp"):
        response = client.get("/api/github/")
    assert "Install Odin on GitHub" in response.text
    assert "Iv1.myapp" in response.text


def test_landing_page_shows_warning_when_not_configured(client: TestClient) -> None:
    """Landing page shows a configuration warning when app_id is absent."""
    with patch.multiple(
        "app.api.github_app.settings",
        github_app_id="",
        github_app_client_id="",
    ):
        response = client.get("/api/github/")
    assert "not yet configured" in response.text
