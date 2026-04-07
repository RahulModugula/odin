"""GitHub App one-click install flow.

Endpoints
---------
GET  /github/app/install        — redirect to GitHub App authorization page
GET  /github/app/callback       — OAuth callback; stores installation record
GET  /github/app/installations  — list active installations (JSON)
POST /github/app/webhook        — receive GitHub App webhook events
GET  /                          — landing page with install button

JWT authentication for GitHub App API calls uses RS256 signed tokens.
PyJWT is preferred when available; falls back to raw cryptography primitives.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.config import settings

logger = structlog.get_logger()

github_app_router = APIRouter()

# ── In-memory installation store (keyed by installation_id) ─────────────────
# Production deployments should swap this for a Redis-backed store.

_installations: dict[int, dict[str, Any]] = {}


# ── JWT helpers ──────────────────────────────────────────────────────────────


def _make_jwt(app_id: str, private_key_pem: str) -> str:
    """Return a signed RS256 JWT suitable for GitHub App API calls.

    The token is valid for 60 seconds — well within GitHub's 10-minute limit.
    PyJWT is used when available; otherwise falls back to the ``cryptography``
    package's hazmat primitives.
    """
    now = int(time.time())
    payload = {
        "iat": now - 60,  # issued 60 s in the past to allow clock skew
        "exp": now + 60,
        "iss": app_id,
    }

    # Normalise escaped newlines that may appear when the key is stored as an
    # environment variable (e.g. "-----BEGIN RSA PRIVATE KEY-----\nMII...")
    pem = private_key_pem.replace("\\n", "\n")

    try:
        import jwt  # PyJWT

        return jwt.encode(payload, pem, algorithm="RS256")  # type: ignore[no-any-return]
    except ImportError:
        pass

    # Fallback: build the JWT manually using cryptography.hazmat
    import base64

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    message = f"{header}.{body}".encode()

    private_key = serialization.load_pem_private_key(pem.encode(), password=None)
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[call-arg]
    return f"{header}.{body}.{_b64url(signature)}"


# ── Graceful guard ───────────────────────────────────────────────────────────


def _require_app_configured() -> None:
    """Raise HTTP 503 with setup instructions when app credentials are absent."""
    if not settings.github_app_id:
        raise HTTPException(
            status_code=503,
            detail=(
                "GitHub App not configured. Set the following environment variables: "
                "ODIN_GITHUB_APP_ID, ODIN_GITHUB_APP_CLIENT_ID, "
                "ODIN_GITHUB_APP_CLIENT_SECRET, ODIN_GITHUB_APP_PRIVATE_KEY, "
                "ODIN_GITHUB_APP_WEBHOOK_SECRET"
            ),
        )


# ── Landing page ─────────────────────────────────────────────────────────────


@github_app_router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def landing_page() -> HTMLResponse:
    """Self-hoster landing page with a one-click GitHub App install button."""
    app_configured = bool(settings.github_app_id and settings.github_app_client_id)
    if app_configured:
        install_url = (
            f"https://github.com/apps/{settings.github_app_client_id}/installations/new"
        )
        button_html = (
            f'<a href="{install_url}" class="btn">Install Odin on GitHub</a>'
        )
    else:
        button_html = (
            '<p class="warn">GitHub App is not yet configured on this instance. '
            "Set <code>ODIN_GITHUB_APP_ID</code> and related env vars.</p>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Odin — AI Code Review</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 640px; margin: 80px auto; padding: 0 24px; color: #111; }}
    h1 {{ font-size: 2rem; margin-bottom: 0.25rem; }}
    p {{ color: #555; line-height: 1.6; }}
    .btn {{
      display: inline-block; margin-top: 24px; padding: 14px 28px;
      background: #24292f; color: #fff; border-radius: 6px;
      text-decoration: none; font-weight: 600; font-size: 1rem;
    }}
    .btn:hover {{ background: #444d56; }}
    .warn {{ color: #b45309; background: #fef3c7; padding: 12px 16px; border-radius: 6px; }}
    code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
  </style>
</head>
<body>
  <h1>Odin</h1>
  <p>AI-powered code review that lives in your GitHub workflow.
     Install the GitHub App to get automatic PR reviews — no manual webhook
     setup required.</p>
  {button_html}
</body>
</html>"""
    return HTMLResponse(content=html)


# ── Install redirect ─────────────────────────────────────────────────────────


@github_app_router.get("/app/install")
async def github_app_install() -> RedirectResponse:
    """Redirect the user to the GitHub App installation page."""
    _require_app_configured()
    install_url = (
        f"https://github.com/apps/{settings.github_app_client_id}/installations/new"
    )
    logger.info("redirecting to github app install", url=install_url)
    return RedirectResponse(url=install_url, status_code=302)


# ── OAuth callback ───────────────────────────────────────────────────────────


@github_app_router.get("/app/callback", response_class=HTMLResponse)
async def github_app_callback(
    installation_id: int | None = None,
    setup_action: str | None = None,
    code: str | None = None,
) -> HTMLResponse:
    """Handle the post-install callback from GitHub.

    GitHub redirects here with ``?installation_id=<id>&setup_action=install``
    after the user grants access.  We store the installation and show a
    confirmation page.
    """
    _require_app_configured()

    if installation_id is None:
        raise HTTPException(status_code=400, detail="Missing installation_id parameter")

    # Fetch installation details from GitHub to get the account info
    account_login = "unknown"
    account_type = "unknown"
    repos: list[str] = []

    try:
        import httpx

        token = _make_jwt(settings.github_app_id, settings.github_app_private_key)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.github.com/app/installations/{installation_id}",
                headers=headers,
            )
        if resp.status_code == 200:
            data = resp.json()
            account = data.get("account", {})
            account_login = account.get("login", "unknown")
            account_type = account.get("type", "unknown")
    except Exception as exc:
        logger.warning("could not fetch installation details", error=str(exc))

    record = {
        "installation_id": installation_id,
        "account_login": account_login,
        "account_type": account_type,
        "repos": repos,
        "setup_action": setup_action or "install",
        "installed_at": datetime.now(timezone.utc).isoformat(),
    }
    _installations[installation_id] = record

    logger.info(
        "github app installed",
        installation_id=installation_id,
        account=account_login,
        action=setup_action,
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Odin — Installation successful</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 560px; margin: 80px auto; padding: 0 24px; color: #111; }}
    h1 {{ color: #166534; }}
    p {{ color: #555; line-height: 1.6; }}
    code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>Odin installed successfully</h1>
  <p>The Odin GitHub App has been installed on <strong>{account_login}</strong>.</p>
  <p>Odin will now automatically review pull requests. No further configuration needed.</p>
  <p>Installation ID: <code>{installation_id}</code></p>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


# ── Installations list ───────────────────────────────────────────────────────


@github_app_router.get("/app/installations")
async def list_installations() -> JSONResponse:
    """Return all active GitHub App installations as JSON."""
    _require_app_configured()
    return JSONResponse(content={"installations": list(_installations.values())})


# ── App webhook ──────────────────────────────────────────────────────────────


def _verify_app_webhook_signature(payload: bytes, sig_header: str | None) -> bool:
    """Verify the X-Hub-Signature-256 header using the app webhook secret."""
    secret = settings.github_app_webhook_secret
    if not secret or not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)


async def _handle_installation_event(payload: dict[str, Any]) -> None:
    """Process installation created/deleted events."""
    action = payload.get("action", "")
    installation = payload.get("installation", {})
    installation_id: int = installation.get("id", 0)
    account = installation.get("account", {})
    account_login: str = account.get("login", "unknown")
    account_type: str = account.get("type", "unknown")

    if action == "created":
        repos = [r.get("full_name", "") for r in payload.get("repositories", [])]
        _installations[installation_id] = {
            "installation_id": installation_id,
            "account_login": account_login,
            "account_type": account_type,
            "repos": repos,
            "setup_action": "install",
            "installed_at": datetime.now(timezone.utc).isoformat(),
        }
        logger.info("app installation created", installation_id=installation_id, account=account_login)

    elif action in {"deleted", "suspend"}:
        _installations.pop(installation_id, None)
        logger.info("app installation removed", installation_id=installation_id, action=action)


async def _handle_app_pull_request(payload: dict[str, Any]) -> None:
    """Forward App pull_request events into the existing review pipeline."""
    from app.services.webhook_processor import process_pr_webhook

    action = payload.get("action", "")
    if action not in {"opened", "synchronize", "reopened"}:
        return

    pr = payload.get("pull_request", {})
    repo_full = payload.get("repository", {}).get("full_name", "")
    if not repo_full:
        return

    owner, _, repo = repo_full.partition("/")
    pull_number: int = pr.get("number", 0)
    head_sha: str = pr.get("head", {}).get("sha", "")

    if not (owner and repo and pull_number and head_sha):
        return

    logger.info(
        "app webhook: dispatching pr review",
        repo=repo_full,
        pr=pull_number,
        sha=head_sha[:8],
    )
    await process_pr_webhook(owner=owner, repo=repo, pull_number=pull_number, head_sha=head_sha)


@github_app_router.post("/app/webhook")
async def github_app_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict[str, str]:
    """Receive and dispatch GitHub App webhook events.

    Handles: installation, pull_request, push.
    Signature is verified with ODIN_GITHUB_APP_WEBHOOK_SECRET.
    """
    payload_bytes = await request.body()
    sig_header = request.headers.get("X-Hub-Signature-256")

    if not _verify_app_webhook_signature(payload_bytes, sig_header):
        logger.warning("app webhook signature verification failed")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event_type = request.headers.get("X-GitHub-Event", "")
    payload: dict[str, Any] = json.loads(payload_bytes)

    if event_type == "installation":
        background_tasks.add_task(_handle_installation_event, payload)
        return {"status": "accepted", "event": "installation"}

    if event_type == "pull_request":
        background_tasks.add_task(_handle_app_pull_request, payload)
        return {"status": "accepted", "event": "pull_request"}

    logger.debug("app webhook: ignored event", event_name=event_type)
    return {"status": "ignored", "reason": f"event '{event_type}' not handled"}
