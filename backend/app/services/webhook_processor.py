"""Orchestrates GitHub PR webhook processing: fetch changed files, review each, post results."""

import asyncio
from pathlib import Path
from typing import Any

import structlog

from app.agents.graph import review_graph
from app.config import settings
from app.models.enums import Language, Severity
from app.models.schemas import Finding, ReviewResult
from app.models.state import ReviewState
from app.services.github_client import (
    GithubClientError,
    GithubRateLimitError,
    create_pr_review,
    get_file_content,
    get_pr_files,
)

logger = structlog.get_logger()

MAX_FILES_PER_PR = 20

EXTENSION_TO_LANGUAGE: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".go": Language.GO,
}

LOCK_FILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "go.sum",
    "Cargo.lock",
    "go.mod",
}


def detect_language(filename: str) -> Language | None:
    """Return the Language for a filename based on extension, or None if unsupported."""
    return EXTENSION_TO_LANGUAGE.get(Path(filename).suffix.lower())


def should_skip_file(filename: str, status: str) -> bool:
    """Return True if the file should be excluded from review."""
    path = Path(filename)

    # Only review added or modified files
    if status not in {"added", "modified"}:
        return True

    # Unsupported extension
    if path.suffix.lower() not in EXTENSION_TO_LANGUAGE:
        return True

    # Lock files / generated files
    if path.name in LOCK_FILE_NAMES:
        return True

    # Minified files
    if filename.endswith(".min.js") or filename.endswith(".min.ts"):
        return True

    # Vendored / node_modules
    parts = filename.replace("\\", "/").split("/")
    if "vendor" in parts or "node_modules" in parts:
        return True

    return False


async def _review_single_file(
    owner: str,
    repo: str,
    ref: str,
    filename: str,
    language: Language,
) -> ReviewResult | None:
    """Fetch and review a single file. Returns None on any error."""
    try:
        content = await get_file_content(owner, repo, ref, filename)
        if content is None:
            logger.debug("skipping file (no content)", filename=filename)
            return None

        state: ReviewState = {
            "code": content,
            "language": language.value,
            "ast_summary": "",
            "metrics": None,  # type: ignore[typeddict-item]
            "findings": [],
            "agent_outputs": [],
            "overall_score": 100,
            "summary": "",
            "codebase_context": "",
            "file_path": filename,
        }
        result: dict[str, Any] = await review_graph.ainvoke(state, config={"callbacks": []})

        return ReviewResult(
            metrics=result["metrics"],
            findings=result["findings"],
            overall_score=result["overall_score"],
            summary=result["summary"],
            agent_outputs=result.get("agent_outputs", []),
            language=language,
        )
    except Exception as exc:
        logger.error("failed to review file", filename=filename, error=str(exc))
        return None


def _severity_sort_key(s: Severity) -> int:
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    return order.get(s, 99)


def _build_review_body(
    file_results: list[tuple[str, ReviewResult | None]],
) -> str:
    """Build the top-level markdown body for the GitHub PR review."""
    lines = ["## Odin AI Code Review\n"]

    # Summary table
    lines.append("| File | Score | Issues |")
    lines.append("|------|-------|--------|")

    general_findings: list[tuple[str, Finding]] = []

    for filename, result in file_results:
        if result is None:
            lines.append(f"| `{filename}` | — | Review failed |")
            continue

        counts: dict[str, int] = {}
        for f in result.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        issue_parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            if counts.get(sev, 0) > 0:
                issue_parts.append(f"{counts[sev]} {sev}")
        issues_str = ", ".join(issue_parts) if issue_parts else "none"

        lines.append(f"| `{filename}` | {result.overall_score}/100 | {issues_str} |")

        # Collect findings without line numbers for the general section
        for finding in result.findings:
            if finding.line_start is None:
                general_findings.append((filename, finding))

    total_findings = sum(
        len(r.findings) for _, r in file_results if r is not None
    )
    reviewed = sum(1 for _, r in file_results if r is not None)
    lines.append(f"\n**{total_findings} total findings** across {reviewed} file(s)\n")

    if general_findings:
        lines.append("### General Findings\n")
        for filename, finding in general_findings:
            lines.append(
                f"**`{filename}`** — **[{finding.severity.upper()}/{finding.category.upper()}]** "
                f"{finding.title}\n\n{finding.description}\n"
            )
            if finding.suggestion:
                lines.append(f"> {finding.suggestion}\n")

    lines.append("---")
    lines.append("_Powered by [Odin](https://github.com/rahulvramesh/odin) — AI-powered multi-agent code review_")

    return "\n".join(lines)


def _build_inline_comments(
    filename: str,
    result: ReviewResult,
) -> list[dict]:  # type: ignore[type-arg]
    """Build GitHub inline review comment objects for findings that have line numbers."""
    comments = []
    for finding in sorted(result.findings, key=lambda f: _severity_sort_key(f.severity)):
        if finding.line_start is None:
            continue

        body_parts = [
            f"**[{finding.severity.upper()}/{finding.category.upper()}]** {finding.title}",
            "",
            finding.description,
        ]
        if finding.suggestion:
            body_parts.extend(["", f"> **Suggestion:** {finding.suggestion}"])
        body_parts.extend(["", f"_Confidence: {finding.confidence:.0%}_"])

        comments.append(
            {
                "path": filename,
                "line": finding.line_start,
                "side": "RIGHT",
                "body": "\n".join(body_parts),
            }
        )

    return comments


async def process_pr_webhook(
    owner: str,
    repo: str,
    pull_number: int,
    head_sha: str,
    installation_id: int | None = None,
) -> None:
    """Entry point for background PR review processing.

    Fetches changed files, reviews each concurrently, and posts a GitHub PR review.
    Designed to run as a FastAPI BackgroundTask — never raises, always logs errors.
    """
    log = logger.bind(repo=f"{owner}/{repo}", pr=pull_number, sha=head_sha[:8])

    if not settings.github_token:
        log.warning("ODIN_GITHUB_TOKEN not set — skipping PR review")
        return

    try:
        pr_files = await get_pr_files(owner, repo, pull_number)
    except (GithubClientError, GithubRateLimitError) as exc:
        log.error("failed to fetch PR files", error=str(exc))
        return

    # Filter to qualifying files
    qualifying = [
        f for f in pr_files
        if not should_skip_file(f["filename"], f.get("status", ""))
    ]

    if not qualifying:
        log.info("no qualifying files to review")
        try:
            await create_pr_review(
                owner, repo, pull_number, head_sha,
                body="## Odin AI Code Review\n\nNo files in supported languages (Python, JavaScript, TypeScript, Go) found in this PR.",
                comments=[],
            )
        except Exception as exc:
            log.error("failed to post empty review", error=str(exc))
        return

    # Sort by most-changed files first; cap at MAX_FILES_PER_PR
    qualifying.sort(key=lambda f: f.get("changes", 0), reverse=True)
    skipped_count = max(0, len(qualifying) - MAX_FILES_PER_PR)
    qualifying = qualifying[:MAX_FILES_PER_PR]

    log.info("starting pr review", files=len(qualifying), skipped=skipped_count)

    # Fan out: review all files concurrently
    tasks = [
        _review_single_file(
            owner, repo, head_sha,
            f["filename"],
            detect_language(f["filename"]),  # type: ignore[arg-type]
        )
        for f in qualifying
    ]
    results: list[ReviewResult | None] = await asyncio.gather(*tasks)

    file_results: list[tuple[str, ReviewResult | None]] = [
        (f["filename"], result)
        for f, result in zip(qualifying, results, strict=True)
    ]

    # Build review body
    review_body = _build_review_body(file_results)
    if skipped_count > 0:
        review_body += (
            f"\n\n> ⚠️ {skipped_count} additional file(s) were not reviewed "
            f"(PR exceeds {MAX_FILES_PER_PR}-file limit)."
        )

    # Build inline comments
    all_comments: list[dict] = []  # type: ignore[type-arg]
    for filename, result in file_results:
        if result is not None:
            all_comments.extend(_build_inline_comments(filename, result))

    try:
        await create_pr_review(
            owner, repo, pull_number, head_sha,
            body=review_body,
            comments=all_comments,
        )
    except GithubRateLimitError as exc:
        log.warning("rate limited posting review", retry_after=exc.retry_after)
    except GithubClientError as exc:
        log.error("failed to post pr review", error=str(exc), status=exc.status_code)
    except Exception as exc:
        log.error("unexpected error posting review", error=str(exc))
