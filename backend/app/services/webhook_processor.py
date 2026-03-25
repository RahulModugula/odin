"""Orchestrates GitHub PR webhook processing: fetch changed files, review each, post results."""

import asyncio
import re
from pathlib import Path
from typing import Any

import structlog

from app.agents.graph import review_graph
from app.agents.summary_agent import generate_pr_summary
from app.config import settings
from app.models.enums import Language, Severity
from app.models.schemas import Finding, ReviewResult
from app.models.state import ReviewState
from app.services.github_client import (
    GithubClientError,
    GithubRateLimitError,
    create_pr_review,
    get_file_content,
    get_pr_details,
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
    return bool("vendor" in parts or "node_modules" in parts)


def _parse_changed_lines(patch: str | None) -> list[tuple[int, int]]:
    """Extract changed line ranges from a unified diff patch."""
    if not patch:
        return []

    ranges = []

    for line in patch.splitlines():
        if line.startswith("@@"):
            # Parse @@ -old_start,old_count +new_start,new_count @@
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) else 1
                if count > 0:
                    ranges.append((start, start + count - 1))

    return ranges


async def _review_single_file(
    owner: str,
    repo: str,
    ref: str,
    filename: str,
    language: Language,
    patch: str | None = None,
    changed_lines: list[tuple[int, int]] | None = None,
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
            "diff": patch or "",
            "changed_lines": changed_lines or [],
            "pr_context": {},
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
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    return order.get(s, 99)


def _build_review_body(
    file_results: list[tuple[str, ReviewResult | None]],
    pr_summary: dict | None = None,  # type: ignore[type-arg]
    pr_context: dict | None = None,  # type: ignore[type-arg]
) -> str:
    """Build the top-level markdown body for the GitHub PR review."""
    lines = []

    # Header with branding
    lines.append("## Odin Code Review\n")

    # PR Summary section (if available)
    if pr_summary:
        change_type = pr_summary.get("change_type", "unknown")
        risk = pr_summary.get("risk", "medium")
        risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(risk, "🟡")
        type_emoji = {
            "feature": "✨",
            "bugfix": "🐛",
            "refactor": "♻️",
            "docs": "📚",
            "tests": "🧪",
            "security": "🔒",
            "chore": "🔧",
        }.get(change_type, "📦")

        lines.append(f"### {type_emoji} Summary")
        lines.append(f"{pr_summary.get('summary', '')}\n")
        lines.append(f"**Type:** {change_type} &nbsp; **Risk:** {risk_emoji} {risk}")
        if pr_summary.get("risk_reason"):
            lines.append(f"  \n*{pr_summary['risk_reason']}*")
        lines.append("")

        # Walkthrough table
        walkthrough = pr_summary.get("walkthrough", [])
        if walkthrough:
            lines.append("<details>")
            lines.append("<summary>📋 Walkthrough</summary>\n")
            lines.append("| File | Change |")
            lines.append("|------|--------|")
            for item in walkthrough:
                fname = item.get("file", "")
                change = item.get("change", "")
                lines.append(f"| `{fname}` | {change} |")
            lines.append("</details>\n")

    # File review table
    lines.append("### 📊 File Review Summary\n")
    lines.append("| File | Score | Critical | High | Medium | Low |")
    lines.append("|------|-------|----------|------|--------|-----|")

    general_findings: list[tuple[str, Finding]] = []
    total_score = 0
    reviewed_count = 0

    for filename, result in file_results:
        if result is None:
            lines.append(f"| `{filename}` | — | — | — | — | — |")
            continue

        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in result.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        s = result.overall_score
        score_emoji = "🟢" if s >= 80 else "🟡" if s >= 60 else "🔴"
        lines.append(
            f"| `{filename}` | {score_emoji} {result.overall_score}/100 | "
            f"{counts['critical'] or '—'} | {counts['high'] or '—'} | "
            f"{counts['medium'] or '—'} | {counts['low'] or '—'} |"
        )
        total_score += result.overall_score
        reviewed_count += 1

        for finding in result.findings:
            if finding.line_start is None:
                general_findings.append((filename, finding))

    if reviewed_count > 0:
        avg_score = total_score // reviewed_count
        score_emoji = "🟢" if avg_score >= 80 else "🟡" if avg_score >= 60 else "🔴"
        total_findings = sum(len(r.findings) for _, r in file_results if r is not None)
        lines.append(
            f"\n**Overall Score: {score_emoji} {avg_score}/100** &nbsp; | &nbsp; "
            f"**{total_findings} finding(s)** across {reviewed_count} file(s)\n"
        )

    # General findings (no line numbers)
    if general_findings:
        lines.append("<details>")
        lines.append("<summary>📝 General Findings</summary>\n")
        for filename, finding in general_findings[:10]:
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪",
            }.get(finding.severity.value, "⚪")
            lines.append(f"**`{filename}`** {severity_emoji} **{finding.title}**")
            lines.append(f"\n{finding.description}\n")
            if finding.suggestion:
                lines.append(f"> 💡 {finding.suggestion}\n")
        lines.append("</details>\n")

    # Footer
    lines.append("---")
    lines.append(
        "*[Odin](https://github.com/odin-review/odin) — Open-source AI code review. "
        "Self-host with LM Studio or OpenRouter.*"
    )
    lines.append(
        "*Configure via `.odin.yaml` • [Docs](https://github.com/odin-review/odin#configuration)*"
    )

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

        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }.get(finding.severity.value, "⚪")
        category = finding.category.value.upper()

        body_parts = [
            f"{severity_emoji} **[{finding.severity.value.upper()}/{category}]** {finding.title}",
            "",
            finding.description,
        ]
        if finding.suggestion:
            body_parts.extend(["", f"> 💡 **Suggestion:** {finding.suggestion}"])
        body_parts.extend(["", f"*Confidence: {finding.confidence:.0%}*"])

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

    # Fetch PR metadata and file list concurrently
    try:
        pr_details, pr_files = await asyncio.gather(
            get_pr_details(owner, repo, pull_number),
            get_pr_files(owner, repo, pull_number),
        )
    except (GithubClientError, GithubRateLimitError) as exc:
        log.error("failed to fetch PR data", error=str(exc))
        return

    # Filter to qualifying files
    qualifying = [f for f in pr_files if not should_skip_file(f["filename"], f.get("status", ""))]

    if not qualifying:
        log.info("no qualifying files to review")
        try:
            await create_pr_review(
                owner,
                repo,
                pull_number,
                head_sha,
                body=(
                    "## Odin Code Review\n\n"
                    "No files in supported languages (Python, JavaScript, TypeScript, Go) "
                    "found in this PR."
                ),
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

    # Generate PR-level summary using the LLM before per-file reviews
    pr_summary: dict | None = None  # type: ignore[type-arg]
    try:
        pr_summary = await generate_pr_summary(
            pr_title=pr_details.get("title", ""),
            pr_body=pr_details.get("body", ""),
            file_changes=pr_files,
        )
        log.debug(
            "pr summary generated",
            change_type=pr_summary.get("change_type"),
            risk=pr_summary.get("risk"),
        )
    except Exception as exc:
        log.warning("pr summary generation failed, continuing without it", error=str(exc))

    # Fan out: review all files concurrently, passing diff context
    tasks = [
        _review_single_file(
            owner,
            repo,
            head_sha,
            f["filename"],
            detect_language(f["filename"]),  # type: ignore[arg-type]
            patch=f.get("patch"),
            changed_lines=_parse_changed_lines(f.get("patch")),
        )
        for f in qualifying
    ]
    results: list[ReviewResult | None] = await asyncio.gather(*tasks)

    file_results: list[tuple[str, ReviewResult | None]] = [
        (f["filename"], result) for f, result in zip(qualifying, results, strict=True)
    ]

    # Build review body with PR summary
    review_body = _build_review_body(
        file_results,
        pr_summary=pr_summary,
        pr_context=pr_details,
    )
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
            owner,
            repo,
            pull_number,
            head_sha,
            body=review_body,
            comments=all_comments,
        )
    except GithubRateLimitError as exc:
        log.warning("rate limited posting review", retry_after=exc.retry_after)
    except GithubClientError as exc:
        log.error("failed to post pr review", error=str(exc), status=exc.status_code)
    except Exception as exc:
        log.error("unexpected error posting review", error=str(exc))
