"""PR-level summary agent — generates walkthrough and change summary."""

import json

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.llm import get_llm

logger = structlog.get_logger()

PR_SUMMARY_SYSTEM_PROMPT = """You are a senior software engineer writing PR review summaries.

Given a list of changed files and their diffs, generate:
1. A concise one-paragraph summary of what this PR does
2. A walkthrough table of file changes
3. A change type classification
4. A risk assessment

Respond with JSON:
{
  "summary": "One paragraph describing the PR's purpose and main changes",
  "change_type": "feature|bugfix|refactor|docs|tests|chore|security",
  "risk": "low|medium|high",
  "risk_reason": "brief explanation of why this risk level",
  "walkthrough": [
    {"file": "path/to/file.py", "change": "Brief description of what changed in this file"}
  ]
}"""


async def generate_pr_summary(
    pr_title: str,
    pr_body: str,
    file_changes: list[dict],  # [{filename, patch, additions, deletions}]
) -> dict:  # type: ignore[type-arg]
    """Generate a PR-level summary using LLM."""
    # Build a condensed view of changes (don't send full diffs, too expensive)
    changes_text = []
    for f in file_changes[:15]:  # cap at 15 files for context
        fname = f.get("filename", "")
        additions = f.get("additions", 0)
        deletions = f.get("deletions", 0)
        patch = f.get("patch", "")
        # Include first 30 lines of diff
        patch_preview = "\n".join(patch.splitlines()[:30]) if patch else "(no diff available)"
        header = f"### {fname} (+{additions}/-{deletions})"
        changes_text.append(f"{header}\n```diff\n{patch_preview}\n```")

    prompt = f"""PR Title: {pr_title}

PR Description: {pr_body or "(no description)"}

## Changed Files:
{chr(10).join(changes_text)}

Generate the PR summary JSON."""

    try:
        llm = get_llm()
        messages = [
            SystemMessage(content=PR_SUMMARY_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]
        response = await llm.ainvoke(messages)
        content = response.content

        # Extract JSON
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]

        return json.loads(content.strip())
    except Exception as e:
        logger.warning("pr summary generation failed", error=str(e))
        return {
            "summary": f"PR modifies {len(file_changes)} file(s).",
            "change_type": "unknown",
            "risk": "medium",
            "risk_reason": "Unable to assess — review required",
            "walkthrough": [
                {"file": f["filename"], "change": "Modified"} for f in file_changes[:10]
            ],
        }
