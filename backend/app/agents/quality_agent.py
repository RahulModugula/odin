import time

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel, Field

from app.agents.llm import get_llm
from app.agents.prompts import QUALITY_SYSTEM_PROMPT, build_review_prompt
from app.models.enums import Category, Severity
from app.models.schemas import AgentOutput, Finding

logger = structlog.get_logger()


class QualityFinding(BaseModel):
    severity: Severity
    title: str
    description: str
    line_start: int | None = None
    line_end: int | None = None
    suggestion: str | None = None
    fix_code: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


class QualityReviewOutput(BaseModel):
    findings: list[QualityFinding] = []


async def run_quality_agent(
    state: dict,  # type: ignore[type-arg]
    config: RunnableConfig | None = None,
) -> dict:  # type: ignore[type-arg]
    start = time.perf_counter()

    try:
        structured_llm = get_llm().with_structured_output(QualityReviewOutput, method="json_mode")

        codebase_context = state.get("codebase_context", "")

        try:
            from app.agents.tools import REVIEW_TOOLS

            tool_context_parts: list[str] = []
            for tool_fn in REVIEW_TOOLS:
                if hasattr(tool_fn, "name") and hasattr(tool_fn, "description"):
                    tool_context_parts.append(f"- {tool_fn.name}: {tool_fn.description}")
            if tool_context_parts:
                codebase_context += (
                    "\n\n**Available retrieval tools** (ask for more context if needed):\n"
                    + "\n".join(tool_context_parts)
                )
        except Exception:
            pass

        prompt = build_review_prompt(
            state["code"],
            state["language"],
            state["ast_summary"],
            codebase_context,
            diff=state.get("diff", ""),
            changed_lines=state.get("changed_lines"),
            pr_context=state.get("pr_context"),
            ai_generated=bool(state.get("ai_generated", False)),
        )
        messages = [
            SystemMessage(content=QUALITY_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]

        result = await structured_llm.ainvoke(messages, config=config)
        findings = [
            Finding(
                severity=f.severity,
                category=Category.QUALITY,
                title=f.title,
                description=f.description,
                line_start=f.line_start,
                line_end=f.line_end,
                suggestion=f.suggestion,
                fix_code=f.fix_code,
                confidence=f.confidence,
                source="ai",
            )
            for f in result.findings  # type: ignore[union-attr]
        ]
    except Exception as e:
        logger.error("quality agent failed", error=str(e))
        findings = []

    elapsed = (time.perf_counter() - start) * 1000
    agent_output = AgentOutput(
        agent_name="quality",
        findings=findings,
        execution_time_ms=round(elapsed, 2),
    )

    return {
        "findings": findings,
        "agent_outputs": [agent_output],
    }
