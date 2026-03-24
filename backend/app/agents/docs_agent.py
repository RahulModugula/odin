import time

import structlog
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel, Field

from app.agents.prompts import DOCS_SYSTEM_PROMPT, build_review_prompt
from app.config import settings
from app.models.enums import Category, Severity
from app.models.schemas import AgentOutput, Finding

logger = structlog.get_logger()


class DocsFinding(BaseModel):
    """A single documentation finding."""

    severity: Severity
    title: str
    description: str
    line_start: int | None = None
    line_end: int | None = None
    suggestion: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


class DocsReviewOutput(BaseModel):
    """Structured output from the documentation review agent."""

    findings: list[DocsFinding] = []


async def run_docs_agent(
    state: dict,  # type: ignore[type-arg]
    config: RunnableConfig | None = None,
) -> dict:  # type: ignore[type-arg]
    start = time.perf_counter()

    try:
        llm = ChatAnthropic(
            model=settings.llm_model,
            api_key=settings.anthropic_api_key,
            temperature=0,
            max_tokens=4096,
        )
        structured_llm = llm.with_structured_output(DocsReviewOutput)

        prompt = build_review_prompt(
            state["code"],
            state["language"],
            state["ast_summary"],
            state.get("codebase_context", ""),
        )
        messages = [
            SystemMessage(content=DOCS_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]

        result = await structured_llm.ainvoke(messages, config=config)
        findings = [
            Finding(
                severity=f.severity,
                category=Category.DOCUMENTATION,
                title=f.title,
                description=f.description,
                line_start=f.line_start,
                line_end=f.line_end,
                suggestion=f.suggestion,
                confidence=f.confidence,
            )
            for f in result.findings
        ]
    except Exception as e:
        logger.error("docs agent failed", error=str(e))
        findings = []

    elapsed = (time.perf_counter() - start) * 1000
    agent_output = AgentOutput(
        agent_name="documentation",
        findings=findings,
        execution_time_ms=round(elapsed, 2),
    )

    return {
        "findings": findings,
        "agent_outputs": [agent_output],
    }
