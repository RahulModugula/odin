import operator
from typing import Annotated, NotRequired, TypedDict

from app.models.schemas import AgentOutput, CodeMetrics, Finding


class ReviewState(TypedDict):
    code: str
    language: str
    ast_summary: str
    metrics: CodeMetrics
    findings: Annotated[list[Finding], operator.add]
    agent_outputs: Annotated[list[AgentOutput], operator.add]
    overall_score: int
    summary: str
    codebase_context: str
    file_path: str | None
    # PR-context fields (optional — not set when using the direct /review API)
    diff: NotRequired[str]
    changed_lines: NotRequired[list[tuple[int, int]]]
    pr_context: NotRequired[dict]


class AgentInput(TypedDict):
    code: str
    language: str
    ast_summary: str
    metrics: CodeMetrics
    codebase_context: str
