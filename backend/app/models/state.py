import operator
from typing import Annotated, Any, NotRequired, TypedDict

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
    diff: NotRequired[str]
    changed_lines: NotRequired[list[tuple[int, int]]]
    pr_context: NotRequired[dict[str, Any]]
    pr_context_files: NotRequired[dict[str, list[str]]]
    ai_generated: NotRequired[bool]  # lowers confidence floor + reshapes prompts


class AgentInput(TypedDict):
    code: str
    language: str
    ast_summary: str
    metrics: CodeMetrics
    codebase_context: str
    diff: NotRequired[str]  # unified diff patch — agents focus on changed lines
    changed_lines: NotRequired[list[tuple[int, int]]]  # [(start, end), ...]
    pr_context: NotRequired[dict[str, Any]]  # PR title, description, author
    ai_generated: NotRequired[bool]  # signal that the code under review was AI-produced
