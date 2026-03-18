import operator
from typing import Annotated, TypedDict

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


class AgentInput(TypedDict):
    code: str
    language: str
    ast_summary: str
    metrics: CodeMetrics
