from __future__ import annotations

from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    name: str
    kind: str  # "function" | "class" | "module"
    file_path: str
    language: str
    line_start: int | None = None
    line_end: int | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    relationship: str  # "CALLS" | "IMPORTS" | "INHERITS" | "CONTAINS"
    metadata: dict[str, object] = Field(default_factory=dict)


class CallerInfo(BaseModel):
    name: str
    file_path: str
    kind: str


class CalleeInfo(BaseModel):
    name: str
    file_path: str


class CodebaseContext(BaseModel):
    """Graph RAG context returned to review agents."""

    queried_names: list[str] = Field(default_factory=list)
    callers: list[CallerInfo] = Field(default_factory=list)
    callees: list[CalleeInfo] = Field(default_factory=list)
    siblings: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    parent_class: str | None = None
