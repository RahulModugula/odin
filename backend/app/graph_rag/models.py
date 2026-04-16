from __future__ import annotations

from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    name: str
    kind: str  # "function" | "class" | "module" | "type" | "decorator" | "interface"
    file_path: str
    language: str
    line_start: int | None = None
    line_end: int | None = None
    signature: str | None = None
    decorators: list[str] = Field(default_factory=list)
    param_types: list[str] = Field(default_factory=list)
    return_type: str | None = None
    docstring: str | None = None
    parent_class_name: str | None = None
    source_hash: str | None = None
    embedding_id: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    relationship: str  # noqa: E501 — CALLS|IMPORTS|INHERITS|CONTAINS|IMPLEMENTS|OVERRIDES|USES_TYPE|DATAFLOWS_TO|HAS_DECORATOR
    weight: float = 1.0
    metadata: dict[str, object] = Field(default_factory=dict)


class CallerInfo(BaseModel):
    name: str
    file_path: str
    kind: str
    signature: str | None = None
    decorators: list[str] = Field(default_factory=list)
    line_start: int | None = None
    line_end: int | None = None


class CalleeInfo(BaseModel):
    name: str
    file_path: str
    signature: str | None = None
    line_start: int | None = None
    line_end: int | None = None


class DataflowPath(BaseModel):
    source_name: str
    sink_name: str
    source_file: str
    sink_file: str
    source_kind: str
    sink_kind: str
    hops: list[str] = Field(default_factory=list)


class InheritanceInfo(BaseModel):
    class_name: str
    parent_class: str
    file_path: str
    overridden_methods: list[str] = Field(default_factory=list)


class CodebaseContext(BaseModel):
    queried_names: list[str] = Field(default_factory=list)
    callers: list[CallerInfo] = Field(default_factory=list)
    callees: list[CalleeInfo] = Field(default_factory=list)
    siblings: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    parent_class: str | None = None
    inheritance: list[InheritanceInfo] = Field(default_factory=list)
    decorators: list[str] = Field(default_factory=list)
    dataflow_paths: list[DataflowPath] = Field(default_factory=list)
    overridden_methods: list[str] = Field(default_factory=list)
    cross_file_relations: list[str] = Field(default_factory=list)
