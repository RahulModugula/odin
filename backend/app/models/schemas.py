import uuid

from pydantic import BaseModel, Field

from app.models.enums import Category, Language, Severity


class ReviewRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=100_000)
    language: Language = Language.PYTHON
    filename: str | None = None


class FunctionInfo(BaseModel):
    name: str
    line_start: int
    line_end: int
    param_count: int
    body_length: int
    has_docstring: bool = False


class ClassInfo(BaseModel):
    name: str
    line_start: int
    line_end: int
    method_count: int
    has_docstring: bool = False


class CodeMetrics(BaseModel):
    lines_of_code: int
    num_functions: int
    num_classes: int
    avg_function_length: float
    max_function_length: int
    max_nesting_depth: int
    cyclomatic_complexity: int
    comment_ratio: float
    import_count: int


class CodeStructure(BaseModel):
    functions: list[FunctionInfo] = []
    classes: list[ClassInfo] = []
    imports: list[str] = []
    metrics: CodeMetrics


class Finding(BaseModel):
    severity: Severity
    category: Category
    title: str
    description: str
    line_start: int | None = None
    line_end: int | None = None
    suggestion: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    source: str | None = None  # "rule" | "ai"


class AgentOutput(BaseModel):
    agent_name: str
    findings: list[Finding] = []
    execution_time_ms: float = 0.0


class ReviewResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    metrics: CodeMetrics
    findings: list[Finding] = []
    overall_score: int = Field(ge=0, le=100, default=100)
    summary: str = ""
    agent_outputs: list[AgentOutput] = []
    total_time_ms: float = 0.0
    language: Language
    cached: bool = False
