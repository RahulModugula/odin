"""Data schemas for the dataflow-guided LLM triage pipeline.

Architecture reference: LLift (OOPSLA 2024), INFERROI (ICSE 2025), QLCoder (ICSE 2025).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from app.models.enums import Language


class SourceKind(StrEnum):
    HTTP_PARAM = "http_param"
    HTTP_BODY = "http_body"
    ENV_VAR = "env_var"
    FILE_READ = "file_read"
    ARGV = "argv"
    DESERIALIZED = "deserialized"
    NETWORK = "network"
    DB_READ = "db_read"
    USER_INPUT = "user_input"


class SinkKind(StrEnum):
    CODE_EXEC = "code_exec"        # eval, exec, compile
    SHELL_EXEC = "shell_exec"      # os.system, subprocess(shell=True)
    SQL_QUERY = "sql_query"        # cursor.execute(f"...")
    DOM_WRITE = "dom_write"        # innerHTML, document.write
    PATH_TRAVERSAL = "path_traversal"  # open(user_input)
    SSRF_FETCH = "ssrf_fetch"      # requests.get(user_url)
    TEMPLATE_RENDER = "template_render"  # render(user_template)
    DESERIALIZED = "deserialized"  # pickle.loads, yaml.load


@dataclass(frozen=True)
class SourceSpec:
    kind: SourceKind
    language: Language
    # Pattern descriptors — at least one must be set
    call_pattern: str | None = None   # function call e.g. "request.args.get"
    attr_pattern: str | None = None   # attribute access e.g. "request.form"
    module: str | None = None         # for grouping / display
    signature: str = ""               # stable fingerprint

    def __post_init__(self) -> None:
        if not self.signature:
            raw = f"{self.kind}:{self.language}:{self.call_pattern}:{self.attr_pattern}"
            object.__setattr__(self, "signature", hashlib.sha256(raw.encode()).hexdigest()[:12])


@dataclass(frozen=True)
class SinkSpec:
    kind: SinkKind
    language: Language
    call_pattern: str               # function/method name pattern
    tainted_arg_positions: tuple[int, ...] | Literal["all"] = "all"
    kwarg_conditions: dict[str, str] = field(default_factory=dict)
    module: str | None = None
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.signature:
            raw = f"{self.kind}:{self.language}:{self.call_pattern}"
            object.__setattr__(self, "signature", hashlib.sha256(raw.encode()).hexdigest()[:12])


@dataclass
class TaintHop:
    """One step in a taint propagation chain."""
    line: int
    col: int
    variable: str
    operation: Literal["assign", "param", "return", "augment", "fstring", "call_arg", "subscript"]
    snippet: str  # the line text


@dataclass
class TaintCandidate:
    """A potential source→sink taint path, pre-LLM-triage."""
    candidate_id: str
    language: Language
    function_name: str | None
    source: SourceSpec
    source_location: tuple[int, int]   # (line, col)
    sink: SinkSpec
    sink_location: tuple[int, int]     # (line, col)
    hops: list[TaintHop]
    snippet: str                       # multi-line context for LLM

    @classmethod
    def make_id(
        cls,
        source_sig: str,
        sink_sig: str,
        function_name: str | None,
        sink_line: int,
    ) -> str:
        raw = f"{source_sig}:{sink_sig}:{function_name}:{sink_line}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class TriageVerdict:
    """LLM judgment on one TaintCandidate."""
    candidate_id: str
    exploitable: bool
    confidence: float          # 0.0–1.0
    exploit_scenario: str      # "an attacker can ... to achieve ..."
    suggested_sanitizer: str
    reasoning: str
