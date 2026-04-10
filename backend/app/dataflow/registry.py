"""Source, sink, and sanitizer registries — data-driven, language-dispatched.

Rather than hardcoding patterns in Python, each registry is populated from
declarative spec lists. This makes it easy for contributors to add patterns
without touching the core analysis engine.
"""

from __future__ import annotations

from app.dataflow.schemas import SinkKind, SinkSpec, SourceKind, SourceSpec
from app.models.enums import Language

# ─────────────────────────────────────────────────────────────────────────────
# Python sources — taint entry points
# ─────────────────────────────────────────────────────────────────────────────

_PYTHON_SOURCES: list[SourceSpec] = [
    # Flask / Starlette / FastAPI
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.PYTHON, call_pattern="request.args.get", module="flask"),
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.PYTHON, attr_pattern="request.args", module="flask"),
    SourceSpec(kind=SourceKind.HTTP_BODY, language=Language.PYTHON, attr_pattern="request.form", module="flask"),
    SourceSpec(kind=SourceKind.HTTP_BODY, language=Language.PYTHON, attr_pattern="request.json", module="flask"),
    SourceSpec(kind=SourceKind.HTTP_BODY, language=Language.PYTHON, attr_pattern="request.data", module="flask"),
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.PYTHON, call_pattern="request.get_json", module="flask"),
    # Django
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.PYTHON, attr_pattern="request.GET", module="django"),
    SourceSpec(kind=SourceKind.HTTP_BODY, language=Language.PYTHON, attr_pattern="request.POST", module="django"),
    SourceSpec(kind=SourceKind.HTTP_BODY, language=Language.PYTHON, attr_pattern="request.body", module="django"),
    # FastAPI path/query params (function parameter heuristic — handled by tracker)
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.PYTHON, attr_pattern="Query(", module="fastapi"),
    SourceSpec(kind=SourceKind.HTTP_BODY, language=Language.PYTHON, attr_pattern="Body(", module="fastapi"),
    # Env vars
    SourceSpec(kind=SourceKind.ENV_VAR, language=Language.PYTHON, call_pattern="os.environ.get"),
    SourceSpec(kind=SourceKind.ENV_VAR, language=Language.PYTHON, attr_pattern="os.environ"),
    SourceSpec(kind=SourceKind.ENV_VAR, language=Language.PYTHON, call_pattern="os.getenv"),
    # File reads
    SourceSpec(kind=SourceKind.FILE_READ, language=Language.PYTHON, call_pattern="open("),
    SourceSpec(kind=SourceKind.FILE_READ, language=Language.PYTHON, call_pattern=".read("),
    SourceSpec(kind=SourceKind.FILE_READ, language=Language.PYTHON, call_pattern=".readline("),
    # Stdin / argv
    SourceSpec(kind=SourceKind.ARGV, language=Language.PYTHON, attr_pattern="sys.argv"),
    SourceSpec(kind=SourceKind.USER_INPUT, language=Language.PYTHON, call_pattern="input("),
    # Deserialization
    SourceSpec(kind=SourceKind.DESERIALIZED, language=Language.PYTHON, call_pattern="pickle.loads"),
    SourceSpec(kind=SourceKind.DESERIALIZED, language=Language.PYTHON, call_pattern="json.loads"),
    SourceSpec(kind=SourceKind.DESERIALIZED, language=Language.PYTHON, call_pattern="yaml.load"),
    SourceSpec(kind=SourceKind.DESERIALIZED, language=Language.PYTHON, call_pattern="yaml.safe_load"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Python sinks — dangerous operations
# ─────────────────────────────────────────────────────────────────────────────

_PYTHON_SINKS: list[SinkSpec] = [
    # Code execution
    SinkSpec(kind=SinkKind.CODE_EXEC, language=Language.PYTHON, call_pattern="eval(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.CODE_EXEC, language=Language.PYTHON, call_pattern="exec(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.CODE_EXEC, language=Language.PYTHON, call_pattern="compile(", tainted_arg_positions=(0,)),
    # Shell execution
    SinkSpec(kind=SinkKind.SHELL_EXEC, language=Language.PYTHON, call_pattern="os.system(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SHELL_EXEC, language=Language.PYTHON, call_pattern="os.popen(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SHELL_EXEC, language=Language.PYTHON, call_pattern="subprocess.run(", tainted_arg_positions=(0,), kwarg_conditions={"shell": "True"}),
    SinkSpec(kind=SinkKind.SHELL_EXEC, language=Language.PYTHON, call_pattern="subprocess.call(", tainted_arg_positions=(0,), kwarg_conditions={"shell": "True"}),
    SinkSpec(kind=SinkKind.SHELL_EXEC, language=Language.PYTHON, call_pattern="subprocess.Popen(", tainted_arg_positions=(0,), kwarg_conditions={"shell": "True"}),
    # SQL — format strings and % interpolation
    SinkSpec(kind=SinkKind.SQL_QUERY, language=Language.PYTHON, call_pattern=".execute(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SQL_QUERY, language=Language.PYTHON, call_pattern=".executemany(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SQL_QUERY, language=Language.PYTHON, call_pattern=".raw(", tainted_arg_positions=(0,)),
    # Path traversal
    SinkSpec(kind=SinkKind.PATH_TRAVERSAL, language=Language.PYTHON, call_pattern="open(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.PATH_TRAVERSAL, language=Language.PYTHON, call_pattern="Path(", tainted_arg_positions=(0,)),
    # SSRF
    SinkSpec(kind=SinkKind.SSRF_FETCH, language=Language.PYTHON, call_pattern="requests.get(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SSRF_FETCH, language=Language.PYTHON, call_pattern="requests.post(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SSRF_FETCH, language=Language.PYTHON, call_pattern="httpx.get(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SSRF_FETCH, language=Language.PYTHON, call_pattern="httpx.AsyncClient().get(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SSRF_FETCH, language=Language.PYTHON, call_pattern="client.get(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SSRF_FETCH, language=Language.PYTHON, call_pattern="urllib.request.urlopen(", tainted_arg_positions=(0,)),
    # Deserialization
    SinkSpec(kind=SinkKind.DESERIALIZED, language=Language.PYTHON, call_pattern="pickle.loads(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.DESERIALIZED, language=Language.PYTHON, call_pattern="yaml.load(", tainted_arg_positions=(0,)),
]

# ─────────────────────────────────────────────────────────────────────────────
# Python sanitizers — operations that remove taint
# ─────────────────────────────────────────────────────────────────────────────

_PYTHON_SANITIZERS: list[str] = [
    "html.escape(",
    "bleach.clean(",
    "bleach.linkify(",
    "shlex.quote(",
    "shlex.split(",
    "re.fullmatch(",
    "re.match(",
    "hashlib.",
    ".encode(",
    "int(",
    "float(",
    "str(",
    "bool(",
    "uuid.UUID(",
]

# ─────────────────────────────────────────────────────────────────────────────
# JavaScript / TypeScript sources
# ─────────────────────────────────────────────────────────────────────────────

_JS_SOURCES: list[SourceSpec] = [
    # Express.js / Fastify
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.JAVASCRIPT, attr_pattern="req.query"),
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.JAVASCRIPT, attr_pattern="req.params"),
    SourceSpec(kind=SourceKind.HTTP_BODY, language=Language.JAVASCRIPT, attr_pattern="req.body"),
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.JAVASCRIPT, attr_pattern="request.query"),
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.JAVASCRIPT, attr_pattern="request.params"),
    SourceSpec(kind=SourceKind.HTTP_BODY, language=Language.JAVASCRIPT, attr_pattern="request.body"),
    # Browser APIs
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.JAVASCRIPT, call_pattern="URLSearchParams"),
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.JAVASCRIPT, attr_pattern="location.search"),
    SourceSpec(kind=SourceKind.HTTP_PARAM, language=Language.JAVASCRIPT, attr_pattern="location.hash"),
    SourceSpec(kind=SourceKind.USER_INPUT, language=Language.JAVASCRIPT, call_pattern="document.getElementById"),
    SourceSpec(kind=SourceKind.USER_INPUT, language=Language.JAVASCRIPT, attr_pattern=".value"),
    # Env / argv
    SourceSpec(kind=SourceKind.ENV_VAR, language=Language.JAVASCRIPT, attr_pattern="process.env"),
    SourceSpec(kind=SourceKind.ARGV, language=Language.JAVASCRIPT, attr_pattern="process.argv"),
    # JSON parsing
    SourceSpec(kind=SourceKind.DESERIALIZED, language=Language.JAVASCRIPT, call_pattern="JSON.parse("),
]

_TS_SOURCES: list[SourceSpec] = [
    SourceSpec(kind=s.kind, language=Language.TYPESCRIPT, call_pattern=s.call_pattern,
               attr_pattern=s.attr_pattern, module=s.module)
    for s in _JS_SOURCES
]

# ─────────────────────────────────────────────────────────────────────────────
# JavaScript sinks
# ─────────────────────────────────────────────────────────────────────────────

_JS_SINKS: list[SinkSpec] = [
    SinkSpec(kind=SinkKind.CODE_EXEC, language=Language.JAVASCRIPT, call_pattern="eval(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.CODE_EXEC, language=Language.JAVASCRIPT, call_pattern="new Function(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.DOM_WRITE, language=Language.JAVASCRIPT, call_pattern=".innerHTML", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.DOM_WRITE, language=Language.JAVASCRIPT, call_pattern=".outerHTML", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.DOM_WRITE, language=Language.JAVASCRIPT, call_pattern="document.write(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.DOM_WRITE, language=Language.JAVASCRIPT, call_pattern="dangerouslySetInnerHTML", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SHELL_EXEC, language=Language.JAVASCRIPT, call_pattern="child_process.exec(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SHELL_EXEC, language=Language.JAVASCRIPT, call_pattern="child_process.spawn(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SHELL_EXEC, language=Language.JAVASCRIPT, call_pattern="exec(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SSRF_FETCH, language=Language.JAVASCRIPT, call_pattern="fetch(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SSRF_FETCH, language=Language.JAVASCRIPT, call_pattern="axios.get(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SQL_QUERY, language=Language.JAVASCRIPT, call_pattern=".query(", tainted_arg_positions=(0,)),
    SinkSpec(kind=SinkKind.SQL_QUERY, language=Language.JAVASCRIPT, call_pattern=".raw(", tainted_arg_positions=(0,)),
]

_TS_SINKS: list[SinkSpec] = [
    SinkSpec(kind=s.kind, language=Language.TYPESCRIPT, call_pattern=s.call_pattern,
             tainted_arg_positions=s.tainted_arg_positions, kwarg_conditions=s.kwarg_conditions)
    for s in _JS_SINKS
]

# ─────────────────────────────────────────────────────────────────────────────
# Registry classes
# ─────────────────────────────────────────────────────────────────────────────

class SourceRegistry:
    def __init__(self) -> None:
        self._sources: dict[Language, list[SourceSpec]] = {}
        for s in _PYTHON_SOURCES:
            self._sources.setdefault(s.language, []).append(s)
        for s in _JS_SOURCES + _TS_SOURCES:
            self._sources.setdefault(s.language, []).append(s)

    def get(self, language: Language) -> list[SourceSpec]:
        return self._sources.get(language, [])

    def matches(self, line: str, language: Language) -> list[SourceSpec]:
        """Return all SourceSpecs whose pattern appears in line."""
        matched = []
        for spec in self.get(language):
            if spec.call_pattern and spec.call_pattern in line or spec.attr_pattern and spec.attr_pattern in line:
                matched.append(spec)
        return matched


class SinkRegistry:
    def __init__(self) -> None:
        self._sinks: dict[Language, list[SinkSpec]] = {}
        for s in _PYTHON_SINKS:
            self._sinks.setdefault(s.language, []).append(s)
        for s in _JS_SINKS + _TS_SINKS:
            self._sinks.setdefault(s.language, []).append(s)

    def get(self, language: Language) -> list[SinkSpec]:
        return self._sinks.get(language, [])

    def matches(self, line: str, language: Language) -> list[SinkSpec]:
        """Return all SinkSpecs whose pattern appears in line."""
        matched = []
        for spec in self.get(language):
            if spec.call_pattern in line:
                matched.append(spec)
        return matched


class SanitizerRegistry:
    def __init__(self) -> None:
        self._patterns: dict[Language, list[str]] = {
            Language.PYTHON: _PYTHON_SANITIZERS,
            Language.JAVASCRIPT: [
                "DOMPurify.sanitize(",
                "encodeURIComponent(",
                "encodeURI(",
                "escape(",
                "parseInt(",
                "parseFloat(",
                "Number(",
                "String(",
                "Boolean(",
                "JSON.stringify(",
            ],
            Language.TYPESCRIPT: [
                "DOMPurify.sanitize(",
                "encodeURIComponent(",
                "encodeURI(",
                "parseInt(",
                "parseFloat(",
                "Number(",
                "String(",
                "Boolean(",
                "JSON.stringify(",
            ],
        }

    def is_sanitizer(self, token: str, language: Language) -> bool:
        return any(p in token for p in self._patterns.get(language, []))


# Module-level singletons
source_registry = SourceRegistry()
sink_registry = SinkRegistry()
sanitizer_registry = SanitizerRegistry()
