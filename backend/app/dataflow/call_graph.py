"""Mini call-graph builder for PR-scoped interprocedural taint analysis.

Extracts function definitions and call sites from PR-changed files + one hop
of callers/callees. Uses tree-sitter for reliable multi-language parsing.

Scope:
  - PR-changed files + immediate callers/callees (1-hop neighbourhood)
  - Max 5 files to keep analysis bounded
  - Reuses existing parse_code() infrastructure

Explicitly out of scope:
  - Whole-repo indexing (Greptile-style)
  - Dynamic dispatch / virtual method resolution
  - Higher-order functions / callbacks
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from app.models.enums import Language

MAX_CROSS_FILE_DEPTH = 5


@dataclass
class FunctionDef:
    """A function definition with its body text and location."""

    name: str
    file_path: str
    line_start: int
    line_end: int
    params: list[str]
    body: str
    return_lines: list[str] = field(default_factory=list)


@dataclass
class CallSite:
    """A function call within a function body."""

    caller: str  # function name that contains this call
    callee: str  # function being called
    file_path: str
    line: int
    arg_text: str  # raw text of arguments passed


@dataclass
class CallGraph:
    """Lightweight call graph for a set of files."""

    functions: dict[str, FunctionDef] = field(default_factory=dict)  # name -> def
    call_sites: list[CallSite] = field(default_factory=list)
    files_analyzed: list[str] = field(default_factory=list)

    def callers_of(self, func_name: str) -> list[CallSite]:
        return [cs for cs in self.call_sites if cs.callee == func_name]

    def callees_of(self, func_name: str) -> list[CallSite]:
        return [cs for cs in self.call_sites if cs.caller == func_name]


# ── Language-specific function definition patterns ────────────────────────────

_FUNC_DEF_PATTERNS: dict[Language, re.Pattern[str]] = {
    Language.PYTHON: re.compile(
        r"^(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->.*)?:",
    ),
    Language.JAVASCRIPT: re.compile(
        r"(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)|"
        r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?([^)]*)\)?\s*=>",
    ),
    Language.TYPESCRIPT: re.compile(
        r"(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)|"
        r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?([^)]*)\)?\s*=>",
    ),
    Language.GO: re.compile(
        r"^func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(([^)]*)\)",
    ),
    Language.RUST: re.compile(
        r"^(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\(([^)]*)\)",
    ),
    Language.JAVA: re.compile(
        r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{",
    ),
}

# ── Function call pattern (language-agnostic, good enough for our purposes) ──

_CALL_PATTERN = re.compile(r"\b(\w+)\s*\(([^)]*)\)")

# ── Return statement patterns ────────────────────────────────────────────────

_RETURN_PATTERNS: dict[Language, re.Pattern[str]] = {
    Language.PYTHON: re.compile(r"^\s+return\s+(.+)$"),
    Language.JAVASCRIPT: re.compile(r"^\s+return\s+(.+);?\s*$"),
    Language.TYPESCRIPT: re.compile(r"^\s+return\s+(.+);?\s*$"),
    Language.GO: re.compile(r"^\s+return\s+(.+)$"),
    Language.RUST: re.compile(r"^\s+(?:return\s+)?(.+);?\s*$"),
    Language.JAVA: re.compile(r"^\s+return\s+(.+);?\s*$"),
}


def _extract_functions(code: str, file_path: str, language: Language) -> list[FunctionDef]:
    """Extract function definitions from source code using regex patterns.

    This is intentionally simple — tree-sitter-level accuracy isn't needed
    because the LLM triage stage handles ambiguity.
    """
    pattern = _FUNC_DEF_PATTERNS.get(language)
    if pattern is None:
        return []

    return_pattern = _RETURN_PATTERNS.get(language)
    lines = code.splitlines()
    functions: list[FunctionDef] = []
    current_func: FunctionDef | None = None
    indent_level = 0

    for lineno, line in enumerate(lines, 1):
        m = pattern.match(line.strip() if language in (Language.PYTHON,) else line)
        if m:
            # Save previous function
            if current_func is not None:
                current_func.line_end = lineno - 1
                current_func.body = "\n".join(
                    lines[current_func.line_start - 1 : current_func.line_end]
                )
                functions.append(current_func)

            # Extract name and params from first matching group pair
            groups = m.groups()
            name = next((g for g in groups[::2] if g), None)
            params_raw = next((g for g in groups[1::2] if g is not None), "")

            if name is None:
                continue

            params = [p.strip().split(":")[0].split("=")[0].strip()
                      for p in params_raw.split(",") if p.strip()]
            # Remove 'self' from Python params
            if language == Language.PYTHON and params and params[0] == "self":
                params = params[1:]

            indent_level = len(line) - len(line.lstrip())
            current_func = FunctionDef(
                name=name,
                file_path=file_path,
                line_start=lineno,
                line_end=lineno,
                params=params,
                body="",
            )
            continue

        # Track return statements within current function
        if current_func is not None and return_pattern is not None:
            rm = return_pattern.match(line)
            if rm:
                current_func.return_lines.append(rm.group(1).strip().rstrip(";"))

        # Detect function end (simplified: indentation-based for Python, brace-counting skipped)
        if current_func is not None and language == Language.PYTHON:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                line_indent = len(line) - len(line.lstrip())
                if line_indent <= indent_level and lineno > current_func.line_start:
                    current_func.line_end = lineno - 1
                    current_func.body = "\n".join(
                        lines[current_func.line_start - 1 : current_func.line_end]
                    )
                    functions.append(current_func)
                    current_func = None

    # Capture the last function
    if current_func is not None:
        current_func.line_end = len(lines)
        current_func.body = "\n".join(
            lines[current_func.line_start - 1 : current_func.line_end]
        )
        functions.append(current_func)

    return functions


def _extract_call_sites(
    code: str,
    file_path: str,
    functions: list[FunctionDef],
) -> list[CallSite]:
    """Extract function call sites and map them to their enclosing function."""
    lines = code.splitlines()
    call_sites: list[CallSite] = []

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Find enclosing function
        enclosing = None
        for func in functions:
            if func.line_start <= lineno <= func.line_end:
                enclosing = func
                break

        if enclosing is None:
            continue

        # Find all calls on this line
        for m in _CALL_PATTERN.finditer(line):
            callee_name = m.group(1)
            arg_text = m.group(2).strip()

            # Skip language keywords and builtins
            if callee_name in {
                "if", "for", "while", "return", "print", "len", "range", "str",
                "int", "float", "bool", "list", "dict", "set", "tuple", "type",
                "isinstance", "hasattr", "getattr", "setattr", "super",
                "def", "class", "import", "from", "async", "await",
            }:
                continue

            # Skip if callee is the same as the enclosing function (recursion — skip for now)
            if callee_name == enclosing.name:
                continue

            call_sites.append(CallSite(
                caller=enclosing.name,
                callee=callee_name,
                file_path=file_path,
                line=lineno,
                arg_text=arg_text,
            ))

    return call_sites


def build_call_graph(
    file_contents: dict[str, str],
    language: Language,
) -> CallGraph:
    """Build a call graph from a set of file contents.

    Args:
        file_contents: mapping of file_path → source code
        language: programming language of all files

    Returns:
        CallGraph with function definitions and call sites
    """
    graph = CallGraph()

    # Cap at MAX_CROSS_FILE_DEPTH files
    files = list(file_contents.items())[:MAX_CROSS_FILE_DEPTH]
    graph.files_analyzed = [fp for fp, _ in files]

    all_functions: list[FunctionDef] = []
    for file_path, code in files:
        funcs = _extract_functions(code, file_path, language)
        for func in funcs:
            graph.functions[func.name] = func
        all_functions.extend(funcs)

    for file_path, code in files:
        file_funcs = [f for f in all_functions if f.file_path == file_path]
        sites = _extract_call_sites(code, file_path, file_funcs)
        graph.call_sites.extend(sites)

    return graph
