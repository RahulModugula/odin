"""Intra-procedural taint tracker.

Architecture: LLift (OOPSLA 2024) — cheap static analysis narrows the search
space; the LLM then reasons about exploitability of the resulting candidates.

Scope (v1):
  - Intra-procedural only (one function body at a time)
  - Assignment-chain propagation: var = source → var is tainted
  - f-string propagation: f"...{tainted}..." → result is tainted
  - Call-arg propagation: if tainted reaches a sink argument → candidate
  - Sanitizer removal: passing through a sanitizer removes taint

Explicitly skipped (let the LLM stage handle these):
  - Cross-function taint (return-value tracking)
  - Container writes (dict[key] = tainted)
  - Global-state taint
  - Path sensitivity / branch joins
  - Implicit flows (control-flow-dependent taint)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.dataflow.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from app.dataflow.schemas import (
    SinkSpec,
    SourceSpec,
    TaintCandidate,
    TaintHop,
)
from app.models.enums import Language

# Max candidates per file — prevents LLM cost explosion
MAX_CANDIDATES = 20


@dataclass
class _TaintedVar:
    """A variable name and its provenance chain."""
    name: str
    source: SourceSpec
    hops: list[TaintHop] = field(default_factory=list)


class IntraProceduralTaintTracker:
    """Walk function bodies line-by-line and emit TaintCandidate objects.

    This is intentionally simple — precision comes from the LLM triage stage.
    """

    def __init__(
        self,
        sources: SourceRegistry,
        sinks: SinkRegistry,
        sanitizers: SanitizerRegistry,
        language: Language,
    ) -> None:
        self._src = sources
        self._snk = sinks
        self._san = sanitizers
        self._lang = language

        # Patterns for parsing (language-agnostic for the parts we care about)
        # Python: var = expr  /  JS: const/let/var/  var = expr
        self._assign_py = re.compile(r"^(\w+)\s*=\s*(.+)$")
        self._assign_js = re.compile(r"(?:const|let|var)?\s*(\w+)\s*=\s*(.+)$")
        self._fstring_py = re.compile(r'f["\'].*\{(\w+)\}')
        self._template_js = re.compile(r"`[^`]*\$\{(\w+)\}[^`]*`")

    def analyze(self, code: str, function_context: str | None = None) -> list[TaintCandidate]:
        """Analyze code and return taint candidates.

        Args:
            code: Full source text (whole file or single function body).
            function_context: Optional function name for candidate metadata.
        """
        lines = code.splitlines()
        tainted: dict[str, _TaintedVar] = {}   # var_name → TaintedVar
        candidates: list[TaintCandidate] = []

        assign_pattern = (
            self._assign_py
            if self._lang == Language.PYTHON
            else self._assign_js
        )

        for lineno, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # ── 1. Check if line seeds a new taint source ─────────────────
            source_matches = self._src.matches(raw_line, self._lang)
            for spec in source_matches:
                # Try to extract the LHS variable name
                var = self._extract_lhs(raw_line, assign_pattern)
                if var:
                    hop = TaintHop(
                        line=lineno,
                        col=raw_line.find(var),
                        variable=var,
                        operation="assign",
                        snippet=raw_line.rstrip(),
                    )
                    tainted[var] = _TaintedVar(name=var, source=spec, hops=[hop])

            # ── 2. Propagate taint through assignments ─────────────────────
            lhs = self._extract_lhs(raw_line, assign_pattern)
            if lhs and lhs not in {tv.name for tv in tainted.values()}:
                rhs = raw_line.split("=", 1)[-1] if "=" in raw_line else ""
                for tvar in list(tainted.values()):
                    if self._rhs_uses_tainted(rhs, tvar.name, raw_line):
                        # Check if there's a sanitizer on the RHS
                        if self._san.is_sanitizer(rhs, self._lang):
                            continue
                        new_hops = list(tvar.hops) + [
                            TaintHop(
                                line=lineno,
                                col=raw_line.find(lhs),
                                variable=lhs,
                                operation="assign",
                                snippet=raw_line.rstrip(),
                            )
                        ]
                        tainted[lhs] = _TaintedVar(
                            name=lhs,
                            source=tvar.source,
                            hops=new_hops,
                        )
                        break

            # ── 3. Check for sink matches ──────────────────────────────────
            sink_matches = self._snk.matches(raw_line, self._lang)
            for sink_spec in sink_matches:
                # Check if any tainted variable is used in this sink call
                for tvar in tainted.values():
                    if not self._var_used_in_sink(raw_line, tvar.name, sink_spec):
                        continue
                    # Skip if there's a sanitizer wrapping the tainted variable
                    if self._is_sanitized_at_sink(raw_line, tvar.name):
                        continue

                    candidate_id = TaintCandidate.make_id(
                        tvar.source.signature,
                        sink_spec.signature,
                        function_context,
                        lineno,
                    )

                    # Avoid duplicate candidates for same source→sink pair
                    already = any(c.candidate_id == candidate_id for c in candidates)
                    if already:
                        continue

                    snippet = self._build_snippet(lines, lineno, tvar.hops)

                    candidates.append(TaintCandidate(
                        candidate_id=candidate_id,
                        language=self._lang,
                        function_name=function_context,
                        source=tvar.source,
                        source_location=(tvar.hops[0].line if tvar.hops else lineno, 0),
                        sink=sink_spec,
                        sink_location=(lineno, raw_line.find(sink_spec.call_pattern)),
                        hops=list(tvar.hops),
                        snippet=snippet,
                    ))

                    if len(candidates) >= MAX_CANDIDATES:
                        return candidates

        return candidates

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_lhs(self, line: str, pattern: re.Pattern) -> str | None:
        """Extract the LHS variable name from an assignment line."""
        stripped = line.strip()
        m = pattern.match(stripped)
        if m:
            name = m.group(1).strip()
            # Skip Python decorators, class definitions, etc.
            if name in {"return", "if", "for", "while", "import", "from", "class", "def"}:
                return None
            return name
        return None

    def _rhs_uses_tainted(self, rhs: str, var_name: str, full_line: str) -> bool:
        """Return True if the RHS of an assignment uses the tainted variable."""
        if not var_name:
            return False
        # Whole-word match
        pattern = re.compile(rf"\b{re.escape(var_name)}\b")
        if pattern.search(rhs):
            return True
        # f-string or template literal
        if self._lang == Language.PYTHON and self._fstring_py.search(full_line):
            return var_name in full_line
        if self._lang in (Language.JAVASCRIPT, Language.TYPESCRIPT) and self._template_js.search(full_line):
            return var_name in full_line
        return False

    def _var_used_in_sink(self, line: str, var_name: str, sink: SinkSpec) -> bool:
        """Return True if the tainted variable appears in the sink call on this line."""
        if sink.call_pattern not in line:
            return False
        return bool(re.search(rf"\b{re.escape(var_name)}\b", line))

    def _is_sanitized_at_sink(self, line: str, var_name: str) -> bool:
        """Return True if the tainted variable is wrapped in a sanitizer on this line."""
        return self._san.is_sanitizer(line, self._lang) and var_name in line

    def _build_snippet(self, lines: list[str], sink_line: int, hops: list[TaintHop]) -> str:
        """Build a multi-line context snippet around the source and sink."""
        snippet_lines: list[str] = []
        relevant_linenos = {h.line for h in hops} | {sink_line}
        min_line = max(1, min(relevant_linenos) - 2)
        max_line = min(len(lines), max(relevant_linenos) + 2)
        for i, raw in enumerate(lines[min_line - 1 : max_line], min_line):
            marker = " >> " if i in relevant_linenos else "    "
            snippet_lines.append(f"{i:3d}{marker}{raw}")
        return "\n".join(snippet_lines)
