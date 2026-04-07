"""Cross-function taint tracking within PR scope.

Extends IntraProceduralTaintTracker with interprocedural propagation:
  1. Build a mini call-graph of PR-changed files
  2. Run intra-procedural analysis per function
  3. Propagate taint through return values and call arguments across boundaries
  4. Feed combined candidates into the existing LLM triage pipeline

Bounded: max 5 files, MAX_CANDIDATES=20 total, depth-limited to avoid explosion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.dataflow.call_graph import CallGraph, CallSite, FunctionDef, build_call_graph
from app.dataflow.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from app.dataflow.schemas import (
    SourceSpec,
    TaintCandidate,
    TaintHop,
)
from app.dataflow.tracker import IntraProceduralTaintTracker, MAX_CANDIDATES
from app.models.enums import Language


@dataclass
class _ReturnTaint:
    """Tracks taint that flows through a function's return value."""

    function_name: str
    source: SourceSpec
    hops: list[TaintHop]
    return_expression: str


class InterProceduralTaintTracker:
    """Track taint across function call boundaries within PR scope.

    Strategy:
      1. Run intra-procedural analysis on each function body
      2. Record which functions return tainted values (_ReturnTaint)
      3. At call sites, if callee returns tainted data, propagate taint to caller
      4. Re-run intra analysis on caller with injected taint seeds
      5. Collect all candidates across all functions
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
        self._intra = IntraProceduralTaintTracker(sources, sinks, sanitizers, language)

    def analyze(
        self,
        file_contents: dict[str, str],
    ) -> list[TaintCandidate]:
        """Analyze multiple files for cross-function taint flows.

        Args:
            file_contents: mapping of file_path → source code for PR-changed files

        Returns:
            Combined taint candidates from all functions, capped at MAX_CANDIDATES.
        """
        if not file_contents:
            return []

        # Phase 1: build the call graph
        call_graph = build_call_graph(file_contents, self._lang)

        # Phase 2: intra-procedural analysis per function, collecting return taints
        all_candidates: list[TaintCandidate] = []
        return_taints: dict[str, _ReturnTaint] = {}

        for func_name, func_def in call_graph.functions.items():
            candidates = self._intra.analyze(func_def.body, function_context=func_name)
            all_candidates.extend(candidates)

            # Check if any tainted variable is returned
            rt = self._extract_return_taint(func_def, candidates)
            if rt is not None:
                return_taints[func_name] = rt

        # Phase 3: propagate taint across call boundaries
        cross_candidates = self._propagate_cross_function(
            call_graph, return_taints, file_contents,
        )
        all_candidates.extend(cross_candidates)

        # Deduplicate by candidate_id and cap
        seen: set[str] = set()
        deduped: list[TaintCandidate] = []
        for c in all_candidates:
            if c.candidate_id not in seen:
                seen.add(c.candidate_id)
                deduped.append(c)
            if len(deduped) >= MAX_CANDIDATES:
                break

        return deduped

    def _extract_return_taint(
        self,
        func_def: FunctionDef,
        candidates: list[TaintCandidate],
    ) -> _ReturnTaint | None:
        """Check if any tainted variable appears in the function's return statements."""
        if not func_def.return_lines or not candidates:
            return None

        # Collect tainted variable names from candidates' hop chains
        tainted_vars: dict[str, tuple[SourceSpec, list[TaintHop]]] = {}
        for c in candidates:
            for hop in c.hops:
                tainted_vars[hop.variable] = (c.source, c.hops)

        # Check each return line for tainted variables
        for ret_expr in func_def.return_lines:
            for var_name, (source, hops) in tainted_vars.items():
                if re.search(rf"\b{re.escape(var_name)}\b", ret_expr):
                    return _ReturnTaint(
                        function_name=func_def.name,
                        source=source,
                        hops=hops,
                        return_expression=ret_expr,
                    )

        return None

    def _propagate_cross_function(
        self,
        call_graph: CallGraph,
        return_taints: dict[str, _ReturnTaint],
        file_contents: dict[str, str],
    ) -> list[TaintCandidate]:
        """Propagate taint from callees to callers via return values."""
        cross_candidates: list[TaintCandidate] = []

        for func_name, ret_taint in return_taints.items():
            # Find all call sites where this function is called
            call_sites = call_graph.callers_of(func_name)

            for site in call_sites:
                caller_func = call_graph.functions.get(site.caller)
                if caller_func is None:
                    continue

                # Build cross-function hop
                cross_hop = TaintHop(
                    line=site.line,
                    col=0,
                    variable=f"{func_name}()",
                    operation="return",
                    snippet=f"  # taint flows through return value of {func_name}()",
                )

                # Inject taint at the call site and re-analyze the caller
                injected = self._analyze_with_injected_taint(
                    caller_func,
                    site,
                    ret_taint.source,
                    ret_taint.hops + [cross_hop],
                    file_contents.get(caller_func.file_path, ""),
                )
                cross_candidates.extend(injected)

        return cross_candidates

    def _analyze_with_injected_taint(
        self,
        caller: FunctionDef,
        call_site: CallSite,
        source: SourceSpec,
        prior_hops: list[TaintHop],
        full_file_code: str,
    ) -> list[TaintCandidate]:
        """Re-analyze a caller function with taint injected at a call site.

        We look for the LHS of the call assignment and track it as tainted,
        then check if it flows to any sink within the caller.
        """
        lines = caller.body.splitlines()
        candidates: list[TaintCandidate] = []

        # Find the line in the caller body that contains the call
        call_line_offset = call_site.line - caller.line_start
        if call_line_offset < 0 or call_line_offset >= len(lines):
            return []

        call_line = lines[call_line_offset]

        # Extract LHS variable name (e.g., "result = func_name(...)")
        assign_pattern = re.compile(
            rf"(?:(?:const|let|var)\s+)?(\w+)\s*(?::=|=)\s*.*\b{re.escape(call_site.callee)}\s*\("
        )
        m = assign_pattern.search(call_line)
        if m is None:
            return []

        tainted_var = m.group(1)

        # Now scan remaining lines in the caller for sinks using the tainted var
        for offset, line in enumerate(lines[call_line_offset + 1:], call_line_offset + 1):
            abs_line = caller.line_start + offset
            sink_matches = self._snk.matches(line, self._lang)
            for sink_spec in sink_matches:
                if sink_spec.call_pattern not in line:
                    continue
                if not re.search(rf"\b{re.escape(tainted_var)}\b", line):
                    continue
                if self._san.is_sanitizer(line, self._lang):
                    continue

                sink_hop = TaintHop(
                    line=abs_line,
                    col=line.find(sink_spec.call_pattern),
                    variable=tainted_var,
                    operation="call_arg",
                    snippet=line.rstrip(),
                )

                candidate_id = TaintCandidate.make_id(
                    source.signature,
                    sink_spec.signature,
                    caller.name,
                    abs_line,
                )

                # Build cross-file snippet
                snippet_lines = []
                for hop in prior_hops:
                    snippet_lines.append(f"  >> {hop.snippet}")
                snippet_lines.append(f"  >> {line.rstrip()}")

                candidates.append(TaintCandidate(
                    candidate_id=candidate_id,
                    language=self._lang,
                    function_name=caller.name,
                    source=source,
                    source_location=(prior_hops[0].line if prior_hops else abs_line, 0),
                    sink=sink_spec,
                    sink_location=(abs_line, line.find(sink_spec.call_pattern)),
                    hops=prior_hops + [sink_hop],
                    snippet="\n".join(snippet_lines),
                ))

                if len(candidates) >= MAX_CANDIDATES:
                    return candidates

        return candidates
