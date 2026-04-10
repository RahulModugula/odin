from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from app.agents.docs_agent import run_docs_agent
from app.agents.quality_agent import run_quality_agent
from app.agents.security_agent import run_security_agent
from app.config import settings
from app.models.enums import Category, Language, Severity
from app.models.schemas import AgentOutput, CodeMetrics, Finding
from app.models.state import ReviewState
from app.parsers.tree_sitter_parser import parse_code

SEVERITY_PENALTY = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def parse_code_node(state: ReviewState) -> dict:  # type: ignore[type-arg]
    """Parse source code into AST and extract structural metrics."""
    structure = parse_code(state["code"], Language(state["language"]))

    ast_summary = _build_ast_summary(structure)

    return {
        "metrics": structure.metrics,
        "ast_summary": ast_summary,
    }


async def enrich_context_node(state: ReviewState) -> dict:  # type: ignore[type-arg]
    """Query the Graph RAG knowledge graph to build codebase context for agents."""
    if not settings.graph_rag_enabled:
        return {"codebase_context": ""}

    try:
        # graph_store is expected to be set on app state and passed via context
        # when not available (e.g. tests), fall through gracefully
        import app.graph_rag._store_ref as _ref
        from app.graph_rag.context_builder import build_context
        from app.graph_rag.store import GraphStore

        store: GraphStore | None = getattr(_ref, "store", None)

        context = await build_context(
            state["code"],
            Language(state["language"]),
            state.get("file_path"),
            store,
        )
    except Exception:
        context = ""

    return {"codebase_context": context}


def run_rules_node(state: ReviewState) -> dict:  # type: ignore[type-arg]
    """Run deterministic rule-based checks in parallel with the AI agents."""
    from app.rules.engine import rule_engine
    from app.rules.registry import register_all

    if not settings.rules_enabled:
        return {"findings": []}

    if not rule_engine.is_initialized():
        register_all()

    try:
        lang = Language(state["language"])
        findings = rule_engine.check_all(state["code"], lang)
        return {"findings": findings}
    except Exception:
        return {"findings": []}


def fan_out_to_agents(state: ReviewState) -> list[Send]:
    """Fan out to all four branches in parallel:
      security/quality/docs agents + deterministic rules + dataflow triage.
    """
    agent_input: dict = {
        "code": state["code"],
        "language": state["language"],
        "ast_summary": state["ast_summary"],
        "metrics": state["metrics"],
        "codebase_context": state.get("codebase_context", ""),
    }
    # Pass PR context so agents focus analysis on changed lines only
    if "diff" in state and state["diff"]:
        agent_input["diff"] = state["diff"]
    if "changed_lines" in state and state["changed_lines"]:
        agent_input["changed_lines"] = state["changed_lines"]
    if "pr_context" in state and state["pr_context"]:
        agent_input["pr_context"] = state["pr_context"]
    return [
        Send("quality_agent", agent_input),
        Send("security_agent", agent_input),
        Send("docs_agent", agent_input),
        Send("run_rules", state),
        Send("dataflow_triage", state),  # LLift/INFERROI-style taint analysis
    ]


def synthesize(state: ReviewState) -> dict:  # type: ignore[type-arg]
    """Merge agent outputs, deduplicate findings, and calculate score."""
    findings = state.get("findings", [])

    # Deduplicate: same line range + same category = keep higher confidence
    deduped = _deduplicate_findings(findings)

    # Sort by severity (critical first), then by line number
    severity_order = list(Severity)
    deduped.sort(
        key=lambda f: (
            severity_order.index(f.severity),
            f.line_start or 999999,
        )
    )

    # Calculate score
    score = _calculate_score(deduped, state.get("metrics"))

    # Generate summary
    summary = _generate_summary(deduped, score)

    return {
        "findings": deduped,
        "overall_score": score,
        "summary": summary,
    }


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings based on line range and category."""
    seen: dict[tuple[int | None, int | None, str], Finding] = {}

    for finding in findings:
        key = (finding.line_start, finding.line_end, finding.category)
        if key in seen:
            if finding.confidence > seen[key].confidence:
                seen[key] = finding
        else:
            seen[key] = finding

    return list(seen.values())


def _calculate_score(findings: list[Finding], metrics: CodeMetrics | None) -> int:
    """Calculate an overall review score from 0-100."""
    score = 100

    for finding in findings:
        score -= SEVERITY_PENALTY.get(finding.severity, 0)

    # Bonus points for good code structure
    if metrics:
        if metrics.comment_ratio > 0.15:
            score += 5
        if metrics.max_nesting_depth <= 3:
            score += 5
        if metrics.avg_function_length < 30:
            score += 5

    return max(0, min(100, score))


def _generate_summary(findings: list[Finding], score: int) -> str:
    """Generate a human-readable review summary."""
    if not findings:
        return "No issues found. Code looks clean and well-structured."

    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    parts = []
    total = len(findings)
    parts.append(f"Found {total} issue{'s' if total != 1 else ''}.")

    if Severity.CRITICAL in severity_counts:
        parts.append(f"{severity_counts[Severity.CRITICAL]} critical.")

    if score >= 80:
        parts.append("Overall the code is in good shape with minor improvements needed.")
    elif score >= 50:
        parts.append("Several issues should be addressed before production use.")
    else:
        parts.append("Significant issues found that require immediate attention.")

    return " ".join(parts)


def _build_ast_summary(structure) -> str:  # type: ignore[no-untyped-def]
    """Build a human-readable summary of the AST analysis."""
    m = structure.metrics
    lines = [
        f"Lines of code: {m.lines_of_code}",
        f"Functions: {m.num_functions}",
        f"Classes: {m.num_classes}",
        f"Cyclomatic complexity: {m.cyclomatic_complexity}",
        f"Max nesting depth: {m.max_nesting_depth}",
        f"Average function length: {m.avg_function_length} lines",
        f"Max function length: {m.max_function_length} lines",
        f"Comment ratio: {m.comment_ratio:.1%}",
        f"Imports: {m.import_count}",
    ]

    if structure.functions:
        lines.append("\nFunctions:")
        for f in structure.functions:
            doc_status = "has docstring" if f.has_docstring else "NO docstring"
            lines.append(
                f"  - {f.name}(params={f.param_count}) "
                f"lines {f.line_start}-{f.line_end} ({f.body_length} lines, {doc_status})"
            )

    if structure.classes:
        lines.append("\nClasses:")
        for c in structure.classes:
            doc_status = "has docstring" if c.has_docstring else "NO docstring"
            lines.append(
                f"  - {c.name} lines {c.line_start}-{c.line_end} "
                f"({c.method_count} methods, {doc_status})"
            )

    if structure.imports:
        lines.append(f"\nImports: {', '.join(structure.imports[:10])}")

    return "\n".join(lines)


async def dataflow_triage_node(state: ReviewState) -> dict:  # type: ignore[type-arg]
    """Dataflow-guided LLM triage — open-source reference impl of LLift/INFERROI.

    Phase A: intra-procedural taint analysis to generate candidates
    Phase B: feedback suppression (skip known-FP pairs)
    Phase C: LLM triage — exploitability judgment per candidate
    Phase D: convert confirmed exploitable paths to Findings
    """
    if not settings.dataflow_enabled:
        return {"findings": [], "agent_outputs": []}

    try:
        from app.agents.llm import get_llm
        from app.dataflow.registry import sanitizer_registry, sink_registry, source_registry
        from app.dataflow.tracker import IntraProceduralTaintTracker
        from app.dataflow.triage import TRIAGE_CONFIDENCE_FLOOR, triage_all

        lang = Language(state["language"])
        tracker = IntraProceduralTaintTracker(source_registry, sink_registry, sanitizer_registry, lang)
        candidates = tracker.analyze(state["code"])

        if not candidates:
            return {"findings": [], "agent_outputs": []}

        # Phase B: suppress known-FP source→sink pairs before spending LLM tokens
        try:
            import app.services._feedback_ref as _fb_ref
            feedback_svc = getattr(_fb_ref, "service", None)
            if feedback_svc is not None:
                candidates = await feedback_svc.filter_taint_candidates(candidates)
        except Exception:
            pass

        if not candidates:
            return {"findings": [], "agent_outputs": []}

        llm = get_llm()
        verdicts = await triage_all(candidates, llm)

        findings: list[Finding] = []
        for candidate, verdict in zip(candidates, verdicts, strict=False):
            if not verdict.exploitable or verdict.confidence < TRIAGE_CONFIDENCE_FLOOR:
                continue
            findings.append(Finding(
                severity=Severity.CRITICAL if verdict.confidence >= 0.85 else Severity.HIGH,
                category=Category.SECURITY,
                title=f"Taint flow: {candidate.source.kind.value} → {candidate.sink.kind.value}",
                description=(
                    f"Dataflow analysis detected a tainted path from "
                    f"`{candidate.source.call_pattern or candidate.source.attr_pattern}` "
                    f"to `{candidate.sink.call_pattern}` (lines "
                    f"{candidate.source_location[0]}→{candidate.sink_location[0]}). "
                    f"{verdict.exploit_scenario}"
                ),
                line_start=candidate.sink_location[0],
                line_end=candidate.sink_location[0],
                suggestion=verdict.suggested_sanitizer,
                attack_scenario=verdict.exploit_scenario,
                confidence=verdict.confidence,
                source="dataflow",
            ))

        output = AgentOutput(agent_name="dataflow_triage", findings=findings)
        return {"findings": findings, "agent_outputs": [output]}

    except Exception:
        return {"findings": [], "agent_outputs": []}


# Build the graph
builder = StateGraph(ReviewState)

builder.add_node("parse_code", parse_code_node)
builder.add_node("enrich_context", enrich_context_node)
builder.add_node("quality_agent", run_quality_agent)
builder.add_node("security_agent", run_security_agent)
builder.add_node("docs_agent", run_docs_agent)
builder.add_node("run_rules", run_rules_node)
builder.add_node("dataflow_triage", dataflow_triage_node)
builder.add_node("synthesize", synthesize)

builder.add_edge(START, "parse_code")
builder.add_edge("parse_code", "enrich_context")
builder.add_conditional_edges(
    "enrich_context",
    fan_out_to_agents,
    ["quality_agent", "security_agent", "docs_agent", "run_rules", "dataflow_triage"],
)
builder.add_edge("quality_agent", "synthesize")
builder.add_edge("security_agent", "synthesize")
builder.add_edge("docs_agent", "synthesize")
builder.add_edge("run_rules", "synthesize")
builder.add_edge("dataflow_triage", "synthesize")
builder.add_edge("synthesize", END)

review_graph = builder.compile()
