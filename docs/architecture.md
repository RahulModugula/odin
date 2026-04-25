# Odin Architecture

How Odin reviews code: **cheap static analysis narrows the search space, then an LLM
reasons about exploitability only on the candidates that survive.** This document is the
engineering deep-dive behind that one sentence — the pipeline, the research lineage, the
learning loop, and the parts that are deliberately narrow.

If you only read one thing: the expensive model never looks at a whole file hoping to
spot a bug. A taint tracker finds *suspects* — variables that flow from an attacker-
controllable source into a dangerous sink — and the LLM is asked a much smaller,
much more answerable question: *is this specific flow exploitable, and how?*

---

## 1. Why this shape

Single-shot "here is a diff, find the bugs" LLM review has two failure modes that show
up immediately in production:

1. **Noise.** The model flags style, naming, and speculative issues at the same volume
   as real vulnerabilities. Developers stop reading. Every commercial reviewer's #1
   complaint is false positives.
2. **Cost and non-determinism.** Every line pays for a large-model pass, and the same
   diff yields different findings run to run.

The research literature converged on a better shape. **[LLift (OOPSLA 2024)](https://www.cs.ucr.edu/~zhiyunq/pub/oopsla24_llift.pdf)**
and **[INFERROI (ICSE 2025)](https://conf.researchr.org/details/icse-2025)** both pair a
cheap static pre-pass with an LLM that only reasons about pre-screened candidates.
**QLCoder (ICSE 2025)** frames the LLM stage as structured verdict generation over those
candidates. Odin is an open-source implementation of that lineage, applied to code review
of AI-generated changes.

The payoff is measurable and it is the project's headline: on 193 clean-code samples the
dataflow tracker has a **0.0% false-positive rate**, because it refuses to fire without a
complete source→sink path. See [`bench/reports/leaderboard.md`](../backend/bench/reports/leaderboard.md).

---

## 2. The pipeline

Odin is a [LangGraph](https://langchain-ai.github.io/langgraph/) `StateGraph`
(`app/agents/graph.py`). A review flows through it as a single immutable state object:

```
        ┌── parse_code ──┐        tree-sitter AST for 6 languages
        │                │
        └── enrich_context┘       graph-RAG: pull callers/callees, cross-file signatures
                 │
     ┌───────────┴─────── fan-out (conditional, parallel) ───────────┐
     ▼           ▼            ▼             ▼                ▼
 security     quality       docs         run_rules     dataflow_triage
  agent        agent        agent      (51 rules,      taint tracker
 (LLM)        (LLM)        (LLM)        instant)       → LLM triage
     └───────────┴────────────┴─────────────┴────────────────┘
                             │
                        synthesize            dedup, score, severity-sort,
                             │                apply noise budget
                             ▼
              GitHub PR review / CLI / SSE stream / MCP
```

The fan-out is a real conditional edge (`add_conditional_edges`), so a `--rules-only`
run or a config that disables agents simply doesn't schedule those nodes — the same
graph serves the instant, no-LLM path and the full path.

The interesting node is `dataflow_triage`. The rest of this document is about it.

---

## 3. Stage 1 — the taint tracker (finding suspects, no LLM)

`app/dataflow/tracker.py` walks each function body with an **intra-procedural taint
tracker**, and `app/dataflow/interprocedural.py` extends flows across functions within a
file. The tracker models three things:

- **Sources** — where attacker-controllable data enters (request params, argv, env,
  deserialized input).
- **Propagation** — assignment chains (`x = source; y = x`), call-argument passing,
  f-string / template-literal interpolation, and Go's `:=`. Reassignment through a
  sanitizer (`x = int(x)`) *untaints*.
- **Sinks** — ~8 dangerous operations, each mapped to a CWE (`app/dataflow/triage.py`):

  | Sink kind | CWE |
  |---|---|
  | `code_exec` | CWE-94 Code Injection |
  | `shell_exec` | CWE-78 OS Command Injection |
  | `sql_query` | CWE-89 SQL Injection |
  | `dom_write` | CWE-79 XSS |
  | `path_traversal` | CWE-22 Path Traversal |
  | `ssrf_fetch` | CWE-918 SSRF |
  | `template_render` | CWE-94 SSTI |
  | `deserialized` | CWE-502 Unsafe Deserialization |

A **candidate** is emitted only when a source reaches a sink through a concrete chain of
hops. No path, no candidate — this is the whole reason the FP rate is 0.0%. The tracker
is intentionally high-precision and narrow-recall: it would rather stay silent than guess.

This stage is pure static analysis. It costs milliseconds and is fully deterministic.

---

## 4. Stage 2 — LLM triage (proving exploitability)

Candidates go to `triage_all()`. Before any model call, two cost controls run:

1. **Learning-loop suppression** (§5) removes source→sink pairs a human has marked
   false-positive.
2. **Candidate grouping.** `_group_by_pattern()` buckets candidates by
   `(source.signature, sink.signature)` and triages one representative per bucket — the
   one with the richest snippet — instead of paying for twenty near-identical flows.

The survivors are triaged concurrently under an `asyncio.Semaphore(4)`. Each gets a
structured prompt (`_build_prompt`) carrying the taint summary, the CWE, the annotated
snippet (`>>` marks source/sink/propagation lines), and the exact question the LLM is
good at answering:

> Can an attacker control the source? Does the tainted value reach the sink without
> meaningful sanitization? What is the concrete payload, and the exact fix?

The model returns JSON only — `exploitable`, `confidence`, `exploit_scenario`,
`fix_code`, `reasoning`, and a self-assessed `needs_more_context` flag. Structured output
is what makes the stage composable and testable rather than prose to regex over.

If the model call fails, the verdict falls back to a *conservative* "taint path detected,
manual review recommended" at low confidence — the system fails toward surfacing, not
hiding.

---

## 5. Corrective RAG — the retriage loop

A taint path often can't be judged from the function alone: exploitability depends on
what a *callee* does with the value. Odin implements a **Corrective-RAG-inspired
self-evaluation loop** (`_crag_retriage` in `app/dataflow/triage.py`):

```
verdict = triage(candidate)
while verdict.confidence < 0.6 or verdict.needs_more_context:   # ≤ 2 iterations
    context = fetch_callee_bodies(candidate)   # from the code graph
    if not context: break
    verdict = triage(candidate, extra_context=context)
```

When the first verdict is low-confidence or the model asks for more context, Odin pulls
the **implementations of the callees** (`get_callees` → `get_symbol_body`) out of the
graph store and re-triages with them inlined — up to `CRAG_MAX_RETRIAGE_ITERATIONS = 2`.
So a flow that looked ambiguous ("is `run_query` parameterized?") gets resolved by
actually reading `run_query`, not by guessing. High-confidence verdicts skip the loop
entirely and pay for exactly one call.

This is the mechanism that lets a cheap intra-procedural tracker reach interprocedural
conclusions on demand, only when it matters.

---

## 6. The learning loop (noise that drops over time)

Most reviewers "learn" by post-filtering their own output. Odin suppresses at the
*generator* level, which saves model spend, not just screen space
(`app/services/feedback.py`):

- When a developer marks a finding false-positive, Odin records the offending
  `(source_signature, sink_signature)` pair.
- After the pair crosses the report threshold, `is_taint_pair_suppressed()` returns true
  and `filter_taint_candidates()` drops it **before the LLM triage stage runs** — with a
  configurable TTL so suppression isn't permanent.

The distinction matters: a pair you've dismissed twice never costs another triage call.
Noise and cost fall together, which is the property single-shot reviewers can't offer.

Confirmed-exploitable verdicts also persist `DATAFLOWS_TO` edges into the graph
(`app/agents/graph.py`), so repeat reviews of the same code reuse known paths.

---

## 7. Graph-RAG context

`app/graph_rag/` maintains a code graph whose schema captures `INHERITS`, `OVERRIDES`,
`HAS_DECORATOR`, and `DATAFLOWS_TO` relationships. Two consumers:

- **`enrich_context`** pulls cross-file signatures and caller/callee context into the
  agent prompts, so a changed function that calls a changed function in another file is
  reviewed with that neighbor's signature in view.
- **CRAG retriage** (§5) queries it for callee bodies on demand.

When the graph isn't indexed, `query_codebase` falls back to direct AST lookups, so the
MCP tools degrade gracefully rather than erroring.

---

## 8. Surfaces

The same graph backs every entry point:

- **CLI** — `uvx odin-review review <path>` (rules-only is instant and needs no LLM).
- **MCP server** — `review_diff`, `review_code`, `analyze_file`, `get_findings`,
  `query_codebase`, for Claude Code / Cursor / any MCP client.
- **GitHub App + webhook** — inline PR comments with severity and fix suggestions.
- **SSE stream / web UI** — findings stream in as nodes complete.

---

## 9. Honest benchmarking as an architectural commitment

The benchmark harness (`backend/bench/`) is part of the architecture, not marketing.
Two properties are load-bearing:

- **Line-localized matching.** A finding counts as a true positive only if it lands on
  the vulnerable line — not merely somewhere in the sample. The scorer (`bench/scorer.py`)
  makes the criterion a single, swappable function so it can be tightened in the open.
- **Contamination control.** Ground-truth `# BUG:` markers are stripped from every sample
  before a tool runs, so a comment-linting rule can't score by matching an annotation the
  benchmark itself planted. (Removing this is exactly what once inflated a rule engine to
  a fake 100% recall — documented, and fixed, in the leaderboard.)

Every number regenerates with `python -m bench.harness --seed 42`. We publish the false-
positive rate and the datasets where Odin loses. For a tool whose value proposition is
*trust*, a reproducible benchmark that reports its own weaknesses is the product.

---

## 10. What's deliberately narrow (limitations)

- **Interprocedural taint is within a file.** Cross-file taint uses the graph for context
  on demand (§5) but full cross-file flow tracking is future work.
- **~8 sink categories.** The dataflow tracker's 0.0% FP rate is scoped to those sinks;
  the pattern-rule engine (8.8% FP) covers more ground at lower precision. The `odin-rules`
  number is the fair whole-ruleset comparison to Semgrep.
- **Deterministic rules don't catch logic bugs.** They encode security sink patterns;
  SWE-bench-style off-by-ones are out of scope by design, and the honest benchmark says so.
- **The review agents are single-pass.** They receive rich pre-assembled context but do
  not yet call tools mid-review; converting them to a tool-calling loop is planned.

---

## File map

| Concern | Path |
|---|---|
| Orchestration graph | `backend/app/agents/graph.py` |
| Taint tracker | `backend/app/dataflow/tracker.py`, `interprocedural.py` |
| LLM triage + CRAG loop | `backend/app/dataflow/triage.py` |
| Learning-loop suppression | `backend/app/services/feedback.py` |
| Code graph | `backend/app/graph_rag/` |
| Deterministic rules | `backend/app/rules/` |
| Benchmark harness + scorer | `backend/bench/` |
| MCP server | `backend/app/mcp/` |
