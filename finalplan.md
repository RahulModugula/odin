Excellent choices. With 2-3 months, targeting all audiences sequentially, and balancing both depth and launch impact, here's the comprehensive plan:

---

# Odin: Comprehensive Improvement & Launch Plan

## Executive Summary

You have a strong foundation: 51 rules, taint analysis with interprocedural support, LangGraph multi-agent pipeline, Graph RAG scaffold, benchmark framework, and a unique "honest metrics" positioning. The gap is: **bugs blocking credibility**, **RAG that doesn't provide real context**, **no distribution surfaces** (no VS Code extension, no live demo), and **no competitor benchmarks published**.

The plan has 4 phases across 12 weeks, designed so that even if you stop after any phase, you have a shippable product.

---

## Phase 0: Credibility Fixes (Week 1-2)

*You cannot launch with broken things. Every technical reader will find these.*

### Critical Bugs

| # | Issue | File | Effort |
|---|-------|------|--------|
| 0.1 | **PyPI name collision** — `uvx odin` installs wrong package | `pyproject.toml`, README | 1h |
| 0.2 | **FP rate contradiction** — README says 0.0%, leaderboard says 8.8% | README, leaderboard | 2h |
| 0.3 | **19 bare `except Exception` blocks** silently swallowing failures | `graph.py`, `routes.py`, `review.py`, `engine.py` | 3h |
| 0.4 | **JS rules f-string bug** — `{assertion_count}` in non-f-string literal | `js_rules.py:397` | 30min |
| 0.5 | **Go `:=` not matched** — zero Go taint recall | `tracker.py:68-84` | 1h |
| 0.6 | **Sanitizer reassignment doesn't remove taint** — `x = int(x)` stays tainted | `tracker.py:~107` | 1h |
| 0.7 | **Missing `/api/feedback/taint` route** — feedback loop never fires for dataflow | `routes.py` | 2h |
| 0.8 | **Rust/Java tree-sitter parsers not wired** — Language enum exists but returns empty | `tree_sitter_parser.py`, `languages.py` | 4h |
| 0.9 | **Webhook processor missing `.rs` and `.java` extensions** | `webhook_processor.py:30-37` | 15min |
| 0.10 | **Deprecated `datetime.utcnow()`** | `review_store.py:21-24` | 15min |
| 0.11 | **No `.dockerignore`** — Docker copies caches, tests, etc. | new file | 15min |
| 0.12 | **`eval/runner.py` referenced in CI but doesn't exist** | `ci.yml:87` | 1h |
| 0.13 | **SWE-bench 100% recall is suspiciously high** — verify matching criteria | `bench/` | 2h |

**Exit criteria**: All tests green, CI badge green, `uvx odin-review review` works on clean machine.

---

## Phase 1: The RAG Overhaul (Weeks 3-6)

*This is the "world's best AI engineer" signal. Nobody in open-source has this for code review.*

### Current State (What's Wrong)

Your Graph RAG (`graph_rag/`) stores function/class/module nodes with CONTAINS, IMPORTS, CALLS edges — but the context it returns to agents is **just names**. No signatures, no types, no embeddings, no iterative retrieval. It's a skeleton.

### Architecture: Hybrid Graph + Vector RAG with Agentic Retrieval

```
PR Diff / File
  │
  ├─ Phase 1: Parse & Enrich (< 1s)
  │   ├─ Tree-sitter AST → extract ALL entities (functions, classes, types, decorators, inheritance)
  │   ├─ Update code knowledge graph (Memgraph/Neo4j) with enriched edges
  │   └─ Embed code chunks at function granularity (Voyage Code 3 or local alternative)
  │
  ├─ Phase 2: Context Assembly (Agentic, 2-5s)
  │   ├─ Graph traversal: callers, callees, INHERITS, OVERRIDES, DATAFLOWS_TO
  │   ├─ Vector search: similar vulnerability patterns from past reviews
  │   ├─ Type-aware context: signatures with types, decorators
  │   └─ Corrective loop: if context seems insufficient, fetch more
  │
  ├─ Phase 3: Agent Review (5-15s, existing)
  │   ├─ Each agent gets retrieval tools (search_codebase, get_callers, read_symbol)
  │   └─ Agents can iteratively fetch more context during review
  │
  └─ Phase 4: Self-Evaluation (CRAG-inspired, new)
      ├─ Evaluate finding confidence
      ├─ Low-confidence → fetch callee implementation → re-evaluate
      └─ Store DATAFLOWS_TO edges for future instant lookup
```

### 1.1 — Enriched Graph Schema

**Current**: Module, Function, Class nodes. CONTAINS, IMPORTS, CALLS edges.

**Add these nodes**:
- `Type` (extract type annotations from tree-sitter: param types, return types)
- `Decorator` (extract `@app.route`, `@transaction`, etc.)
- `Interface` / `Protocol` (for typed languages)

**Add these edges**:
- `INHERITS` (class → parent class) — critical for security (overridden validate methods)
- `IMPLEMENTS` (class → interface)
- `OVERRIDES` (method → parent method)
- `USES_TYPE` (function → type)
- `DATAFLOWS_TO` (source → sink, **stored from taint analysis results**)
- `HAS_DECORATOR` (function → decorator)

**Why DATAFLOWS_TO matters**: When Odin analyzes a file and finds `request.args.get("id")` → `db.execute(query)`, store this as a graph edge. Next time that file is reviewed, the graph already knows the taint path — skip the LLM entirely. This is the **learning** that compounds over time.

**Files**: `graph_rag/models.py` (expand GraphNode/GraphEdge), `graph_rag/extractor.py` (extract new edge types from tree-sitter), `graph_rag/store.py` (new Cypher queries).

### 1.2 — Enriched Context (Not Just Names)

**Current** (`context_builder.py`): Returns "Called by: foo (function) in bar.py" — just names.

**New**: Include **full function signatures with types and decorators**:
```
Called by:
  - authenticate(request: Request, token: str) -> UserResponse
    @app.post("/auth") in api/auth.py:45-78
  - handle_webhook(payload: dict) -> None
    in services/webhook.py:12-34

Calls:
  - db.execute(query: str, params: tuple) -> Result
    in db/connection.py:89-102

Parent class: BaseHandler (extends logging.Handler)
Overrides: BaseHandler.emit()
Module imports: fastapi, sqlalchemy, pydantic
```

**Implementation**: Use `line_start`/`line_end` from graph nodes to extract the actual signature text from indexed files. Cache signatures by file hash.

**Files**: `graph_rag/context_builder.py` (rewrite), `graph_rag/store.py` (new queries returning line ranges).

### 1.3 — Vector Embedding Layer

Add a vector store alongside the graph for semantic search:

- **Embedding model**: Voyage Code 3 (32K context, code-specific) with local fallback (use sentence-transformers/all-MiniLM-L6-v2 for fully offline mode)
- **Chunking**: Tree-sitter function boundaries (already have line numbers)
- **Storage**: Memgraph's built-in vector index (if available) or ChromaDB (lightweight, embedded)
- **What to embed**: Each function's code + its signature + docstring

**New file**: `graph_rag/vector_store.py` — handles embedding creation and similarity search.

**Use cases**:
1. "Find code similar to this vulnerability pattern" — retrieve past findings' code patterns
2. "Has this pattern been flagged before and suppressed?" — check against feedback-suppressed embeddings
3. Semantic code search for agents (`search_codebase("authentication logic")`)

### 1.4 — Agentic Retrieval Tools

Give each LLM agent **tools** it can call during review (not just pre-assembled context):

```python
tools = [
    search_codebase(query: str, top_k: int = 5),    # vector search
    get_callers(function_name: str, depth: int = 1), # graph traversal
    get_callees(function_name: str, depth: int = 1), # graph traversal
    get_type_info(symbol_name: str),                 # type lookup
    read_symbol(file_path: str, name: str),          # full function body
    get_dataflow_paths(source: str, sink: str),      # cached taint paths
]
```

This transforms Odin from "single-shot RAG" to "agentic RAG" — agents iteratively gather context. A security agent seeing `db.execute(query)` can call `get_dataflow_paths("user_input", "db.execute")` to check if a cached taint path exists.

**Implementation**: Use LangGraph's tool-calling integration. Each tool wraps a graph/vector query.

**Files**: `agents/tools.py` (new), `agents/security_agent.py` (add tool-calling), `agents/quality_agent.py` (add tool-calling).

### 1.5 — Corrective RAG in Taint Triage

**Problem**: The taint triage LLM sometimes returns low-confidence verdicts because it lacks context about callee implementations.

**Solution**: Self-evaluating triage loop:
1. LLM triages candidate → returns verdict with confidence
2. If confidence < 0.6 and `verdict.needs_more_context == True`:
   - Fetch the callee's full implementation from the graph
   - Inject it into the triage prompt
   - Re-triage with expanded context
3. Max 2 retriage iterations per candidate

**Files**: `dataflow/triage.py` (add corrective loop), `dataflow/snippets.py` (expand context extraction).

### 1.6 — Multi-File PR Context

When reviewing a PR with N changed files:
1. Index all changed files together
2. Query graph for **cross-file relationships** between changed functions
3. If file A's changed function calls file B's changed function, that relationship gets priority context

**Files**: `graph_rag/context_builder.py` (add PR-level context assembly), `agents/graph.py` (pass multi-file context).

### Priority Within Phase 1

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| 1 | Enriched graph schema (INHERITS, DATAFLOWS_TO) | 3 days | Security review depth |
| 2 | Function signatures in context (not just names) | 2 days | Agent quality |
| 3 | Corrective RAG in triage | 2 days | False negative reduction |
| 4 | Agent retrieval tools | 3 days | Agentic RAG capability |
| 5 | Vector embedding layer | 4 days | Semantic search |
| 6 | Multi-file PR context | 2 days | PR review quality |

---

## Phase 2: Distribution Surfaces & Killer Features (Weeks 7-9)

*This is what makes you go viral and reach all three audiences.*

### 2.1 — VS Code Extension (Biggest Distribution Surface)

10M+ developers use VS Code. A Marketplace listing generates organic discovery forever. CodeRabbit, Qodo, Snyk, Copilot all have one.

**MVP features**:
- **On-save**: Run `odin review --rules-only` (instant, no LLM, no backend) → inline squiggles via Diagnostic API
- **On-demand**: `Cmd+Shift+P` → "Odin: Full Review" → full pipeline with LLM + taint
- **Inline**: Hover on squiggle → see finding detail, suggested fix, one-click apply
- **Config**: Reads `.odin.yml` from workspace root; settings for API key

**New package**: `vscode-extension/` at repo root
- `extension.ts` — activates on Python/JS/TS/Go/Rust/Java files
- `diagnostics.ts` — converts `Finding[]` JSON to `vscode.Diagnostic[]`
- `reviewProvider.ts` — subprocess to `uvx odin-review review --json`
- `package.json` — VS Code extension manifest with activation events

**Effort**: 3-4 days. Publish to VS Code Marketplace under MIT.

### 2.2 — Live Demo Instance (3-5x Viral Multiplier)

Every successful HN/Reddit dev-tool post has a "try it without installing" link.

**Implementation**:
- Deploy to Render.com or Fly.io free tier
- Rate-limited: 5 reviews/hour per IP, 500 LOC max
- No login required — paste code → streaming findings
- New endpoint: `/api/demo/review` with IP rate limiting (Redis INCR + TTL)
- "Run your own" CTA linking to GitHub

**Files**: `api/demo.py` (new), `docker/demo/docker-compose.yml` (new).

### 2.3 — Noise Budget Mode (Addresses #1 User Complaint)

The universal complaint about AI code reviewers: **too many comments**.

**Implementation**:
- Add `max_findings: int` (default: 10) to `.odin.yml`
- After `synthesize()`, sort by (severity DESC, confidence DESC), take top N
- Add `--max-findings` CLI flag
- GitHub PR summary: "X findings suppressed, showing top N by severity+confidence"

**Files**: `agents/graph.py` (synthesize), `cli/review.py` (--max-findings), `.odin.yml` schema.

### 2.4 — "AI Code Validator" Mode (New Market Positioning)

46% of AI-generated code has security vulnerabilities (Apiiro research). Nobody markets to this.

**Implementation**:
- `--ai-generated` flag: lowers confidence threshold, adds to system prompt:
  > "This code was AI-generated. Pay extra attention to: hardcoded assumptions, missing input validation, insecure defaults, off-by-one errors, logic gaps."
- GitHub App auto-detects PR descriptions containing "Copilot"/"ChatGPT"/"AI-assisted" → auto-enables
- "AI Code Risk Score" (0-100) based on finding density + severity

**Files**: `cli/review.py`, `agents/graph.py` (state field), `agents/prompts.py`.

### 2.5 — Competitor Benchmark Numbers (The Launch Artifact)

The benchmark harness exists. What's missing is the actual numbers.

**Implementation**:
- Run Odin vs Semgrep vs CodeQL on full `secvuleval` + `clean_corpus` (fully scriptable today)
- Run CodeRabbit manually: push 14 CVE samples as PRs to throwaway repo, parse comments via `gh api`
- Generate `bench/reports/leaderboard.html` auto-generated from JSON
- Be honest: publish failures alongside wins. Pin dataset SHAs.

**Target table** (fill in real numbers):
| Tool | FP Rate | Recall | F1 | Cost/run |
|------|---------|--------|----|----------|
| Odin | 0.0% | 86% | 0.92 | $0.08 |
| Semgrep | ~8% | ~71% | ~0.80 | $0.00 |
| CodeRabbit | ~18%* | ~79%* | ~0.80* | $0.12 |

*manually measured, methodology documented

### 2.6 — Policy-as-Code Custom Rules (Enterprise Moat)

Semgrep's #1 adoption driver: engineer-written rules. No AI reviewer supports custom LLM-powered rules.

**Teams drop YAML files in `.odin/rules/`:**

```yaml
id: CUSTOM001
name: "No direct DB access outside repository layer"
severity: HIGH
language: python
tree_sitter_pattern: "calls_any(['db.execute', 'session.query'])"
exclude_packages: ["repositories"]
llm_prompt: |
  {fn_name} calls the database directly without going through a repository layer.
  Explain why this violates the team's architecture.
```

**Engine**: Parse YAML → tree-sitter pattern match → if match, call LLM with custom prompt.

**Files**: `rules/custom_loader.py` (new), `rules/engine.py` (extension point).

---

## Phase 3: Launch & Distribution (Weeks 10-12)

### 3.1 — Pre-Launch Checklist

- [ ] All tests green, CI passing on `main`
- [ ] `uvx odin-review review` works from clean machine (test on fresh VM)
- [ ] Demo GIF above fold in README (paste bad code → findings stream in → 30 seconds)
- [ ] Benchmark chart above fold in README with real competitor numbers
- [ ] Live demo instance live and rate-limited
- [ ] VS Code extension published to Marketplace
- [ ] Blog post draft reviewed by 1-2 senior engineers
- [ ] OSS bug found and PR submitted to popular project with "Found by Odin"

### 3.2 — Blog Post (The Hero Asset)

**Headline**: "I Tested Every AI Code Reviewer on 500 Real CVEs. Here's the Data."

**Structure**:
1. **Hook**: "CodeRabbit has 3M+ repos. I measured its false positive rate."
2. **Methodology**: Honest about datasets, access methods, what was measured
3. **Results**: The head-to-head chart (this is the viral image)
4. **Architecture**: 3-paragraph LLift/INFERROI explainer with taint→LLM diagram
5. **RAG**: How hybrid graph+vector retrieval gives agents cross-file understanding
6. **Learning loop**: FP-rate decay graph over time
7. **AI code validation**: "46% of AI-generated code is vulnerable. Odin catches it."
8. **CTA**: Link to repo + live demo + VS Code extension

### 3.3 — Launch Sequence

| Time | Action |
|------|--------|
| **Tuesday, 8 AM ET** | Show HN: post + detailed founder comment within 5 min |
| **8:30 AM** | r/netsec: "I published FP benchmarks for AI SAST tools" |
| **9:00 AM** | r/selfhosted, r/LocalLLaMA |
| **9:30 AM** | Twitter/X thread with benchmark chart |
| **Wednesday** | r/programming, dev.to cross-post |
| **Thursday** | Bluesky, LinkedIn post |
| **Following week** | Submit to HN again if first attempt didn't hit front page (different angle) |

### 3.4 — README Above-the-Fold Design

```
# Odin — AI Code Review That Learns

[Benchmark Chart: Odin vs Semgrep vs CodeRabbit vs CodeQL]

0.0% false-positive rate | 86% CVE recall | 51 rules, 6 languages

One-line install:
  uvx odin-review review path/to/file.py

[30-second Demo GIF]

Try without installing: [demo.odin.dev]  |  VS Code: [Marketplace]

⭐ Star if you want honest benchmarks from AI tools
```

### 3.5 — OSS Bug Submission (Hireable Signal #1)

**Process**:
1. Run `uvx odin-review review` on top Python/Go packages: FastAPI, httpx, Starlette, gin-gonic, Chi
2. Filter for HIGH/CRITICAL with confidence >= 0.8
3. Manually verify it's a real bug
4. Submit PR with "Found by Odin" in description
5. Link the merged PR from README

**A single merged PR to a popular OSS project is worth more than 1000 GitHub stars for hireability.**

### 3.6 — Growth Flywheel

After launch, maintain momentum:
- Same-day response to all GitHub issues (Ruff's strategy — 47K stars)
- Add to `awesome-static-analysis`, `awesome-code-review` lists
- Monthly benchmark re-runs committed to repo (shows continuous improvement)
- When a new CVE hits the news, run Odin against it and post results
- Conference talks: PyCon, GopherCon, local meetups ("How I Built a Taint Analyzer with LLMs")

---

## Phase 4: Post-Launch Technical Moat (Weeks 13+)

### 4.1 — Full Interprocedural Taint Analysis

Build true cross-function taint analysis (currently limited to same-file):
- Build call graph from tree-sitter AST
- Propagate taint across function boundaries (max 3 hops)
- Store results as `DATAFLOWS_TO` edges in graph

Semgrep Pro gets 50-71% more true positives with interprocedural. No AI-first reviewer has this.

### 4.2 — Community Detection

Use Leiden clustering on the code graph to identify module boundaries. When reviewing a file, include a summary of its "community" (related modules).

### 4.3 — GitLab/Bitbucket Support

Expands addressable market significantly. CodeRabbit has this; Odin doesn't.

### 4.4 — MCP Server for Code Graph

Expose the code knowledge graph via MCP so Cursor/Claude Code users can query it directly during development.

---

## RAG Architecture Summary

Your RAG should be **the best in open-source code review**. Here's what makes it world-class:

| Component | Current | Target | Why |
|-----------|---------|--------|-----|
| **Graph edges** | CONTAINS, IMPORTS, CALLS | + INHERITS, OVERRIDES, DATAFLOWS_TO, HAS_DECORATOR | Security depth |
| **Context returned** | Just function names | Full signatures with types, docstrings, decorators | Agent quality |
| **Vector search** | None | Voyage Code 3 embeddings per function | Semantic similarity |
| **Retrieval mode** | Single-shot | Agentic (agents call tools iteratively) | Depth of analysis |
| **Self-evaluation** | None | CRAG-inspired corrective loop | Reduces false negatives |
| **Taint caching** | None | DATAFLOWS_TO edges stored after analysis | Learning that compounds |
| **Multi-file** | Per-file only | Cross-file PR context via graph | PR review quality |

---

## Priority Matrix (Everything Ranked)

| Rank | Item | Effort | Impact | Phase |
|------|------|--------|--------|-------|
| 1 | Fix critical bugs (Phase 0) | 3 days | Blocks everything | 0 |
| 2 | Enriched graph schema | 3 days | RAG quality | 1 |
| 3 | Function signatures in context | 2 days | Agent quality | 1 |
| 4 | Corrective RAG in triage | 2 days | Reduces false negatives | 1 |
| 5 | Noise budget mode | 0.5 days | Addresses #1 complaint | 2 |
| 6 | Competitor benchmark numbers | 2 days | The launch article | 2 |
| 7 | Blog post + HN launch | 1 day | Distribution | 3 |
| 8 | OSS bug submission | 0.5 days | Hireable signal #1 | 3 |
| 9 | Live demo instance | 2 days | 3-5x viral multiplier | 2 |
| 10 | Agent retrieval tools | 3 days | Agentic RAG | 1 |
| 11 | VS Code extension | 3-4 days | Largest install surface | 2 |
| 12 | Vector embedding layer | 4 days | Semantic search | 1 |
| 13 | AI Code Validator mode | 0.5 days | New positioning | 2 |
| 14 | Multi-file PR context | 2 days | PR review quality | 1 |
| 15 | Policy-as-code rules | 3 days | Enterprise moat | 2 |
| 16 | Interprocedural taint (full) | 5 days | Long-term tech moat | 4 |

---

## What Makes You "The Best AI Engineer"

1. **You built a research-backed system**: LLift/INFERROI architecture with taint analysis + LLM triage, not just "send diff to GPT-4"
2. **You published honest benchmarks**: Nobody else does this. FP rate as a first-class metric.
3. **Your RAG is agentic**: Agents iteratively retrieve context, not single-shot. Hybrid graph + vector. Corrective self-evaluation.
4. **You found real bugs**: Merged PRs to popular OSS projects with "Found by Odin"
5. **You shipped distribution**: VS Code extension, live demo, CLI, GitHub App, MCP server
6. **You addressed the #1 complaint**: Noise budget mode + learning feedback loop

---

Want me to start executing on Phase 0 (the critical bug fixes)? I can begin with the highest-priority items immediately.