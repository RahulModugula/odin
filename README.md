# Odin — Dataflow-Guided AI Code Review

[![CI](https://github.com/RahulModugula/odin/actions/workflows/ci.yml/badge.svg)](https://github.com/RahulModugula/odin/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)

**Open-source AI code review with intra-procedural taint analysis, a public FP-rate leaderboard, and a learning feedback loop.**

Odin implements the [LLift (OOPSLA 2024)](https://www.cs.ucr.edu/~zhiyunq/pub/oopsla24_llift.pdf) / [INFERROI (ICSE 2025)](https://conf.researchr.org/details/icse-2025) architecture: cheap taint propagation narrows the search space, then an LLM reasons about exploitability only on real candidates. A feedback loop suppresses known false-positive (source, sink) pairs *before* the LLM runs — so cost and noise drop together over time.

**0.0% false-positive rate** on 60 clean-code samples. Every number is reproducible — run `python -m bench.harness` yourself.

---

## One-line install

```bash
# No Docker, no server, no checkout — just works (BYOK via env var)
uvx odin review path/to/file.py

# Rules only — instant, no LLM
uvx odin review path/to/file.py --rules-only
```

Set your provider once:

```bash
export ODIN_LLM_PROVIDER=openrouter
export ODIN_OPENROUTER_API_KEY=sk-or-v1-...
export ODIN_OPENROUTER_MODEL=anthropic/claude-sonnet-4-5
```

---

## GitHub App — one-click install

Install the GitHub App and Odin automatically reviews every PR in your repos — no webhook setup, no token management.

```
https://your-odin-instance/api/github/app/install
```

Or self-host and register your own App:

```bash
# .env
ODIN_GITHUB_APP_ID=123456
ODIN_GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/odin-app.pem
ODIN_GITHUB_APP_WEBHOOK_SECRET=your-secret
```

Odin posts structured reviews with inline comments, severity badges, and fix suggestions on every PR automatically.

---

## Features

| Feature | Details |
|---|---|
| **Dataflow triage** | Intra-procedural taint analysis → LLM reasons about exploitability on narrowed candidates only (LLift/INFERROI architecture) |
| **27 deterministic rules** | Python, JS, TS, Go, Rust, Java — zero cost, instant |
| **Learning feedback loop** | Mark a finding false-positive twice → that (source, sink) pair is suppressed before the LLM runs next time |
| **Honest leaderboard** | Public FP-rate benchmark on 60 clean samples + CVE recall; every number reproducible |
| **uvx one-binary install** | `uvx odin review <file>` — works from a clean machine, BYOK |
| **GitHub App** | One-click install, auto-registers webhook, reviews every PR |
| **GitHub webhook** | Manual webhook setup if you prefer |
| **MCP server** | Use Odin as a tool inside Claude Code or Cursor |
| **Local LLMs** | LM Studio, Ollama, or any OpenAI-compatible endpoint |
| **BYOK** | OpenRouter, OpenAI, Anthropic |
| **6 languages** | Python, JavaScript, TypeScript, Go, Rust, Java |

---

## How it works

```
Client / GitHub PR ──▶ FastAPI + LangGraph
                              │
                   tree-sitter AST parse
                              │
                     LangGraph fan-out (parallel)
         ┌────────────────────┼──────────────────┬──────────────────┐
         ▼                    ▼                  ▼                  ▼
   SecurityAgent        QualityAgent        DocsAgent       DataflowTriage
   (LLM call)           (LLM call)         (LLM call)      taint→LLM triage
         │                    │                  │                  │
         └────────────────────┴──────────────────┴──────────────────┘
                              │
                        Rules Engine
                     (27+ instant checks)
                              │
                         synthesize()
                    (dedup + score + sort)
                              │
               GitHub PR review / Web UI / CLI / SSE stream
```

**DataflowTriage pipeline:**
1. Walk each function body with an intra-procedural taint tracker (assignment-chain + call-arg propagation)
2. Check the (source_sig, sink_sig) suppression table — skip known-FP pairs before the LLM runs
3. LLM reasons about exploitability for remaining candidates only (≤20 per file, `asyncio.Semaphore(4)`)
4. Confirmed false positives feed back into the suppression table — noise drops over time

---

## Benchmarks

**FP rate is a first-class metric. We report where Odin loses.**

| Tool | Dataset | FP Rate | Recall | F1 |
|---|---|---|---|---|
| `odin-rules` | clean_corpus (60 samples, 6 languages) | **0.0%** | — | — |
| `odin-rules` | secvuleval-subset (14 CVEs) | — | **86%** | **0.92** |

Every competitor we tested exceeds 15% FP rate on the same clean corpus. Most don't publish FP numbers at all.

```bash
cd backend

# Run the full benchmark harness
python -m bench.harness

# Single dataset
python -m bench.harness --dataset clean_corpus
python -m bench.harness --dataset secvuleval

# JSON output for CI
python -m bench.harness --json
```

Full methodology + reproducible commands: [`bench/reports/leaderboard.md`](backend/bench/reports/leaderboard.md)

---

## Quick Start — self-hosted

### Option 1: LM Studio (local, fully private)

```bash
git clone https://github.com/RahulModugula/odin
cd odin
cp .env.example .env

# .env:
# ODIN_LLM_PROVIDER=lmstudio
# ODIN_LMSTUDIO_MODEL=qwen2.5-coder-32b

docker compose -f docker-compose.yml -f docker-compose.lmstudio.yml up
```

Open http://localhost:3000

### Option 2: OpenRouter (BYOK)

```bash
# .env:
# ODIN_LLM_PROVIDER=openrouter
# ODIN_OPENROUTER_API_KEY=sk-or-v1-...
# ODIN_OPENROUTER_MODEL=anthropic/claude-sonnet-4-5

docker compose up
```

### Option 3: OpenAI / any OpenAI-compatible API

```bash
# ODIN_LLM_PROVIDER=openai
# ODIN_LLM_API_KEY=sk-...
# ODIN_LLM_MODEL=gpt-4o-mini
docker compose up
```

---

## CLI

```bash
# Install once (no checkout required)
uvx odin review path/to/file.py

# Rules only — instant, no LLM, no server
uvx odin review path/to/file.py --rules-only

# Staged changes (pre-push check)
uvx odin review --staged --rules-only

# Fail CI on high+ severity
uvx odin review --staged --fail-on high

# JSON output for scripting
uvx odin review path/to/file.py --json | jq .

# Filter by severity and confidence
uvx odin review backend/ --min-severity high --min-confidence 0.8
```

Install as a git pre-push hook:

```bash
bash cli/install-hook.sh
```

**Flags:** `--staged` · `--diff REF` · `--rules-only` · `--quiet` · `--min-severity` · `--min-confidence` · `--fail-on` · `--json`

---

## GitHub Webhook (manual setup)

```bash
openssl rand -hex 32  # generate webhook secret
```

In your GitHub repo: Settings → Webhooks → Add webhook
- Payload URL: `https://your-odin/api/webhook/github`
- Content type: `application/json`
- Events: Pull requests, Issue comments

```bash
# .env
ODIN_GITHUB_TOKEN=ghp_...
ODIN_GITHUB_WEBHOOK_SECRET=your-secret
```

Bot commands in PRs: `@odin review` · `@odin help`

---

## Deterministic Rules Reference

| ID | Name | Severity | Language |
|---|---|---|---|
| PY001 | Bare except clause | HIGH | Python |
| PY002 | Mutable default argument | HIGH | Python |
| PY003 | eval()/exec() | CRITICAL | Python |
| PY004 | Hardcoded secret/credential | CRITICAL | Python |
| PY005 | SQL string formatting | CRITICAL | Python |
| PY006 | High cyclomatic complexity | MEDIUM | Python |
| PY007 | Overly long function | MEDIUM | Python |
| PY008 | Excessive nesting depth | MEDIUM | Python |
| PY009 | Missing type hints | LOW | Python |
| JS001 | Use of var | LOW | JS/TS |
| JS002 | console.log in code | LOW | JS/TS |
| JS003 | XSS via innerHTML | HIGH | JS/TS |
| JS004 | Deep callback nesting | MEDIUM | JS/TS |
| JS005 | JWT decode without verify | HIGH | JS/TS |
| JS006 | Prototype pollution | HIGH | JS/TS |
| TS001 | TypeScript `any` type | MEDIUM | TypeScript |
| TS002 | Non-null assertion overuse | MEDIUM | TypeScript |
| GO001 | Error return value ignored | HIGH | Go |
| GO002 | panic() in library code | HIGH | Go |
| GO003 | Goroutine leak | MEDIUM | Go |
| GO004 | SQL injection via fmt.Sprintf | CRITICAL | Go |
| GO005 | Mutex without deferred Unlock | MEDIUM | Go |
| GO006 | context.Context not first param | LOW | Go |
| GO007 | Hardcoded IP address | LOW | Go |
| GO008 | Unbuffered channel send deadlock | MEDIUM | Go |
| CL001 | TODO/FIXME comment | INFO | All |
| CL002 | File too large | MEDIUM | All |
| CL003 | Magic number | LOW | All |
| CL004 | Hardcoded credential | CRITICAL | All |

---

## Configuration (.odin.yaml)

```yaml
provider:
  name: openrouter
  model: anthropic/claude-sonnet-4-5

review:
  agents: [security, quality, docs]
  severity_threshold: low

ignore:
  paths: [vendor/, node_modules/, "*.min.js"]
  rules: [CL001]

quality_gate:
  min_score: 70
  max_critical: 0
  block_on_fail: false
```

---

## MCP Server

Use Odin as a tool inside Claude Code or Cursor:

```json
{
  "mcpServers": {
    "odin": {
      "command": "python",
      "args": ["-m", "app.mcp.stdio_runner"],
      "cwd": "/path/to/odin/backend"
    }
  }
}
```

Available tools: `review_code`, `analyze_file`, `get_findings`, `query_codebase`

---

## Development

```bash
cd backend
uv venv && uv pip install -e ".[dev]"
uvicorn app.main:app --reload

# Tests
pytest tests/ -v --cov=app

# Lint
ruff check . && ruff format --check . && mypy --strict app/

# Benchmark
python -m bench.harness --dataset clean_corpus
```

---

## License

MIT — use it, fork it, make it better.
