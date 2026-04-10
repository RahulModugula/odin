# Odin — Open-Source AI Code Review

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![LM Studio](https://img.shields.io/badge/works%20with-LM%20Studio-green.svg)](https://lmstudio.ai)
[![OpenRouter](https://img.shields.io/badge/BYOK-OpenRouter-blue.svg)](https://openrouter.ai)

**Self-hostable AI code review that works with local LLMs — no cloud required.**

Odin reviews your code with 3 AI agents running in parallel (Security, Quality, Documentation) **plus** 18+ deterministic rules that run instantly without any LLM. Connect LM Studio, OpenRouter, Ollama, or any OpenAI-compatible provider, and get PR-quality reviews right in your terminal or GitHub.

> "Like CodeRabbit but self-hosted and free."

---

## Features

| Feature | Details |
|---------|---------|
| 🤖 **Multi-agent AI review** | Security, Quality, and Documentation agents run in parallel via LangGraph |
| ⚡ **18+ deterministic rules** | Instant, zero-cost checks: bare except, mutable defaults, SQL injection, XSS, secrets, and more |
| 🖥️ **LM Studio support** | Run fully local with Qwen2.5-Coder, Mistral, or any compatible model |
| 🔀 **OpenRouter BYOK** | Plug in your own key — access Claude, GPT-4, Gemini, and 100+ models |
| 🦙 **Ollama support** | Works with any Ollama model |
| 🐙 **GitHub webhook** | Posts structured reviews on every PR with summaries, walkthroughs, and inline comments |
| 🔧 **CLI tool** | Review files locally before you push, or install as a git pre-push hook |
| 🌐 **6 languages** | Python, JavaScript, TypeScript, Go, Rust, Java |
| 📊 **Eval suite** | Benchmark detection accuracy across 10 sample files (93% recall, rules-only) |
| 🧠 **Feedback learning** | Mark findings as helpful/false-positive — Odin adapts over time |
| 🔌 **MCP server** | Use Odin as an MCP tool inside Claude Code or Cursor |

---

## Quick Start

### Option 1: LM Studio (local, free, private)

```bash
# 1. Install and start LM Studio, load a model (Qwen2.5-Coder-32B recommended)
# 2. Enable local server in LM Studio (port 1234)

# Clone and start
git clone https://github.com/your-org/odin
cd odin
cp .env.example .env

# Edit .env:
# ODIN_LLM_PROVIDER=lmstudio
# ODIN_LMSTUDIO_MODEL=qwen2.5-coder-32b

docker compose -f docker-compose.yml -f docker-compose.lmstudio.yml up
```

Open http://localhost:3000

### Option 2: OpenRouter (BYOK)

```bash
cp .env.example .env
# Edit .env:
# ODIN_LLM_PROVIDER=openrouter
# ODIN_OPENROUTER_API_KEY=sk-or-v1-...
# ODIN_OPENROUTER_MODEL=anthropic/claude-sonnet-4-5

docker compose up
```

### Option 3: OpenAI / Any OpenAI-compatible API

```bash
# ODIN_LLM_PROVIDER=openai
# ODIN_LLM_API_KEY=sk-...
# ODIN_LLM_MODEL=gpt-4o-mini
# ODIN_LLM_BASE_URL=https://api.openai.com/v1

docker compose up
```

---

## Web UI — Review in the Browser

**Keyboard shortcuts:**
- `Cmd+Enter` (Mac) / `Ctrl+Enter` (Linux/Windows) — submit review from editor
- Settings modal to switch between LM Studio, OpenRouter, OpenAI, or Ollama

---

## CLI — Review Before You Push

```bash
# Review a single file
python cli/odin_review.py backend/app/main.py --rules-only

# Review staged changes (pre-push check)
python cli/odin_review.py --staged --rules-only

# Review changes since last commit, full AI review
python cli/odin_review.py --diff HEAD~1

# Quiet mode for git hooks (suppress banners)
python cli/odin_review.py --staged --quiet && git push

# Filter by severity and confidence
python cli/odin_review.py backend/ --min-severity high --min-confidence 0.8

# Output as JSON for CI/scripting
python cli/odin_review.py --staged --json | jq .

# Install as git pre-push hook
bash cli/install-hook.sh
```

**CLI flags:**
- `--staged` — review only git staged files
- `--diff REF` — review changes since a commit/branch (e.g., `HEAD~1`, `origin/main`)
- `--rules-only` — run deterministic rules only (instant, no LLM)
- `--quiet` / `-q` — suppress output on clean scans (ideal for CI/hooks)
- `--min-severity {critical|high|medium|low|info}` — filter by severity
- `--min-confidence FLOAT` — filter by confidence score (0.0–1.0)
- `--fail-on {critical|high|...}` — exit 1 if this severity is found
- `--json` — output findings as JSON

Example output:
```
🔍 Odin Code Review
Files: 1  Mode: rules-only

backend/app/api/routes.py
  🔴 CRITICAL [rule] Hardcoded credential or secret  line 42
     Line 42: Credential appears to be hardcoded. CWE-798.
     → Use environment variables: os.environ['MY_SECRET']

Summary: 1 finding(s) in 1 file(s)
  critical: 1
✗ 1 blocking finding(s) at high+ severity
```

---

## GitHub Webhook Setup

1. Generate a webhook secret:
   ```bash
   openssl rand -hex 32
   ```
2. In your GitHub repo: Settings → Webhooks → Add webhook
   - Payload URL: `https://your-odin-instance/api/webhook/github`
   - Content type: `application/json`
   - Secret: your generated secret
   - Events: Pull requests, Issue comments
3. Set env vars:
   ```
   ODIN_GITHUB_TOKEN=ghp_...
   ODIN_GITHUB_WEBHOOK_SECRET=your-secret
   ```

**Bot commands in PRs:**

Comment `@odin review` to trigger a fresh review, or `@odin help` to see all commands.

Odin will post reviews like this on every PR:

```
## 🔍 Odin Code Review

### ✨ Summary
This PR adds user authentication with JWT tokens...

**Type:** feature   **Risk:** 🟡 medium

<details>
<summary>📋 Walkthrough</summary>
| File | Change |
|------|--------|
| `auth/jwt.py` | New JWT generation and validation functions |
| `api/routes.py` | Added /login and /logout endpoints |
</details>

### 📊 File Review Summary
| File | Score | Critical | High | Medium | Low |
|------|-------|----------|------|--------|-----|
| `auth/jwt.py` | 🟡 72/100 | — | 1 | 2 | — |
```

Inline comments with severity badges and fix suggestions are posted on changed lines.

### Bot Commands

Reply to Odin's review comments:
- `@odin review` — trigger a fresh review
- `@odin-bot review` — same

---

## Configuration (.odin.yaml)

Place in your repo root:

```yaml
provider:
  name: lmstudio
  base_url: http://localhost:1234/v1
  model: qwen2.5-coder-32b

review:
  agents: [security, quality, docs]
  severity_threshold: low

ignore:
  paths:
    - vendor/
    - node_modules/
    - "*.min.js"
  rules:
    - CL001  # suppress TODO/FIXME rule

quality_gate:
  min_score: 70
  max_critical: 0
  block_on_fail: false

rules:
  enabled: true
  complexity_threshold: 10
  function_length_threshold: 50
  nesting_depth_threshold: 4
```

---

## Deterministic Rules Reference

| ID | Name | Severity | Language |
|----|------|----------|----------|
| PY001 | Bare except clause | HIGH | Python |
| PY002 | Mutable default argument | HIGH | Python |
| PY003 | Use of eval()/exec() | CRITICAL | Python |
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
| TS001 | TypeScript `any` type | MEDIUM | TypeScript |
| CL001 | TODO/FIXME comment | INFO | All |
| CL002 | File too large | MEDIUM | All |
| CL003 | Magic number | LOW | All |
| CL004 | Hardcoded credential | CRITICAL | All |

---

## Architecture

```
                           .odin.yaml / env vars
                                   │
Client / GitHub PR ──────▶ FastAPI Backend
                                   │
                     tree-sitter AST parse
                                   │
                          LangGraph fan-out
                   ┌───────────────┼──────────────┬──────────────┐
                   ▼               ▼              ▼              ▼
            SecurityAgent    QualityAgent    DocsAgent     DataflowTriage
            (LLM call)       (LLM call)    (LLM call)    (taint → LLM)
                   │               │              │              │
                   └───────────────┴──────────────┴──────────────┘
                                   │
                              Rules Engine
                           (18+ instant, zero-cost)
                                   │
                              synthesize()
                           (dedup + score + sort)
                                   │
                      GitHub PR Review / UI / SSE stream
```

**DataflowTriage** implements the [LLift](https://www.cs.ucr.edu/~zhiyunq/pub/oopsla24_llift.pdf) / [INFERROI](https://conf.researchr.org/details/icse-2025) architecture:
1. Intra-procedural taint analysis identifies source→sink candidates
2. LLM reasons about exploitability of narrowed candidates only
3. Feedback loop suppresses known-FP (source, sink) pairs at the generator level

**LLM Providers** (configured via `ODIN_LLM_PROVIDER`):
- `lmstudio` — http://localhost:1234/v1
- `openrouter` — https://openrouter.ai/api/v1
- `openai` — https://api.openai.com/v1
- `ollama` — http://localhost:11434/v1
- `default` — any OpenAI-compatible endpoint

---

## Benchmarks

### Honest Leaderboard (reproducible — run it yourself)

| Tool | Dataset | FP Rate | Recall | Precision | F1 |
|---|---|---|---|---|---|
| `odin-rules` | clean_corpus (60 samples) | **0.0%** | — | — | — |
| `odin-rules` | secvuleval-subset (14 CVEs) | — | **86%** | **100%** | **0.92** |

**FP rate** = false positives on 60 idiomatic, production-quality clean-code samples (Python, JS, TS, Go, Rust, Java). Every competitor we've tested exceeds 15% on the same corpus.

> "We report where Odin loses, not just where it wins. Every number here is reproducible."

```bash
cd backend

# Internal regression suite (instant)
python -m eval.runner --rules-only

# Honest benchmark — clean corpus FP rate + CVE recall
python -m bench.harness

# Single dataset
python -m bench.harness --dataset clean_corpus
python -m bench.harness --dataset secvuleval

# Machine-readable JSON
python -m bench.harness --json
```

Full leaderboard with methodology: [`bench/reports/leaderboard.md`](backend/bench/reports/leaderboard.md)

---

## MCP Server

Use Odin as an MCP tool inside Claude Code or Cursor:

```json
// ~/.claude/claude_desktop_config.json
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

## Self-hosting

```bash
# Production (2 workers, non-root user)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# With Prometheus metrics
curl http://localhost:8000/metrics
```

Environment variables reference: see `.env.example`

---

## Development

```bash
# Backend
cd backend
uv venv && uv pip install -e ".[dev]"
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev

# Run tests
cd backend
pytest tests/ -v

# Benchmark
python -m eval.runner --rules-only
```

---

## vs CodeRabbit

| Feature | Odin | CodeRabbit Free | CodeRabbit Pro |
|---------|------|-----------------|----------------|
| Self-hostable | ✅ | ❌ | ❌ |
| Local LLMs (LM Studio) | ✅ | ❌ | ❌ |
| BYOK (OpenRouter) | ✅ | ❌ | ✅ |
| GitHub webhook | ✅ | ✅ | ✅ |
| PR summary & walkthrough | ✅ | ✅ | ✅ |
| Inline comments | ✅ | ✅ | ✅ |
| Deterministic rules | ✅ (18+) | ✅ (40+) | ✅ (40+) |
| CLI pre-push review | ✅ | ❌ | ❌ |
| Open source | ✅ | ❌ | ❌ |
| Cost | Free | Free (limited) | $24/dev/mo |
| Data privacy | ✅ Full | ❌ | ❌ |

---

## License

MIT — use it, fork it, make it better.
