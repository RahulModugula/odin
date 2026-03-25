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

## CLI — Review Before You Push

```bash
# Review a single file
python cli/odin_review.py backend/app/main.py --rules-only

# Review staged changes (use as pre-push check)
python cli/odin_review.py --staged --rules-only

# Review changes since last commit, full AI review
python cli/odin_review.py --diff HEAD~1

# Install as git pre-push hook
bash cli/install-hook.sh
```

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
                        ┌──────────┴──────────┐
                        │                     │
               tree-sitter AST           Rules Engine
               (parse_code)            (18+ instant rules)
                        │                     │
                   LangGraph ─────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
    SecurityAgent  QualityAgent  DocsAgent
    (LLM call)     (LLM call)   (LLM call)
          │             │             │
          └─────────────┴─────────────┘
                        │
                   synthesize()
                (dedup + score)
                        │
               GitHub PR Review / UI
```

**LLM Providers** (configured via `ODIN_LLM_PROVIDER`):
- `lmstudio` — http://localhost:1234/v1
- `openrouter` — https://openrouter.ai/api/v1
- `openai` — https://api.openai.com/v1
- `ollama` — http://localhost:11434/v1
- `default` — any OpenAI-compatible endpoint

---

## Benchmarks (Rules-only, no LLM)

```
Sample              Lang    Recall  Findings
clean_code          Go      100%    0
goroutine_leak      Go       50%    3
xss_vulnerable      JS      100%    3
complex_function    Python  100%    3
hardcoded_secrets   Python  100%    5
sql_injection       Python  100%    3
any_abuse           TS       75%    10
type_safety         TS      100%    0
─────────────────────────────────────────
AVERAGE                      93%
Passed: 9/10 (recall ≥ 70%)
```

Run the benchmark yourself:
```bash
cd backend
python -m eval.runner --rules-only          # instant
python -m eval.runner                        # full AI (needs LLM)
python -m eval.runner --rules-only --lang python
```

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
