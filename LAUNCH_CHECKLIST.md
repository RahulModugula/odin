# Pre-Launch Checklist

Cross-reference with `finalplan.md` §3.1. Anything marked ⚠ requires action outside this repo (infra, third-party accounts, manual verification).

## ✅ Code complete on `main`

- [x] **Noise budget mode** — `max_findings` in `.odin.yml`, `--max-findings` CLI flag, PR body shows suppressed count (`app/cli/config.py`, `app/cli/review.py`, `app/services/webhook_processor.py`).
- [x] **AI Code Validator mode** — `--ai-generated` flag, auto-detects Copilot/ChatGPT/Claude mentions in PR title/body, lowers dataflow confidence floor to 0.45 (`app/agents/prompts.py`, `app/agents/graph.py`, `app/services/webhook_processor.py`).
- [x] **Semgrep competitor benchmark** — real head-to-head numbers in `backend/bench/reports/leaderboard.md`, reproducible with `python -m bench.harness --seed 42`.
- [x] **Live demo API** — `POST /api/demo/review` + `GET /api/demo/limits`, IP rate-limited via Redis (`app/api/demo.py`).
- [x] **VS Code extension** — compiles clean with `npm run compile`, diagnostics API wired, on-save + on-demand commands (`vscode-extension/`).
- [x] **Policy-as-code** — YAML loader at `app/rules/custom_loader.py`, auto-registered by `register_all()`, sample rule in `.odin/rules/example-no-pickle-loads.yml`.
- [x] **Test suite** — 329 tests green.

## ⚠ Manual steps remaining

### 1. Deploy the live demo instance

Choose Fly.io (free tier scales to zero) or Render (simpler UI):

```bash
# Fly.io — recommended for cost control
flyctl launch --copy-config --config infra/demo/fly.toml --name odin-demo --no-deploy
flyctl redis create --name odin-demo-cache --plan free
flyctl redis attach odin-demo-cache
flyctl secrets set ODIN_LLM_API_KEY=sk-... ODIN_DEMO_ENABLED=true
flyctl deploy
```

After deploy: smoke-test `curl https://odin-demo.fly.dev/api/demo/limits`. Update the frontend demo-page URL in `frontend/` (and any README badges) to point at the new host.

### 2. Publish the VS Code extension

```bash
cd vscode-extension
npm install
npm run compile
npx vsce package
```

Create a publisher at <https://marketplace.visualstudio.com/manage>, then:

```bash
npx vsce login odin-review
npx vsce publish
```

Promote the Marketplace URL from the main README once live.

### 3. Run the benchmark against the hosted competitors

The harness wires in CodeQL, CodeRabbit, Greptile, Qodo, and Copilot Review but each requires an API token / installation the runner detects. Once you have access:

```bash
cd backend
export CODERABBIT_API_KEY=...
export GREPTILE_API_KEY=...
export QODO_API_KEY=...
python -m bench.harness --seed 42
```

The leaderboard regenerates automatically. Commit the new `bench/reports/results/<date>-<run_id>.json` + updated `leaderboard.md`.

### 4. Submit an OSS "Found by Odin" PR

Plan §3.5 prescribes the process. Target repos: FastAPI, httpx, Starlette, gin, Chi. Workflow:

```bash
uvx odin-review review path/to/cloned/repo --min-severity high --min-confidence 0.85 --json > findings.json
```

Manually verify the top finding, file a PR titled *"fix: <issue> (found by Odin)"*, link it from README once merged.

### 5. Blog post + HN launch

`BLOG_POST.md` is drafted. Before posting:

- Refresh all stats against the new leaderboard (semgrep 2.1% FP, Odin dataflow 0.0%, etc.).
- Add screenshots: VS Code extension, live demo page, PR comment.
- Have 1–2 senior engineers review before posting to HN.

Launch sequence (Tuesday 8 AM ET): Show HN → r/netsec → r/selfhosted → X thread. See `LAUNCH_PLAYBOOK.md`.

## Smoke test on a clean machine

Before posting, validate the zero-install path works end-to-end:

```bash
# On a fresh VM with only Python 3.12 + uv installed
export ODIN_LLM_PROVIDER=openrouter
export ODIN_OPENROUTER_API_KEY=sk-or-v1-...
uvx odin-review review <(echo 'import subprocess; subprocess.run(user_input, shell=True)') --rules-only
```

Expected: critical finding for command injection, exit code 1. If anything fails, fix it *before* posting — every HN reader will try this one-liner.

## Files touched this round

- `backend/app/cli/review.py` — `--max-findings`, `--ai-generated` flags
- `backend/app/cli/config.py` — `max_findings` in `.odin.yml`
- `backend/app/config.py` — `max_findings`, `demo_enabled` settings
- `backend/app/agents/prompts.py` — `AI_GENERATED_APPENDIX`, `detect_ai_generated()`
- `backend/app/agents/graph.py`, `security_agent.py`, `quality_agent.py`, `docs_agent.py` — thread the flag through
- `backend/app/services/webhook_processor.py` — `_apply_noise_budget`, auto AI-detection
- `backend/app/api/demo.py` — public rate-limited endpoint
- `backend/app/rules/custom_loader.py` — YAML rule parser + engine bridge
- `backend/app/rules/registry.py` — auto-loads custom rules
- `backend/tests/test_ai_generated_mode.py`, `test_custom_rules.py`, `test_demo_endpoint.py` — coverage for new surfaces
- `backend/bench/reports/leaderboard.md` — real Semgrep vs Odin head-to-head
- `vscode-extension/` — full TypeScript scaffold, compiles clean
- `infra/demo/fly.toml`, `infra/demo/README.md` — deployment config
- `.odin/rules/example-no-pickle-loads.yml` — seed custom rule
- `README.md` — competitor chart, new-flag docs, editor/demo section
