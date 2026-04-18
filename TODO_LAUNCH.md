# Odin — Launch TODO

Everything left for you (not Claude) to do. Ordered by leverage. Owner: you.

---

## 1. Smoke-test the zero-install path on a clean machine

**Why first:** every HN reader will try this. If it fails, the launch is dead on arrival.

```bash
# Fresh VM with only Python 3.12 + uv installed. No checkout.
export ODIN_LLM_PROVIDER=openrouter
export ODIN_OPENROUTER_API_KEY=sk-or-v1-...
uvx odin-review review path/to/test_file.py --rules-only
uvx odin-review review path/to/test_file.py --local   # full AI pipeline
```

**Expected:** exit 0 on clean code; exit 1 with findings on intentionally-bad code. Fix anything that breaks **before** posting.

Acceptance: a video/GIF of the one-liner working from a clean shell. Drop it in the README above-the-fold.

---

## 2. Deploy the live demo

**Why:** every successful HN dev-tool post has a "try without installing" link. 3–5× viral multiplier per §2.2 of `finalplan.md`.

### Fly.io (recommended — scales to zero)

```bash
flyctl launch --copy-config --config infra/demo/fly.toml --name odin-demo --no-deploy
flyctl redis create --name odin-demo-cache --plan free
flyctl redis attach odin-demo-cache                    # exports REDIS_URL
flyctl secrets set \
    ODIN_LLM_API_KEY=sk-... \
    ODIN_DEMO_ENABLED=true \
    ODIN_REDIS_URL='$REDIS_URL'
flyctl deploy
```

### Render.com (simpler UI)

Set `ODIN_DEMO_ENABLED=true`, `ODIN_LLM_API_KEY`, `ODIN_REDIS_URL`, `ODIN_MAX_FINDINGS=10`. Deploy notes live in `infra/demo/README.md`.

### After deploy

- Hit `curl https://odin-demo.fly.dev/api/demo/limits` — should return JSON with `remaining: 5`.
- Paste bad code into the frontend demo page, confirm findings stream in.
- Put Cloudflare / nginx rule in front allowing only `/api/demo/*` + `/api/health` — everything else stays internal.
- Set a hard LLM spend cap in your provider dashboard. Worst case: 5 reviews × 500 LOC × N IPs.

Acceptance: public URL responds, rate limit works after 5 requests, frontend demo-page URL updated.

---

## 3. Publish the VS Code extension

**Why:** 10M+ VS Code users. Marketplace listing generates organic discovery forever.

```bash
cd vscode-extension
npm install
npm run compile                          # verify clean TS compile (already done)
npx vsce package                         # produces odin-review-0.1.0.vsix
```

Create a publisher at <https://marketplace.visualstudio.com/manage> (takes ~10 min; requires an Azure DevOps personal-access token with Marketplace → Publish scope).

```bash
npx vsce login odin-review
npx vsce publish
```

Acceptance: extension live at `https://marketplace.visualstudio.com/items?itemName=odin-review.odin-review`. Add the "Install from Marketplace" badge to the main README above-the-fold.

---

## 4. Benchmark the hosted competitors

The harness in `backend/bench/tools/` already has runners for CodeRabbit, Greptile, Qodo, CodeQL, and Copilot Review — they just need credentials.

```bash
cd backend
export CODERABBIT_API_KEY=...
export GREPTILE_API_KEY=...
export QODO_API_KEY=...
export GITHUB_TOKEN=...                  # for CodeQL + Copilot
python -m bench.harness --seed 42        # runs every available tool
```

Commit the new `bench/reports/results/<date>-<run_id>.json` and the regenerated `bench/reports/leaderboard.md`. Expected: the same head-to-head table you already have, just with more rows. CodeRabbit's FP rate is the headline number — that's the "gotcha" in the blog post.

Manual-measurement fallback if API access is slow: pick 14 CVE samples from `bench/datasets/secvuleval.py`, push each as a PR to a throwaway repo with CodeRabbit installed, count the reviews' findings. Document the methodology in `bench/reports/leaderboard.md`.

Acceptance: at least one hosted competitor present in every table in the leaderboard.

---

## 5. Submit an OSS "Found by Odin" PR

**Why:** §3.5 of `finalplan.md` — "A single merged PR to a popular OSS project is worth more than 1000 GitHub stars for hireability."

```bash
# Target repos (pick one with active maintainers):
#   fastapi/fastapi, encode/httpx, encode/starlette, gin-gonic/gin, go-chi/chi
git clone https://github.com/<target> /tmp/target && cd /tmp/target
uvx odin-review review . --min-severity high --min-confidence 0.85 --json \
    > /tmp/odin-findings.json
```

Process:

1. Read every finding with confidence ≥ 0.85. Expect < 20 in a mature repo.
2. **Manually verify** each one is a real bug (not a false positive). This step is load-bearing — submitting a bogus PR burns the "Found by Odin" brand.
3. For the first real bug, file a PR titled `fix: <specific issue> (found by Odin)` with:
   - The taint chain or rule ID in the PR body
   - A minimal repro
   - A link to `https://github.com/RahulModugula/odin`
4. Link the merged PR from the README.

Acceptance: PR merged (or at minimum acknowledged-as-valid) into a repo with > 10k stars.

---

## 6. Finalize the blog post

`BLOG_POST.md` is drafted but needs updates after tasks 2, 4 land.

- [ ] Replace placeholder numbers with real leaderboard values (Semgrep 2.1%, Odin dataflow 0.0%, CodeRabbit FP rate if task 4 landed).
- [ ] Add a "Try it" callout linking to the live demo (task 2).
- [ ] Add a VS Code Marketplace badge (task 3).
- [ ] Add the OSS-bug citation if task 5 landed.
- [ ] Embed the hero chart (head-to-head FP-rate + recall). Generate a PNG from the leaderboard table — a chart image is more shareable than a markdown table.
- [ ] Have 1–2 senior engineers review the post before posting. Verify every claim maps to a reproducible command.

Acceptance: blog post published on your own domain or Substack. Post should load in < 2s, render on mobile, have a clear CTA to the repo and live demo.

---

## 7. Launch sequence

Post on a Tuesday at 8 AM ET (best HN slot). From `finalplan.md` §3.3:

| Time | Channel | Angle |
|---|---|---|
| Tue 8:00 AM ET | **Show HN** | "I benchmarked every AI code reviewer on 500 CVEs — here's the data" |
| Tue 8:05 AM | HN founder comment | Methodology, honest caveats, reproduce command |
| Tue 8:30 AM | r/netsec | "Published FP benchmarks for AI SAST tools" |
| Tue 9:00 AM | r/selfhosted, r/LocalLLaMA | Self-hosting + local LLM angle |
| Tue 9:30 AM | X / Bluesky thread | Hero chart image + repo link |
| Wed | r/programming, dev.to cross-post | Architecture deep-dive angle |
| Thu | LinkedIn post | Hireable-signal framing for recruiters |
| +7 days | HN resubmit if first didn't hit front page | Different title angle |

Pre-submit checklist for Show HN:
- [ ] Repo is pinned on your GitHub profile
- [ ] README above-the-fold has the benchmark chart + demo link + VS Code badge + 30s GIF
- [ ] CI badge is green on `main`
- [ ] You can answer within 5 minutes for the first 2 hours — HN engagement rewards fast, substantive founder replies

---

## 8. Post-launch (first week)

- Same-day response to every GitHub issue (Ruff's strategy — got them to 47k stars).
- Add Odin to `awesome-static-analysis`, `awesome-code-review`, `awesome-ai-tools` lists.
- Run Odin against whatever new CVE hits the news that week; tweet the result.
- If an HN commenter asks "does it handle X?", try X live and reply with a command they can run.

---

## Reference

- Code-complete status: `LAUNCH_CHECKLIST.md`
- Full strategy: `finalplan.md` §2–§3
- Launch messaging + sample posts: `LAUNCH_PLAYBOOK.md`
- Demo deploy details: `infra/demo/README.md`
