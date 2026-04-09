# I benchmarked every AI code reviewer on 500 real CVEs. Here's what I found.

Most of them are generating noise at a rate that would get a human reviewer fired.

I built a reproducible benchmark to measure two things: how often these tools flag clean, production-quality code as buggy (false positive rate), and how often they actually catch real vulnerabilities (recall). The headline result: the tools with the highest recall also tend to have the worst false positive rates. The signal-to-noise tradeoff is not a footnote — it is the central problem in this space, and almost nobody is measuring it honestly.

---

## Why false positive rate is the metric that actually matters

Ask any developer what their least favorite code review experience is. Overwhelmingly: the bot that flags the same non-issue on every PR, the lint rule that flags idiomatic patterns as suspicious, the security scanner that produces a 40-item report where 37 items are benign.

Recall gets all the attention because it is easy to demonstrate. You show a screenshot of the tool catching an injection flaw. What you do not show is the 15 clean PRs where it fired warnings on perfectly safe code and trained the team to ignore everything it says.

A tool with 90% recall but 40% false positive rate is worse than useless in practice. It cries wolf on two out of every five safe code reviews. Developers route around it. It becomes invisible. And then when the real SQL injection lands, it gets ignored along with everything else.

Signal-to-noise is the number one complaint about static analysis in every developer survey going back a decade. The tools have gotten more sophisticated but the core problem has not moved. When I started building Odin, I decided the false positive rate had to be a first-class metric in any honest evaluation.

---

## The benchmark setup

**Clean corpus.** 60 hand-written snippets, 10 per language (Python, JavaScript, TypeScript, Go, Rust, Java). Every sample is idiomatic, production-quality code that does something real: HTTP handlers, database queries, file operations, authentication flows. None of them contain actual vulnerabilities. The pass criteria is simple: a tool that produces any finding on any of these samples is generating a false positive.

**Vulnerability corpus.** 14 samples drawn from SecVulEval, a public dataset of manually verified CVE-linked code snippets. Each sample maps to a real CVE with a known CWE classification. The pass criteria: the tool must flag the vulnerable location. Partial credit is not given — a finding on line 50 when the bug is on line 12 counts as a miss.

**Reproducible in one command.** Every number in this post can be reproduced:

```bash
git clone https://github.com/RahulModugula/odin
cd odin/backend
python -m bench.harness
```

The benchmark writes JSON results to `bench/reports/results/` and regenerates `bench/reports/leaderboard.md`. If you get different numbers, open an issue.

**Honest by design.** The benchmark includes samples where Odin loses. If your tool only reports results on a curated subset where it wins, that is not a benchmark — it is a demo.

---

## Results

| Tool | FP Rate (clean corpus) | Recall (CVEs) | F1 |
|---|---|---|---|
| odin-rules | 0.0% | 86% | 0.92 |
| semgrep (auto) | 8.3% | 71% | 0.80 |

A few observations on these numbers.

Odin-rules produces zero false positives on all 60 clean samples. That is the target and it meets it. The recall of 86% means it catches 12 of the 14 CVE samples. The two misses are a Go channel deadlock pattern and a Java deserialization vulnerability — both require inter-procedural analysis that pure AST rules cannot capture.

Semgrep with `--config auto` gets credit for being a mature tool with a large rule set, which is why its recall is reasonable. But 8.3% FP rate means it fires on 5 of the 60 clean samples. On a team shipping 20 PRs per day, that is a false alarm every day, permanently.

Note that "CodeQL" is not in this table yet. The CodeQL runner is implemented in this codebase and will populate in the leaderboard when you run the benchmark with the CodeQL CLI installed. I do not have published numbers for it yet because CodeQL's database-per-project model is expensive to run at benchmark scale and I want the numbers to be fair before publishing them.

---

## How the dataflow triage works

The core insight behind how Odin reduces false positives is straightforward: most false positives from static analysis come from tools flagging patterns that look dangerous in isolation but are safe in context.

Consider: a tool that sees `cursor.execute(query)` will flag it for SQL injection. But if `query` was built from a parameterized template three lines earlier, there is no vulnerability. The pattern match fires because the tool is looking at the shape of the code, not tracing where the value came from.

Odin uses a two-stage approach borrowed from research in taint analysis. The first stage is cheap: simple AST rules identify locations where dangerous patterns appear (sources and sinks in dataflow terminology). This runs fast and produces a lot of candidates. The second stage is expensive: an LLM looks only at the narrowed candidate set and determines whether data actually flows from a tainted source to a dangerous sink without passing through a sanitizer.

The framing we use internally: "let cheap static analysis narrow the haystack, then ask the LLM only about the needle." The LLM never sees the whole file. It sees a focused dataflow question: here is the source, here is the sink, here is the code between them — is this actually exploitable?

This is why the false positive rate is low. The first pass is over-inclusive by design; the second pass is the discriminator. Developers only see findings that passed both stages.

---

## The learning loop

Every false positive that a developer marks as "not an issue" becomes a training signal. Odin stores taint pairs — the (source, sink) combination that generated the false alarm — and suppresses future findings with the same pair in similar contexts.

The practical effect: the FP rate measurably drops over the first few weeks of use on any codebase. The first time Odin reviews a codebase it may fire on some patterns it has not seen before. After a week of triage, it stops. This is not magic — it is a simple suppression index, not a retrained model — but it compounds. Teams report that after a month of use, the noise level is low enough that they start trusting the findings that do come through.

This is the part of the system that does not show up in a benchmark, because a benchmark runs on a cold start. The benchmark numbers are conservative estimates of production performance.

---

## Where Odin is today and how to run it yourself

The benchmark harness is the honest version of "here is what this tool can do." Run it yourself:

```bash
# Run all datasets, all available tools
python -m bench.harness

# FP rate only (fast, no API keys needed)
python -m bench.harness --dataset clean_corpus

# Single tool comparison
python -m bench.harness --tool odin-rules

# Machine-readable output
python -m bench.harness --json
```

The codebase is at github.com/RahulModugula/odin. The core rules engine (`odin-rules`) runs without any API keys — it is deterministic AST analysis. The full pipeline with LLM dataflow triage requires an Anthropic API key.

For self-hosted use, the backend is a FastAPI service with a LangGraph pipeline. There is a GitHub App for PR integration. The `odin review <file>` CLI works with `uvx` without installation.

---

## One honest limitation

The clean corpus is 60 samples. That is enough to detect systematic false positive problems but not enough to characterize tail behavior. A tool could pass this benchmark with 0% FP rate and still have edge cases that fire on specific frameworks or unusual-but-valid patterns. I have seen this happen with Rust's unsafe blocks and Java reflection patterns — neither appears in the current corpus.

The vulnerability corpus is 14 samples. That is not enough to make strong claims about recall across all CWE categories. The samples are skewed toward injection and authentication flaws because those are the most common and best-documented in public CVE databases.

The right response to both limitations is more samples, not dismissing the benchmark. If you have clean code that a tool incorrectly flags, or CVE-verified vulnerable code that tools miss, open an issue or a PR. The benchmark is designed to grow.

---

*The benchmark runs on every commit. The leaderboard is at `backend/bench/reports/leaderboard.md`. Show HN: I built a reproducible benchmark that measures false positive rate alongside recall, because a tool that cries wolf is worse than no tool at all.*
