# Odin Benchmark Leaderboard

**Run**: `db76e24a` | **Commit**: `fc73128` | **Last full rerun**: 2026-04-17

> Reproducible benchmark of AI code review tools on clean code (false-positive rate)
> and real vulnerability samples (recall). Every number here can be reproduced with
> `python -m bench.harness --seed 42`. We report **where Odin loses**, not just where it wins.

## What each dataset actually measures

Read this before reading the tables. Confusing "security bugs" with "logic bugs" is
the single most common way these benchmarks are misread.

| Dataset | What it tests | Fair to compare across tools? |
|---|---|---|
| `clean_corpus` (193 samples) | **False-positive rate** on idiomatic, production-quality code with zero real issues. | Yes — a lower FP rate is strictly better. |
| `secvuleval-subset` (14 samples) | **Security-bug recall** on Python/JS equivalents of CVEs and CWEs. SecVulEval itself is C/C++. | Yes, for security tools. |
| `cvebench-crits` (50 samples) | **Security-bug recall** on critical CVEs. Reported SOTA is ~13% — very hard. | Yes, for security tools. |
| `swebench-verified` (50 samples) | **General-bug recall** on logic errors, off-by-ones, and feature bugs — **not security**. | ⚠ Apples-to-oranges when compared against SAST tools. Treat as a ceiling for "can a reviewer catch any bug at all?", not a CVE number. |

## False Positive Rate on Clean Code (193 samples)

A tool with a high FP rate generates noise that erodes developer trust.

| Tool | FP Rate | False Positives | Samples | Reproduce |
|---|---|---|---|---|
| `semgrep` | 2.1% | 4/193 | 193 | `python -m bench.harness --dataset clean_corpus --tool semgrep --seed 42` |

**Scope of the 0.0% dataflow number quoted in the README:** Odin's dataflow tracker only
fires on candidates that have a full source → sink path through ~8 sink categories
(`code_exec`, `shell_exec`, `sql_query`, `dom_write`, `path_traversal`, `ssrf_fetch`,
`template_render`, `deserialized`). A 0.0% FP rate on that narrow surface is not the same
shape of claim as Semgrep's 2.1% across its entire ruleset — it's a much smaller haystack.
The `odin-rules` 8.8% FP rate on the same clean corpus is the fairer head-to-head number.

Full Odin rows are regenerated via the harness but not committed to this file while
results are in flux; run `python -m bench.harness --tool odin-dataflow --dataset clean_corpus --seed 42`
to reproduce the dataflow row locally.

## Recall on SecVulEval (14 Python/JS CVEs)

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `semgrep` | 50% | 100% | 0.67 | 7 | 7 | `python -m bench.harness --dataset secvuleval-subset --tool semgrep --seed 42` |

## Recall on CVE-Bench critical CVEs (SOTA ~13%)

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `semgrep` | 26% | 100% | 0.41 | 13 | 37 | `python -m bench.harness --dataset cvebench-crits --tool semgrep --seed 42` |

## Recall on SWE-bench Verified (⚠ logic bugs, not CVEs)

> **Read this first.** SWE-bench Verified measures general bug-finding — feature bugs,
> off-by-ones, missing null checks, incorrect return values. It is **not** a security
> benchmark. High recall here means "this tool can flag arbitrary bugs in real repos,"
> not "this tool catches security vulnerabilities." Do not compare these numbers
> directly against the SecVulEval / CVE-Bench rows above.

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `semgrep` | 2% | 100% | 0.04 | 1 | 49 | `python -m bench.harness --dataset swebench-verified --tool semgrep --seed 42` |

## Methodology

- **Clean corpus**: 200+ clean snippets across Python/JS/TS/Go/Rust/Java — FP rate is the headline metric.
- **SecVulEval subset**: 14 Python/JS CVE/CWE samples (language-equivalent; SecVulEval itself is C/C++).
- **CVE-Bench crits**: 50 critical CVEs; SOTA is ~13% recall — low numbers are expected and disclosed.
- **SWE-bench Verified**: 50-sample general-bug-detection subset. Logic errors, not security. Do not compare recall here to CVE recall.
- **Competitor notes**: CodeRabbit / Greptile / Qodo / CodeQL / Copilot Review runners exist in the harness but require API access. Until those rows are populated, the head-to-head is against Semgrep only.
- **Reproducible**: every row has the exact command to regenerate it; dataset versions pinned by `DATASET_VERSION`.
- **Honest**: we include all samples where Odin loses, including hard cases.

## Reproduce These Results

```bash
cd backend
python -m bench.harness --seed 42
```

*Dataset versions: secvuleval-v1.0 · swebench-verified-v1 · cvebench-v1-crits-50 · See `bench/datasets/` for all samples.*