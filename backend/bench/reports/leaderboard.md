# Odin Benchmark Leaderboard

**Run**: `eb5741b8` | **Commit**: `62587bb` | **Date**: 2026-04-16

> Reproducible benchmark of AI code review tools on clean code (false positive rate) and real vulnerability samples (recall).
> Every number here can be reproduced: `python -m bench.harness --seed 42`
> We report **where Odin loses**, not just where it wins.

## Key Metric: False Positive Rate on Clean Code

A tool with a high FP rate generates noise that erodes developer trust.
All 200+ samples in the clean corpus are idiomatic, production-quality code with **zero real issues**.

| Tool | FP Rate | False Positives | Samples | Reproduce |
|---|---|---|---|---|
| `odin-rules` | 8.8% | 17/193 | 193 | `python -m bench.harness --dataset clean_corpus --tool odin-rules --seed 42` |

## Recall on SecVulEval (Python/JS CVEs)

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `odin-rules` | 86% | 100% | 0.92 | 12 | 2 | `python -m bench.harness --dataset secvuleval-subset --tool odin-rules --seed 42` |

## Recall on SWE-bench Verified (bug-detection)

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `odin-rules` | 100% | 100% | 1.00 | 50 | 0 | `python -m bench.harness --dataset swebench-verified --tool odin-rules --seed 42` |

## Recall on CVE-Bench (critical CVEs, SOTA ~13%)

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `odin-rules` | 32% | 100% | 0.48 | 16 | 34 | `python -m bench.harness --dataset cvebench-crits --tool odin-rules --seed 42` |

## Methodology

- **Clean corpus**: 200+ clean snippets across Python/JS/TS/Go/Rust/Java — FP rate is the headline metric
- **SecVulEval subset**: 14 Python/JS CVE/CWE samples (language-equivalent, SecVulEval is C/C++)
- **SWE-bench Verified**: 50-sample bug-detection subset — logic errors, not just security issues
- **CVE-Bench**: 50 critical CVEs; SOTA is ~13% recall — low numbers expected and disclosed
- **Competitor notes**: CodeRabbit/Greptile/Qodo run snippet-only (no repo context) — their numbers are a floor
- **Reproducible**: every row has the exact command to regenerate it; dataset versions pinned by DATASET_VERSION
- **Honest**: we include all samples where Odin loses, including hard cases

## Reproduce These Results

```bash
cd backend
python -m bench.harness --seed 42
```

*Dataset versions: secvuleval-v1.0 · swebench-verified-v1 · cvebench-v1-crits-50 · See `bench/datasets/` for all samples*