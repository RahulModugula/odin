# Odin Benchmark Leaderboard

**Run**: `3cd0fa08` | **Commit**: `0c744a7` | **Date**: 2026-04-10

> Reproducible benchmark of AI code review tools on clean code (false positive rate) and real CVE samples (recall).
> Every number here can be reproduced: `python -m bench.harness`
> We report **where Odin loses**, not just where it wins.

## Key Metric: False Positive Rate on Clean Code

A tool with a high FP rate generates noise that erodes developer trust.
All 60 samples in the clean corpus are idiomatic, production-quality code with **zero real issues**.

| Tool | FP Rate | False Positives | Samples |
|---|---|---|---|
| `odin-rules` | 0.0% | 0/60 | 60 |

## Recall on Known Vulnerabilities

| Tool | Dataset | Recall | Precision | F1 | TP | FN |
|---|---|---|---|---|---|---|
| `odin-rules` | secvuleval-subset | 86% | 100% | 0.92 | 12 | 2 |

## Methodology

- **Clean corpus**: 1 tool(s) × 60 clean snippets across Python/JS/TS/Go/Rust/Java
- **Vulnerability corpus**: 14 manually-verified CVE/CWE samples
- **Reproducible**: pin dataset version, run `python -m bench.harness`, compare JSON in `bench/reports/`
- **Honest**: we include samples where Odin loses

## Reproduce These Results

```bash
cd backend
python -m bench.harness
```

*Dataset version: `dev` · See `bench/datasets/` for all samples*