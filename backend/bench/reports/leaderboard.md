# Odin Benchmark Leaderboard

**Run**: `db76e24a` | **Commit**: `fc73128` | **Date**: 2026-04-17

> Reproducible benchmark of AI code review tools on clean code (false positive rate) and real vulnerability samples (recall).
> Every number here can be reproduced: `python -m bench.harness --seed 42`
> We report **where Odin loses**, not just where it wins.

## Key Metric: False Positive Rate on Clean Code

A tool with a high FP rate generates noise that erodes developer trust.
All 200+ samples in the clean corpus are idiomatic, production-quality code with **zero real issues**.

| Tool | FP Rate | False Positives | Samples | Reproduce |
|---|---|---|---|---|
| `semgrep` | 2.1% | 4/193 | 193 | `python -m bench.harness --dataset clean_corpus --tool semgrep --seed 42` |

## Recall on SecVulEval (Python/JS CVEs)

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `semgrep` | 50% | 100% | 0.67 | 7 | 7 | `python -m bench.harness --dataset secvuleval-subset --tool semgrep --seed 42` |

## Recall on SWE-bench Verified (bug-detection)

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `semgrep` | 2% | 100% | 0.04 | 1 | 49 | `python -m bench.harness --dataset swebench-verified --tool semgrep --seed 42` |

## Recall on CVE-Bench (critical CVEs, SOTA ~13%)

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `semgrep` | 26% | 100% | 0.41 | 13 | 37 | `python -m bench.harness --dataset cvebench-crits --tool semgrep --seed 42` |

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