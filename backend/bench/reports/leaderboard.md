# Odin Benchmark Leaderboard

**Commit**: `f9472d2` | **Last full rerun**: 2026-04-22 (line-localized matching)

> Reproducible benchmark of AI code review tools on clean code (false-positive rate)
> and real vulnerability samples (recall). Every number here can be reproduced with
> `python -m bench.harness --seed 42`. We report **where Odin loses**, not just where it wins.

## What changed in this run — and why the old numbers were wrong

The previous version of this leaderboard used **unconditional sample-level matching**:
*any* finding, anywhere in a sample, on *any* line, counted as catching the bug. Under
that rule Odin's deterministic engine reported **100% recall on SWE-bench**, **86% on
SecVulEval**, and **32% on CVE-Bench (vs ~13% SOTA)**. Those numbers were not honest, for
two compounding reasons:

1. **Any finding counted.** A tool that flagged a "magic number" or "missing docstring"
   on a snippet whose real bug was an off-by-one still got full credit. Recall measured
   rule *breadth*, not vulnerability *detection*.
2. **Ground-truth markers leaked into the input.** Each vulnerable sample embeds a
   `# BUG:` / `// VULNERABLE:` comment on the buggy line. Odin's CL001 rule flags
   `TODO`/`FIXME`/`BUG` comments — so it "detected" the marker *we* planted. The 100% on
   SWE-bench was literally the tool grepping for a comment the benchmark inserted.

This run fixes both, in `bench/scorer.py`:

- **Line-localized matching** — a finding counts only if its reported line range overlaps
  the ground-truth marker line (window `[M, M+1]`). Clean samples carry no markers, so the
  false-positive definition is unchanged.
- **Marker stripping (contamination control)** — the `# BUG:` / `// VULNERABLE:` text is
  removed from every sample before the tool sees it (line numbers preserved), so no rule
  can score by matching the annotation.

The numbers below are lower and honest. The FP-rate story — Odin's genuine, rare
strength — is untouched, because it never depended on the matching criterion.

## What each dataset actually measures

| Dataset | What it tests | Fair to compare across tools? |
|---|---|---|
| `clean_corpus` (193 samples) | **False-positive rate** on idiomatic, production-quality code with zero real issues. | Yes — a lower FP rate is strictly better. |
| `secvuleval-subset` (14 samples) | **Security-bug recall** on Python/JS equivalents of CVEs/CWEs. | Yes, for security tools. |
| `cvebench-crits` (50 samples) | **Security-bug recall** on critical CVEs. Reported SOTA is ~13% — very hard. | Yes, for security tools. |
| `swebench-verified` (50 samples) | **General-bug recall** on logic errors — **not security**. Deterministic SAST is not expected to shine here. | ⚠ Apples-to-oranges vs SAST tools. |

## False Positive Rate on Clean Code (193 samples)

The headline metric — and the one nobody else publishes. A high FP rate is noise that
erodes developer trust. Unchanged by this run (clean samples have no markers).

| Tool | FP Rate | False Positives | Samples | Reproduce |
|---|---|---|---|---|
| `odin-dataflow` | **0.0%** | 0/193 | 193 | `python -m bench.harness --dataset clean_corpus --tool odin-dataflow --seed 42` |
| `semgrep` | 2.1% | 4/193 | 193 | `python -m bench.harness --dataset clean_corpus --tool semgrep --seed 42` |
| `odin-rules` | 8.8% | 17/193 | 193 | `python -m bench.harness --dataset clean_corpus --tool odin-rules --seed 42` |

**Scope of the 0.0% dataflow number:** Odin's taint tracker only fires on a full
source → sink path through ~8 sink categories (`code_exec`, `shell_exec`, `sql_query`,
`dom_write`, `path_traversal`, `ssrf_fetch`, `template_render`, `deserialized`). A 0.0%
FP rate on that narrow surface is a smaller-haystack claim than Semgrep's 2.1% across its
whole ruleset. The `odin-rules` 8.8% is the fairer whole-ruleset head-to-head.

## Recall on SecVulEval (14 Python/JS CVEs)

Odin's deterministic security rules genuinely lead here — they encode real sink patterns
(SQLi, `eval`, deserialization, path traversal), so they fire *on the vulnerable line*.

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `odin-rules` | **64%** | 100% | 0.78 | 9 | 5 | `python -m bench.harness --dataset secvuleval --tool odin-rules --seed 42` |
| `semgrep` | 29% | 100% | 0.44 | 4 | 10 | `python -m bench.harness --dataset secvuleval --tool semgrep --seed 42` |
| `odin-dataflow` | 7% | 100% | 0.13 | 1 | 13 | `python -m bench.harness --dataset secvuleval --tool odin-dataflow --seed 42` |

## Recall on CVE-Bench critical CVEs (SOTA ~13%)

Brutally hard. Under honest matching Odin and Semgrep tie — and both sit below the ~13%
SOTA. We report it anyway.

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `odin-rules` | 8% | 100% | 0.15 | 4 | 46 | `python -m bench.harness --dataset cvebench --tool odin-rules --seed 42` |
| `semgrep` | 8% | 100% | 0.15 | 4 | 46 | `python -m bench.harness --dataset cvebench --tool semgrep --seed 42` |
| `odin-dataflow` | 0% | — | 0.00 | 0 | 50 | `python -m bench.harness --dataset cvebench --tool odin-dataflow --seed 42` |

## Recall on SWE-bench Verified (⚠ logic bugs, not CVEs)

> **Read this first.** SWE-bench Verified measures general bug-finding — off-by-ones,
> missing null checks, wrong return values. It is **not** security. Deterministic SAST
> tools are not built to catch these, and the honest numbers show it. The old "100%" here
> was pure marker contamination (see top of file); the real number is near-zero, as
> expected for pattern rules on logic bugs.

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `odin-rules` | 4% | 100% | 0.08 | 2 | 48 | `python -m bench.harness --dataset swebench --tool odin-rules --seed 42` |
| `odin-dataflow` | 2% | 100% | 0.04 | 1 | 49 | `python -m bench.harness --dataset swebench --tool odin-dataflow --seed 42` |
| `semgrep` | 0% | — | 0.00 | 0 | 50 | `python -m bench.harness --dataset swebench --tool semgrep --seed 42` |

## Methodology

### Datasets

- **Clean corpus**: 193 clean snippets across Python/JS/TS/Go/Rust/Java — FP rate is the headline metric.
- **SecVulEval subset**: 14 Python/JS CVE/CWE samples (SecVulEval itself is C/C++; these are language-equivalents).
- **CVE-Bench crits**: 50 critical CVEs; SOTA is ~13% recall — low numbers expected and disclosed.
- **SWE-bench Verified**: 50-sample general-bug subset. Logic errors, not security.
- **Competitor notes**: CodeRabbit / Greptile / Qodo / CodeQL / Copilot runners exist in the harness but require API access. Independent third-party benchmarks (Greptile ~82% bug-catch, Qodo ~60% F1, CodeRabbit ~44%) are cited in the blog rather than self-run.
- **Reproducible**: every row has the exact command; dataset versions pinned by `DATASET_VERSION`.

### Matching criterion (how TP / FP / FN / TN are computed)

Implemented in `bench/scorer.py`:

1. Each tool runs against a sample (with ground-truth markers **stripped**) and produces
   zero or more `ToolFinding` objects (`rule_id`, `line_start`, `line_end`, `category`, `confidence`).
2. Findings below `min_confidence` (default 0.0) are discarded.
3. Each remaining finding passes through `matches()`, which returns true only if the
   finding's `[line_start, line_end]` overlaps a ground-truth marker window `[M, M+1]`
   derived from the original (pre-strip) sample. A finding with no line range, or on an
   unrelated line, does **not** match. Samples with no markers (all clean samples) fall
   back to sample-level so the FP definition is unchanged.
4. A vulnerable sample with ≥1 matching finding is a **TP**, else **FN**. A clean sample
   with ≥1 finding is a **FP**, else **TN**.
5. `Precision = TP/(TP+FP)`, `Recall = TP/(TP+FN)`, `F1 = 2PR/(P+R)`, `FP rate = FP/(FP+TN)`.

### Contamination control

Ground-truth `# BUG:` / `// VULNERABLE:` markers are removed from each sample before the
tool runs (`strip_markers` in `bench/scorer.py`), with line numbers preserved so
localization still scores correctly. Without this, any rule that flags `TODO`/`FIXME`/`BUG`
comments trivially "detects" the planted marker — which is exactly what produced the old,
retracted 100% SWE-bench figure.

### Caveats and limitations

- **Line-localized ≠ semantically correct.** A finding on the right line for the wrong
  reason still counts as a TP. This is a much tighter bar than the old any-finding rule,
  but it does not verify the tool understood *why* the line is buggy.
- **Not comparable to the official SWE-bench leaderboard**, which measures patch
  generation, not bug detection.
- **Small datasets.** 14/50/50 samples — treat single-point differences as noise; the
  FP-rate corpus (193) is the statistically meaningful one.

## Reproduce These Results

```bash
cd backend
python -m bench.harness --seed 42
```

*Dataset versions: secvuleval-v1.0 · swebench-verified-v1 · cvebench-v1-crits-50 · See `bench/datasets/` for all samples.*
