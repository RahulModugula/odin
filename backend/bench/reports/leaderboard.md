# Odin Benchmark Leaderboard

**Run**: `f88a5c57` | **Commit**: `f9472d2` | **Last full rerun**: 2026-04-19

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
| `odin-dataflow` | 0.0% | 0/193 | 193 | `python -m bench.harness --dataset clean_corpus --tool odin-dataflow --seed 42` |
| `odin-rules` | 8.8% | 17/193 | 193 | `python -m bench.harness --dataset clean_corpus --tool odin-rules --seed 42` |

**Scope of the 0.0% dataflow number quoted in the README:** Odin's dataflow tracker only
fires on candidates that have a full source → sink path through ~8 sink categories
(`code_exec`, `shell_exec`, `sql_query`, `dom_write`, `path_traversal`, `ssrf_fetch`,
`template_render`, `deserialized`). A 0.0% FP rate on that narrow surface is not the same
shape of claim as Semgrep's 2.1% across its entire ruleset — it's a much smaller haystack.
The `odin-rules` 8.8% FP rate on the same clean corpus is the fairer head-to-head number.

## Recall on SecVulEval (14 Python/JS CVEs)

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `semgrep` | 50% | 100% | 0.67 | 7 | 7 | `python -m bench.harness --dataset secvuleval-subset --tool semgrep --seed 42` |
| `odin-rules` | 86% | 100% | 0.92 | 12 | 2 | `python -m bench.harness --dataset secvuleval-subset --tool odin-rules --seed 42` |
| `odin-dataflow` | 21% | 100% | 0.35 | 3 | 11 | `python -m bench.harness --dataset secvuleval-subset --tool odin-dataflow --seed 42` |

## Recall on CVE-Bench critical CVEs (SOTA ~13%)

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `semgrep` | 26% | 100% | 0.41 | 13 | 37 | `python -m bench.harness --dataset cvebench-crits --tool semgrep --seed 42` |
| `odin-rules` | 32% | 100% | 0.48 | 16 | 34 | `python -m bench.harness --dataset cvebench-crits --tool odin-rules --seed 42` |
| `odin-dataflow` | 6% | 100% | 0.11 | 3 | 47 | `python -m bench.harness --dataset cvebench-crits --tool odin-dataflow --seed 42` |

## Recall on SWE-bench Verified (⚠ logic bugs, not CVEs)

> **Read this first.** SWE-bench Verified measures general bug-finding — feature bugs,
> off-by-ones, missing null checks, incorrect return values. It is **not** a security
> benchmark. High recall here means "this tool can flag arbitrary bugs in real repos,"
> not "this tool catches security vulnerabilities." Do not compare these numbers
> directly against the SecVulEval / CVE-Bench rows above.

| Tool | Recall | Precision | F1 | TP | FN | Reproduce |
|---|---|---|---|---|---|---|
| `semgrep` | 2% | 100% | 0.04 | 1 | 49 | `python -m bench.harness --dataset swebench-verified --tool semgrep --seed 42` |
| `odin-rules` | 100% | 100% | 1.00 | 50 | 0 | `python -m bench.harness --dataset swebench-verified --tool odin-rules --seed 42` |
| `odin-dataflow` | 2% | 100% | 0.04 | 1 | 49 | `python -m bench.harness --dataset swebench-verified --tool odin-dataflow --seed 42` |

## Methodology

### Datasets

- **Clean corpus**: 200+ clean snippets across Python/JS/TS/Go/Rust/Java — FP rate is the headline metric.
- **SecVulEval subset**: 14 Python/JS CVE/CWE samples (language-equivalent; SecVulEval itself is C/C++).
- **CVE-Bench crits**: 50 critical CVEs; SOTA is ~13% recall — low numbers are expected and disclosed.
- **SWE-bench Verified**: 50-sample general-bug-detection subset. Logic errors, not security. Do not compare recall here to CVE recall.
- **Competitor notes**: CodeRabbit / Greptile / Qodo / CodeQL / Copilot Review runners exist in the harness but require API access. Until those rows are populated, the head-to-head is against Semgrep only.
- **Reproducible**: every row has the exact command to regenerate it; dataset versions pinned by `DATASET_VERSION`.
- **Honest**: we include all samples where Odin loses, including hard cases.

### Matching criterion (how TP / FP / FN / TN are computed)

The harness uses **sample-level matching** implemented in `bench/scorer.py`:

1. Each tool is run against a sample and produces zero or more `ToolFinding`
   objects (each with `rule_id`, `title`, `severity`, `line_start`, `line_end`,
   `category`, `confidence`).

2. Findings below the `min_confidence` threshold (default 0.0 — all findings
   pass) are discarded.

3. The remaining findings are passed through a `matches()` check.  Currently
   this check is **unconditional** — every finding is considered a match
   (see rationale below).

4. If **at least one** matching finding exists, the sample is "flagged":

   | Ground truth | Flagged? | Result |
   |---|---|---|
   | `vulnerable` | Yes | **True positive (TP)** |
   | `vulnerable` | No | **False negative (FN)** |
   | `clean` | Yes | **False positive (FP)** |
   | `clean` | No | **True negative (TN)** |

5. Aggregate metrics are computed as:
   - **Precision** = TP / (TP + FP)
   - **Recall** = TP / (TP + FN)
   - **F1** = 2 × Precision × Recall / (Precision + Recall)
   - **FP rate** = FP / (FP + TN)

**What counts as a true positive:** the tool produced *any* finding (of any
category, at any line range) on a vulnerable sample.  No line-range overlap
with the ground-truth buggy lines is required.  No category or rule
correlation is required.

**What counts as a false positive:** the tool produced *any* finding on a
clean sample.

**What counts as a false negative:** the tool produced *no* findings on a
vulnerable sample.

**What counts as a true negative:** the tool produced *no* findings on a
clean sample.

### Why sample-level matching (no line-range overlap)

All datasets except the clean corpus consist of **self-contained code
snippets** — typically 5–15 lines — where the entire snippet *is* the buggy
code.  There is no surrounding file context, no unrelated functions, and no
"correct" code for a tool to accidentally flag.  Any finding the tool
produces is necessarily within the bug's code context.

For this reason, requiring line-range overlap with the ground-truth buggy
lines would be misleadingly strict: a finding on line 3 of a 5-line snippet
that correctly identifies a bug pattern but happens to be one line off from
the `# BUG:` comment should still count.

### Caveats and limitations

- **SWE-bench 100% recall for odin-rules**: The 50/50 (100%) recall reflects
  that Odin's deterministic rule engine fires *at least one* finding on every
  sample.  This does **not** mean Odin correctly identified the specific bug
  in every case — it means it flagged *something* (which may be a tangential
  quality or style issue rather than the ground-truth logic error).  The
  number measures breadth of rule coverage, not precision of bug localization.

- **Category mismatch is possible**: A tool could flag "missing docstring" on
  a snippet whose ground-truth bug is an off-by-one error, and it would still
  count as a TP.  This is an inherent limitation of sample-level matching on
  small snippets and should be considered when interpreting recall numbers.

- **Not comparable to SWE-bench leaderboard**: The official SWE-bench
  leaderboard measures *patch generation* (can an agent produce the correct
  fix?).  This benchmark measures *bug detection* (can a tool flag the
  defective code?).  These are fundamentally different tasks.

### Reimplementation guide

To reimplement the scoring from scratch:

```python
def classify(sample_label, findings, min_confidence=0.0):
    """Return (tp, fp, tn, fn) for one sample."""
    relevant = [f for f in findings if f.confidence >= min_confidence]
    flagged = len(relevant) > 0  # sample-level: any finding = flagged

    if sample_label == "vulnerable":
        return (flagged, False, False, not flagged)
    else:  # "clean"
        return (False, flagged, not flagged, False)
```

The `matches()` function in `bench/scorer.py` serves as the extension point
for tightening the criterion (e.g., requiring line-range overlap or category
correlation) without modifying the rest of the pipeline.

## Reproduce These Results

```bash
cd backend
python -m bench.harness --seed 42
```

*Dataset versions: secvuleval-v1.0 · swebench-verified-v1 · cvebench-v1-crits-50 · See `bench/datasets/` for all samples.*
