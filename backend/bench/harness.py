"""Odin Benchmark Harness.

Reproducible head-to-head evaluation of code review tools against:
  - clean_corpus    : 200+ clean samples → measures false positive rate
  - secvuleval      : 13 real CVE/CWE samples → measures recall on known vulns
  - swebench        : 50 SWE-bench Verified bug-detection samples
  - cvebench        : 50 critical CVE samples (SOTA ~13% recall — hard)

Usage:
    python -m bench.harness                            # all datasets, all tools
    python -m bench.harness --dataset clean_corpus     # FP-rate benchmark only
    python -m bench.harness --dataset swebench         # SWE-bench subset
    python -m bench.harness --dataset cvebench         # CVE-Bench crits
    python -m bench.harness --tool odin-rules          # single tool
    python -m bench.harness --seed 42                  # reproducible shuffle
    python -m bench.harness --json                     # machine-readable JSON

Reproducibility contract:
    Every result row in the leaderboard includes the exact command to reproduce
    it, e.g.:
        python -m bench.harness --dataset secvuleval --tool odin-rules --seed 42
    Dataset versions are pinned by DATASET_VERSION constants in each loader.
"""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
import uuid
from pathlib import Path

from bench.datasets.clean_corpus import CLEAN_SAMPLES
from bench.datasets.clean_corpus_extended import EXTENDED_CLEAN_SAMPLES
from bench.datasets.cvebench import load_samples as load_cvebench
from bench.datasets.secvuleval import load_samples as load_secvuleval
from bench.datasets.swebench_verified import load_samples as load_swebench
from bench.schemas import (
    BenchmarkReport,
    DatasetMetrics,
    SampleLabel,
)
from bench.scorer import run_tool_on_dataset
from bench.tools.codeql import CodeQLRunner
from bench.tools.coderabbit import CodeRabbitRunner
from bench.tools.common import BenchSample, ToolRunner
from bench.tools.copilot_review import CopilotReviewRunner
from bench.tools.greptile import GreptileRunner
from bench.tools.odin import OdinRulesRunner
from bench.tools.qodo import QodoRunner
from bench.tools.semgrep import SemgrepRunner

REPORTS_DIR = Path(__file__).parent / "reports"


def _get_git_sha() -> str:
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=Path(__file__).parent.parent,
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
    except Exception:
        return "unknown"


def _load_clean_corpus() -> list[BenchSample]:
    all_samples = CLEAN_SAMPLES + EXTENDED_CLEAN_SAMPLES
    return [
        BenchSample(
            id=s["id"],
            language=s["language"],
            code=s["code"],
            label=SampleLabel.CLEAN,
            dataset="clean_corpus",
            notes=s.get("notes", ""),
        )
        for s in all_samples
    ]


def _build_runners(filter_tool: str | None) -> list[ToolRunner]:
    candidates: list[ToolRunner] = [
        OdinRulesRunner(),
        SemgrepRunner(),
        CodeQLRunner(),
        CodeRabbitRunner(),
        CopilotReviewRunner(),
        QodoRunner(),
        GreptileRunner(),
    ]
    available = [r for r in candidates if r.is_available()]
    if filter_tool:
        available = [r for r in available if r.name == filter_tool]
    return available


def run_benchmark(
    datasets: list[str] | None = None,
    filter_tool: str | None = None,
    seed: int | None = None,
) -> BenchmarkReport:
    datasets = datasets or ["clean_corpus", "secvuleval", "swebench", "cvebench"]
    runners = _build_runners(filter_tool)

    all_samples: list[BenchSample] = []
    if "clean_corpus" in datasets:
        all_samples.extend(_load_clean_corpus())
    if "secvuleval" in datasets:
        all_samples.extend(load_secvuleval())
    if "swebench" in datasets:
        all_samples.extend(load_swebench(seed=seed))
    if "cvebench" in datasets:
        all_samples.extend(load_cvebench(seed=seed))

    # Collect the actual dataset names used (may differ from CLI alias)
    actual_dataset_names = list({s.dataset for s in all_samples})

    all_results = []
    all_metrics = []

    for runner in runners:
        for ds_name in actual_dataset_names:
            ds_samples = [s for s in all_samples if s.dataset == ds_name]
            if not ds_samples:
                continue
            results = run_tool_on_dataset(runner, ds_samples)
            all_results.extend(results)
            metrics = DatasetMetrics.from_results(runner.name, ds_name, results)
            all_metrics.append(metrics)

    return BenchmarkReport(
        run_id=str(uuid.uuid4())[:8],
        timestamp=datetime.datetime.utcnow().isoformat(),
        commit_sha=_get_git_sha(),
        odin_version="dev",
        datasets=datasets,
        tools=[r.name for r in runners],
        metrics=all_metrics,
        sample_results=all_results,
        seed=seed,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Reporting
# ──────────────────────────────────────────────────────────────────────────────


def _print_metrics_table(metrics: list[DatasetMetrics]) -> None:
    print()
    header = f"{'Tool':<20} {'Dataset':<18} {'N':>4} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'Prec':>6} {'Recall':>7} {'F1':>6} {'FP-rate':>8} {'ms/s':>6}"
    print(header)
    print("─" * len(header))
    for m in metrics:
        print(
            f"{m.tool:<20} {m.dataset:<18} {m.n_samples:>4} {m.tp:>4} {m.fp:>4} "
            f"{m.tn:>4} {m.fn:>4} {m.precision:>6.2f} {m.recall:>7.2f} {m.f1:>6.2f} "
            f"{m.fp_rate:>8.2%} {m.avg_latency_ms:>6.0f}"
        )
    print()


def _generate_leaderboard_md(report: BenchmarkReport) -> str:
    seed_str = f" --seed {report.seed}" if report.seed is not None else ""
    reproduce_cmd = f"python -m bench.harness{seed_str}"

    lines = [
        "# Odin Benchmark Leaderboard",
        "",
        f"**Run**: `{report.run_id}` | **Commit**: `{report.commit_sha}` | **Date**: {report.timestamp[:10]}",
        "",
        "> Reproducible benchmark of AI code review tools on clean code (false positive rate) and real vulnerability samples (recall).",
        f"> Every number here can be reproduced: `{reproduce_cmd}`",
        "> We report **where Odin loses**, not just where it wins.",
        "",
        "## Key Metric: False Positive Rate on Clean Code",
        "",
        "A tool with a high FP rate generates noise that erodes developer trust.",
        "All 200+ samples in the clean corpus are idiomatic, production-quality code with **zero real issues**.",
        "",
    ]

    # FP rate table (clean corpus only)
    clean_metrics = [m for m in report.metrics if m.dataset == "clean_corpus"]
    if clean_metrics:
        lines += [
            "| Tool | FP Rate | False Positives | Samples | Reproduce |",
            "|---|---|---|---|---|",
        ]
        for m in sorted(clean_metrics, key=lambda x: x.fp_rate):
            fp_pct = f"{m.fp_rate:.1%}"
            cmd = f"`python -m bench.harness --dataset clean_corpus --tool {m.tool}{seed_str}`"
            lines.append(f"| `{m.tool}` | {fp_pct} | {m.fp}/{m.n_clean} | {m.n_samples} | {cmd} |")
        lines.append("")

    # Recall table per dataset
    dataset_order = ["secvuleval-subset", "swebench-verified", "cvebench-crits"]
    dataset_labels = {
        "secvuleval-subset": "SecVulEval (Python/JS CVEs)",
        "swebench-verified": "SWE-bench Verified (bug-detection)",
        "cvebench-crits":    "CVE-Bench (critical CVEs, SOTA ~13%)",
    }

    for ds in dataset_order:
        ds_metrics = [m for m in report.metrics if m.dataset == ds]
        if not ds_metrics:
            continue
        label = dataset_labels.get(ds, ds)
        lines += [
            f"## Recall on {label}",
            "",
            "| Tool | Recall | Precision | F1 | TP | FN | Reproduce |",
            "|---|---|---|---|---|---|---|",
        ]
        for m in sorted(ds_metrics, key=lambda x: -x.recall):
            cmd = f"`python -m bench.harness --dataset {ds} --tool {m.tool}{seed_str}`"
            lines.append(
                f"| `{m.tool}` | {m.recall:.0%} | {m.precision:.0%} | {m.f1:.2f} | {m.tp} | {m.fn} | {cmd} |"
            )
        lines.append("")

    lines += [
        "## Methodology",
        "",
        "- **Clean corpus**: 200+ clean snippets across Python/JS/TS/Go/Rust/Java — FP rate is the headline metric",
        f"- **SecVulEval subset**: {sum(m.n_vuln for m in report.metrics if m.dataset == 'secvuleval-subset')} Python/JS CVE/CWE samples (language-equivalent, SecVulEval is C/C++)",
        "- **SWE-bench Verified**: 50-sample bug-detection subset — logic errors, not just security issues",
        "- **CVE-Bench**: 50 critical CVEs; SOTA is ~13% recall — low numbers expected and disclosed",
        "- **Competitor notes**: CodeRabbit/Greptile/Qodo run snippet-only (no repo context) — their numbers are a floor",
        "- **Reproducible**: every row has the exact command to regenerate it; dataset versions pinned by DATASET_VERSION",
        "- **Honest**: we include all samples where Odin loses, including hard cases",
        "",
        "## Reproduce These Results",
        "",
        "```bash",
        "cd backend",
        f"{reproduce_cmd}",
        "```",
        "",
        "*Dataset versions: secvuleval-v1.0 · swebench-verified-v1 · cvebench-v1-crits-50 · See `bench/datasets/` for all samples*",
    ]
    return "\n".join(lines)


def _save_report(report: BenchmarkReport) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    results_dir = REPORTS_DIR / "results"
    results_dir.mkdir(exist_ok=True)

    # Save full JSON
    json_path = results_dir / f"{report.timestamp[:10]}-{report.run_id}.json"
    report_dict = {
        "run_id": report.run_id,
        "timestamp": report.timestamp,
        "commit_sha": report.commit_sha,
        "odin_version": report.odin_version,
        "seed": report.seed,
        "datasets": report.datasets,
        "tools": report.tools,
        "metrics": [
            {
                "tool": m.tool,
                "dataset": m.dataset,
                "n_samples": m.n_samples,
                "n_vuln": m.n_vuln,
                "n_clean": m.n_clean,
                "tp": m.tp,
                "fp": m.fp,
                "tn": m.tn,
                "fn": m.fn,
                "precision": m.precision,
                "recall": m.recall,
                "f1": m.f1,
                "fp_rate": m.fp_rate,
                "avg_latency_ms": m.avg_latency_ms,
            }
            for m in report.metrics
        ],
    }
    json_path.write_text(json.dumps(report_dict, indent=2))

    # Save leaderboard markdown
    md_path = REPORTS_DIR / "leaderboard.md"
    md_path.write_text(_generate_leaderboard_md(report))

    return json_path


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────


_ALL_DATASETS = ["clean_corpus", "secvuleval", "swebench", "cvebench"]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Odin benchmark harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m bench.harness\n"
            "  python -m bench.harness --dataset secvuleval --tool odin-rules --seed 42\n"
            "  python -m bench.harness --dataset cvebench --json\n"
        ),
    )
    p.add_argument(
        "--dataset",
        choices=[*_ALL_DATASETS, "all"],
        default="all",
        help="Which dataset(s) to run (default: all)",
    )
    p.add_argument("--tool", help="Run only this tool (e.g. odin-rules, semgrep, greptile)")
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="RNG seed for reproducible dataset shuffling (e.g. --seed 42)",
    )
    p.add_argument("--json", action="store_true", help="Print JSON report to stdout")
    p.add_argument("--no-save", action="store_true", help="Don't save report to disk")
    args = p.parse_args(argv)

    datasets = _ALL_DATASETS if args.dataset == "all" else [args.dataset]

    print("\nOdin Benchmark Harness")
    print(f"   Datasets : {', '.join(datasets)}")
    if args.tool:
        print(f"   Tool     : {args.tool}")
    if args.seed is not None:
        print(f"   Seed     : {args.seed}")
    print()

    report = run_benchmark(datasets=datasets, filter_tool=args.tool, seed=args.seed)

    if not report.metrics:
        print("No tools available. Install semgrep or run from within the odin backend.")
        return 1

    if args.json:
        print(
            json.dumps(
                {
                    "run_id": report.run_id,
                    "commit_sha": report.commit_sha,
                    "metrics": [
                        {
                            "tool": m.tool,
                            "dataset": m.dataset,
                            "precision": m.precision,
                            "recall": m.recall,
                            "f1": m.f1,
                            "fp_rate": m.fp_rate,
                            "tp": m.tp,
                            "fp": m.fp,
                            "tn": m.tn,
                            "fn": m.fn,
                        }
                        for m in report.metrics
                    ],
                },
                indent=2,
            )
        )
    else:
        _print_metrics_table(report.metrics)

    if not args.no_save:
        json_path = _save_report(report)
        print(f"Results saved → {json_path}")
        print(f"Leaderboard  → {REPORTS_DIR / 'leaderboard.md'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
