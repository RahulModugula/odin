"""Evaluation benchmark runner for the Odin review pipeline.

Supports two modes:
  --rules-only   Instant deterministic-only benchmark (no LLM needed)
  --full         Full AI + rules benchmark (requires LLM config)

New expected.json format supports min_count for flexible matching:
  {"expected_findings": [{"category": "security", "severity": "critical",
                           "title_pattern": "SQL", "min_count": 1}]}
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent / "samples"
EXPECTED_DIR = Path(__file__).parent / "expected"
RESULTS_DIR  = Path(__file__).parent / "results"

EXTENSION_TO_LANGUAGE = {
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "typescript",
    ".tsx":  "typescript",
    ".go":   "go",
    ".rs":   "rust",
    ".java": "java",
}


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _load_expected(name: str) -> list[dict] | None:
    path = EXPECTED_DIR / f"{name}.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    # Support both old format (list) and new format (dict with expected_findings)
    if isinstance(data, list):
        return data
    return data.get("expected_findings", [])


def _match_findings(expected: list[dict], actual_findings: list) -> int:
    """Count how many expected patterns are satisfied."""
    satisfied = 0
    for exp in expected:
        pattern     = exp.get("title_pattern", "")
        category    = exp.get("category", "")
        severity    = exp.get("severity", "")
        min_count   = exp.get("min_count", 1)

        matched = 0
        for actual in actual_findings:
            actual_cat   = actual.get("category", "") if isinstance(actual, dict) else str(getattr(actual, "category", ""))
            actual_sev   = actual.get("severity", "") if isinstance(actual, dict) else str(getattr(actual, "severity", ""))
            actual_title = actual.get("title",    "") if isinstance(actual, dict) else str(getattr(actual, "title",    ""))

            # Flexible matching: category and severity are "contains" checks
            cat_ok = not category or str(actual_cat).lower() == category.lower()
            sev_ok = not severity or str(actual_sev).lower() == severity.lower()
            ttl_ok = not pattern  or re.search(pattern, actual_title, re.IGNORECASE)

            if cat_ok and sev_ok and ttl_ok:
                matched += 1

        if matched >= min_count:
            satisfied += 1

    return satisfied


def _run_rules_sync(code: str, language: str) -> list:
    from app.models.enums import Language
    from app.rules.engine import rule_engine
    from app.rules.registry import register_all

    if not rule_engine.is_initialized():
        register_all()
    return rule_engine.check_all(code, Language(language))


async def _run_full(code: str, language: str) -> tuple[list, int]:
    from app.agents.graph import review_graph

    state = {
        "code":          code,
        "language":      language,
        "ast_summary":   "",
        "metrics":       None,
        "findings":      [],
        "agent_outputs": [],
        "overall_score": 100,
        "summary":       "",
        "codebase_context": "",
        "file_path":     None,
    }
    result = await review_graph.ainvoke(state)
    return result.get("findings", []), result.get("overall_score", 0)


# --------------------------------------------------------------------------- #
# Main benchmark runner                                                        #
# --------------------------------------------------------------------------- #

async def run_benchmark(rules_only: bool = False, filter_lang: str | None = None) -> list[dict]:
    samples = sorted(SAMPLES_DIR.rglob("*.*"))
    samples = [s for s in samples if s.suffix in EXTENSION_TO_LANGUAGE]

    if filter_lang:
        samples = [s for s in samples if EXTENSION_TO_LANGUAGE.get(s.suffix) == filter_lang]

    results = []

    for sample_path in samples:
        sample_name = sample_path.stem
        lang = EXTENSION_TO_LANGUAGE[sample_path.suffix]
        expected = _load_expected(sample_name)

        if expected is None:
            print(f"  SKIP  {sample_name:<25} (no expected file)")
            continue

        code = sample_path.read_text(encoding="utf-8", errors="ignore")
        print(f"  RUN   {sample_name:<25} [{lang}] ...", end="", flush=True)

        start = time.perf_counter()
        try:
            if rules_only:
                findings = _run_rules_sync(code, lang)
                score = 100
            else:
                findings, score = await _run_full(code, lang)
            elapsed = time.perf_counter() - start

        except Exception as exc:
            elapsed = time.perf_counter() - start
            print(f" ERROR: {exc}")
            results.append({"sample": sample_name, "language": lang, "error": str(exc)})
            continue

        satisfied = _match_findings(expected, findings)
        actual_count = len(findings)
        exp_count    = len(expected)

        precision = satisfied / actual_count if actual_count > 0 else (1.0 if exp_count == 0 else 0.0)
        recall    = satisfied / exp_count    if exp_count    > 0 else 1.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        status = "✓" if recall >= 0.7 else "✗"
        print(f" {status}  recall={recall:.0%}  findings={actual_count}  {elapsed:.1f}s")

        results.append({
            "sample":         sample_name,
            "language":       lang,
            "expected_count": exp_count,
            "actual_count":   actual_count,
            "satisfied":      satisfied,
            "precision":      round(precision, 3),
            "recall":         round(recall, 3),
            "f1":             round(f1, 3),
            "score":          score,
            "time_s":         round(elapsed, 2),
            "mode":           "rules" if rules_only else "full",
        })

    return results


def _print_table(results: list[dict]) -> None:
    sep = "=" * 100
    print(f"\n{sep}")
    print(f"{'Sample':<25} {'Lang':<6} {'Exp':<5} {'Found':<7} {'Sat':<5} {'Prec':<7} {'Recall':<8} {'F1':<7} {'Score':<6} {'Time'}")
    print("-" * 100)

    prec_vals, rec_vals, f1_vals = [], [], []
    pass_count = 0

    for r in results:
        if "error" in r:
            print(f"{r['sample']:<25} {r['language']:<6} ERROR: {r['error']}")
            continue
        status = "✓" if r["recall"] >= 0.7 else "✗"
        print(
            f"{status} {r['sample']:<23} {r['language']:<6} "
            f"{r['expected_count']:<5} {r['actual_count']:<7} {r['satisfied']:<5} "
            f"{r['precision']:<7.2f} {r['recall']:<8.2f} {r['f1']:<7.2f} "
            f"{r['score']:<6} {r['time_s']:.1f}s"
        )
        prec_vals.append(r["precision"])
        rec_vals.append(r["recall"])
        f1_vals.append(r["f1"])
        if r["recall"] >= 0.7:
            pass_count += 1

    if f1_vals:
        print("-" * 100)
        print(
            f"  {'AVERAGE':<23} {'':6} {'':5} {'':7} {'':5} "
            f"{sum(prec_vals)/len(prec_vals):<7.2f} "
            f"{sum(rec_vals)/len(rec_vals):<8.2f} "
            f"{sum(f1_vals)/len(f1_vals):<7.2f}"
        )
        print(f"\nPassed: {pass_count}/{len(f1_vals)} samples (recall ≥ 70%)")
    print(sep)


async def main_async(args: argparse.Namespace) -> None:
    print("\n🔍 Odin Eval Suite")
    print(f"   Mode:     {'rules-only (instant)' if args.rules_only else 'full (AI + rules)'}")
    if args.lang:
        print(f"   Language: {args.lang}")
    print()

    results = await run_benchmark(rules_only=args.rules_only, filter_lang=args.lang)
    _print_table(results)

    # Save results
    RESULTS_DIR.mkdir(exist_ok=True)
    out_file = RESULTS_DIR / ("latest_rules.json" if args.rules_only else "latest_full.json")
    out_file.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved → {out_file}")

    # Exit non-zero if avg recall < 0.5
    f1_vals = [r["f1"] for r in results if "error" not in r]
    if f1_vals and sum(f1_vals) / len(f1_vals) < 0.5:
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Odin benchmark runner")
    parser.add_argument("--rules-only", action="store_true", help="Deterministic rules only (fast, no LLM)")
    parser.add_argument("--lang", help="Filter to a single language (e.g. python, typescript)")
    args = parser.parse_args()
    asyncio.run(main_async(args))
