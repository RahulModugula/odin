"""Evaluation benchmark runner for the Odin review pipeline."""

import asyncio
import json
import re
import sys
import time
from pathlib import Path

from app.agents.graph import review_graph
from app.models.enums import Language

SAMPLES_DIR = Path(__file__).parent / "samples"
EXPECTED_DIR = Path(__file__).parent / "expected"


async def run_benchmark():
    """Run all benchmark samples and calculate precision/recall."""
    samples = list(SAMPLES_DIR.glob("**/*.*"))
    samples = [s for s in samples if s.suffix in (".py", ".js")]

    results = []

    for sample_path in sorted(samples):
        sample_name = sample_path.stem
        expected_path = EXPECTED_DIR / f"{sample_name}.json"

        if not expected_path.exists():
            print(f"  SKIP {sample_name} (no expected file)")
            continue

        code = sample_path.read_text()
        expected = json.loads(expected_path.read_text())

        lang = "javascript" if sample_path.suffix == ".js" else "python"

        print(f"  Running: {sample_name} ({lang})...")
        start = time.perf_counter()

        try:
            state = {
                "code": code,
                "language": lang,
                "ast_summary": "",
                "metrics": None,
                "findings": [],
                "agent_outputs": [],
                "overall_score": 100,
                "summary": "",
            }
            result = await review_graph.ainvoke(state)
            elapsed = time.perf_counter() - start

            actual_findings = result.get("findings", [])

            # Calculate matches
            true_positives = 0
            for exp in expected:
                for actual in actual_findings:
                    if (actual.category == exp["category"] and
                        actual.severity == exp["severity"] and
                        re.search(exp["title_pattern"], actual.title)):
                        true_positives += 1
                        break

            precision = true_positives / len(actual_findings) if actual_findings else (1.0 if not expected else 0.0)
            recall = true_positives / len(expected) if expected else 1.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

            results.append({
                "sample": sample_name,
                "language": lang,
                "expected_count": len(expected),
                "actual_count": len(actual_findings),
                "true_positives": true_positives,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "score": result.get("overall_score", 0),
                "time_s": round(elapsed, 2),
            })

        except Exception as e:
            print(f"    ERROR: {e}")
            results.append({
                "sample": sample_name,
                "language": lang,
                "error": str(e),
            })

    # Print results table
    print("\n" + "=" * 90)
    print(f"{'Sample':<20} {'Lang':<6} {'Expected':<9} {'Found':<7} {'TP':<5} {'Prec':<7} {'Recall':<8} {'F1':<7} {'Score':<6} {'Time':<6}")
    print("-" * 90)

    total_precision = []
    total_recall = []
    total_f1 = []

    for r in results:
        if "error" in r:
            print(f"{r['sample']:<20} {r['language']:<6} ERROR: {r['error']}")
            continue
        print(f"{r['sample']:<20} {r['language']:<6} {r['expected_count']:<9} {r['actual_count']:<7} {r['true_positives']:<5} {r['precision']:<7.2f} {r['recall']:<8.2f} {r['f1']:<7.2f} {r['score']:<6} {r['time_s']:<6.1f}s")
        total_precision.append(r['precision'])
        total_recall.append(r['recall'])
        total_f1.append(r['f1'])

    if total_f1:
        print("-" * 90)
        avg_p = sum(total_precision) / len(total_precision)
        avg_r = sum(total_recall) / len(total_recall)
        avg_f1 = sum(total_f1) / len(total_f1)
        print(f"{'AVERAGE':<20} {'':6} {'':9} {'':7} {'':5} {avg_p:<7.2f} {avg_r:<8.2f} {avg_f1:<7.2f}")
    print("=" * 90)

    # Save results
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "latest.json"
    output_path.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    asyncio.run(run_benchmark())
