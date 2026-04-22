"""Generate the Odin benchmark hero chart (FP rate + security recall).

Numbers are the honest, line-localized-matching results from
`python -m bench.harness --seed 42` (see leaderboard.md). Regenerate with:

    python bench/reports/make_hero_chart.py
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.font_manager as fm  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

# --- palette (validated categorical slots + neutral competitor) ---
ODIN_DATAFLOW = "#2a78d6"  # slot 1 blue
ODIN_RULES = "#1baf7a"  # slot 2 aqua
SEMGREP = "#8a8a86"  # neutral gray — the reference baseline
INK = "#0b0b0b"
MUTED = "#6b6a67"
SURFACE = "#ffffff"
GRID = "#e7e7e3"

# --- data (from bench/reports/leaderboard.md) ---
# (label, value, color)
fp = [
    ("odin-dataflow", 0.0, ODIN_DATAFLOW),
    ("semgrep", 2.1, SEMGREP),
    ("odin-rules", 8.8, ODIN_RULES),
]
recall = [
    ("odin-rules", 64, ODIN_RULES),
    ("semgrep", 29, SEMGREP),
    ("odin-dataflow", 7, ODIN_DATAFLOW),
]

try:
    fm.findfont("DejaVu Sans", fallback_to_default=False)
    plt.rcParams["font.family"] = "DejaVu Sans"
except Exception:
    pass

fig, (axl, axr) = plt.subplots(1, 2, figsize=(11.5, 4.4), dpi=200)
fig.patch.set_facecolor(SURFACE)


def rounded_bars(ax, rows, xmax, better_low):
    ax.set_facecolor(SURFACE)
    labels = [r[0] for r in rows]
    y = list(range(len(rows)))[::-1]  # first row on top
    for (_label, val, color), yi in zip(rows, y, strict=True):
        ax.add_patch(
            FancyBboxPatch(
                (0, yi - 0.28),
                max(val, 0.001),
                0.56,
                boxstyle="round,pad=0,rounding_size=0.14",
                mutation_aspect=0.5,
                linewidth=0,
                facecolor=color,
                clip_on=False,
            )
        )
        ax.text(
            val + xmax * 0.02,
            yi,
            f"{val:.1f}%" if better_low else f"{val:.0f}%",
            va="center",
            ha="left",
            fontsize=13,
            color=INK,
            fontweight="bold",
        )
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=12, color=INK)
    ax.set_xlim(0, xmax)
    ax.set_ylim(-0.6, len(rows) - 0.4)
    ax.set_xticks([])
    for s in ("top", "right", "bottom", "left"):
        ax.spines[s].set_visible(False)
    ax.tick_params(length=0)


rounded_bars(axl, fp, xmax=11, better_low=True)
axl.set_title(
    "False-positive rate on 193 clean samples",
    fontsize=13.5,
    color=INK,
    fontweight="bold",
    loc="left",
    pad=14,
)
axl.text(0, 3.05, "↓ lower is better", fontsize=10.5, color=MUTED, transform=axl.transData)

rounded_bars(axr, recall, xmax=78, better_low=False)
axr.set_title(
    "Security-bug recall on SecVulEval (14 CVEs)",
    fontsize=13.5,
    color=INK,
    fontweight="bold",
    loc="left",
    pad=14,
)
axr.text(0, 3.05, "↑ higher is better", fontsize=10.5, color=MUTED, transform=axr.transData)

fig.suptitle(
    "Odin — honest, reproducible benchmarks vs Semgrep",
    fontsize=16,
    color=INK,
    fontweight="bold",
    x=0.5,
    y=1.02,
)
fig.text(
    0.5,
    -0.04,
    "Line-localized matching: a finding must land on the vulnerable line to count. "
    "Ground-truth markers are stripped so a comment rule can't cheat.  "
    "Reproduce: python -m bench.harness --seed 42",
    ha="center",
    fontsize=9,
    color=MUTED,
)

fig.tight_layout(rect=(0, 0, 1, 0.97))
out = Path(__file__).parent / "hero-chart.png"
fig.savefig(out, bbox_inches="tight", facecolor=SURFACE, pad_inches=0.25)
print(f"wrote {out}")
