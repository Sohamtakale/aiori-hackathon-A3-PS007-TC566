"""Plots for the evaluation report (PRD section 11, FR-H3).

Matplotlib with the Agg backend (no display needed). Colours are chosen to be
distinguishable in greyscale and for common colour-vision deficiencies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt   # noqa: E402

C_MAYFLY, C_B1, C_B2 = "#1b6ca8", "#c84b31", "#e6a700"


def _errs(means):
    return [m.ci for m in means]


def detection_bars(per_scenario: Dict[str, dict], path: Path) -> None:
    names = [n for n in per_scenario if per_scenario[n]["mayfly"].get("detection_rate")]
    x = range(len(names))
    w = 0.26
    fig, ax = plt.subplots(figsize=(8, 4.2))
    for off, det, col in ((-w, "mayfly", C_MAYFLY), (0.0, "B1", C_B1), (w, "B2", C_B2)):
        vals = [per_scenario[n][det].get("detection_rate") for n in names]
        ax.bar([i + off for i in x], [v.mean if v else 0 for v in vals], w,
               yerr=[v.ci if v else 0 for v in vals], capsize=3, label=det, color=col)
    ax.set_xticks(list(x))
    ax.set_xticklabels(names)
    ax.set_ylabel("detection rate")
    ax.set_ylim(0, 1.08)
    ax.set_title("Detection rate per attack scenario (95% CI)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def rotation_headline(rows: List[dict], path: Path) -> None:
    xs = [r["rotate"] for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4.3))
    # draw B2 and B1 first, Mayfly on top (thicker) so it is not occluded when it overlaps B2
    for det, col, style, lw, z in (("B2", C_B2, "--", 1.8, 2), ("B1", C_B1, "-", 1.8, 2),
                                   ("mayfly", C_MAYFLY, "-", 2.8, 3)):
        ys = [r[det].mean for r in rows]
        es = [r[det].ci for r in rows]
        ax.errorbar(xs, ys, yerr=es, marker="o", capsize=3, label=det, color=col,
                    linestyle=style, linewidth=lw, zorder=z)
    ax.set_xscale("log")
    ax.set_xticks(xs)
    ax.set_xticklabels([str(x) for x in xs])
    ax.set_xlabel("attacker address rotation interval (s)  <- faster rotation")
    ax.set_ylabel("detection rate")
    ax.set_ylim(-0.05, 1.08)
    ax.set_title("S4: per-address baseline degrades as rotation speeds up; Mayfly does not")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def threshold_curve(rows: List[dict], path: Path, title: str) -> None:
    fig, ax = plt.subplots(figsize=(7, 4.3))
    det = [r["detection_rate"].mean for r in rows]
    fp = [r["fp_per_hour"].mean for r in rows]
    labels = [r["ns_threshold"] for r in rows]
    ax.plot(fp, det, marker="o", color=C_MAYFLY)
    for f, d, lab in zip(fp, det, labels):
        ax.annotate("NS>=%d" % lab, (f, d), textcoords="offset points", xytext=(6, -4), fontsize=8)
    ax.set_xlabel("false positives per hour")
    ax.set_ylabel("detection rate")
    ax.set_ylim(-0.05, 1.08)
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
