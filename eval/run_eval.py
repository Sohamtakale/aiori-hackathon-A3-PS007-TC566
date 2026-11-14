#!/usr/bin/env python3
"""Run the full evaluation (PRD section 11) and write metrics + plots.

  .venv/bin/python -m eval.run_eval --seeds 30 --out runs/eval

Produces, under the output directory:
  metrics.csv              per-scenario detection/ttd/fp/attribution for Mayfly, B1, B2
  rotation_sweep.csv       S4 detection rate vs attacker rotation interval (the headline)
  threshold_sweep.csv      detection vs false positives as the NS threshold scales
  summary.json             overhead and headline numbers
  *.png                    the figures
No root, no namespaces; fully seeded (FR-H1).
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
from pathlib import Path
from typing import List

from eval.harness import rotation_sweep, run_scenario, threshold_sweep
from eval.plots import detection_bars, rotation_headline, threshold_curve
from eval.scenarios import SCENARIO_DESC, SCENARIOS, ScenarioConfig

METRIC_KEYS = ["detection_rate", "time_to_detect", "false_positives_per_hour", "attribution_accuracy"]


def _cell(m):
    return "" if m is None else "%.4f" % m.mean
def _ci(m):
    return "" if m is None else "%.4f" % m.ci


def main(argv: List[str] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seeds", type=int, default=30, help="runs per scenario (PRD: >= 30)")
    ap.add_argument("--duration", type=float, default=120.0)
    ap.add_argument("--out", type=Path, default=Path("runs") / ("eval-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S")))
    ap.add_argument("--no-plots", action="store_true")
    args = ap.parse_args(argv)
    seeds = range(args.seeds)
    cfg = ScenarioConfig(duration=args.duration)
    args.out.mkdir(parents=True, exist_ok=True)

    print("Mayfly evaluation: %d seeds/scenario, %.0fs each" % (args.seeds, args.duration))
    per_scenario = {}
    with open(args.out / "metrics.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["scenario", "description", "detector", "n_seeds"] +
                   [k for key in METRIC_KEYS for k in (key, key + "_ci95")])
        for name in SCENARIOS:
            res = run_scenario(name, seeds, cfg)
            per_scenario[name] = res
            for det in ("mayfly", "B1", "B2"):
                row = [name, SCENARIO_DESC[name], det, args.seeds]
                for key in METRIC_KEYS:
                    m = res[det].get(key)
                    row += [_cell(m), _ci(m)]
                w.writerow(row)
            m = res["mayfly"]
            dr = m.get("detection_rate")
            print("  %-3s %-40s detect=%-15s fp/h=%-14s attr=%s"
                  % (name, SCENARIO_DESC[name], (str(dr) if dr else "n/a (benign)"),
                     str(m["false_positives_per_hour"]),
                     str(m.get("attribution_accuracy") or "n/a")))

    print("\nHeadline: S4 rotation sweep")
    rot = rotation_sweep(seeds, base=cfg)
    with open(args.out / "rotation_sweep.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["rotate_interval_s", "mayfly", "mayfly_ci", "B1", "B1_ci", "B2", "B2_ci"])
        for r in rot:
            w.writerow([r["rotate"], r["mayfly"].mean, r["mayfly"].ci, r["B1"].mean, r["B1"].ci,
                        r["B2"].mean, r["B2"].ci])
            print("  rot=%-5s Mayfly=%s  B1=%s  B2=%s" % (r["rotate"], r["mayfly"], r["B1"], r["B2"]))

    thr = threshold_sweep("S4", seeds, base=cfg)
    with open(args.out / "threshold_sweep.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ns_threshold", "detection_rate", "detection_ci", "fp_per_hour", "fp_ci"])
        for r in thr:
            w.writerow([r["ns_threshold"], r["detection_rate"].mean, r["detection_rate"].ci,
                        r["fp_per_hour"].mean, r["fp_per_hour"].ci])

    over = per_scenario["S4"]["mayfly"]
    summary = {
        "seeds": args.seeds, "duration": args.duration,
        "overhead_packets_per_sec": over.get("pps").mean if over.get("pps") else None,
        "overhead_us_per_packet": over.get("us_per_packet").mean if over.get("us_per_packet") else None,
        "headline": {("rot_%g" % r["rotate"]): {"mayfly": r["mayfly"].mean, "B1": r["B1"].mean} for r in rot},
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    if not args.no_plots:
        detection_bars(per_scenario, args.out / "detection_rate.png")
        rotation_headline(rot, args.out / "rotation_headline.png")
        threshold_curve(thr, args.out / "threshold_sweep.png", "S4 detection vs false positives (NS threshold)")
        print("\nplots: %s" % ", ".join(p.name for p in sorted(args.out.glob("*.png"))))
    print("\nwritten to %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
