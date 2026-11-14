#!/usr/bin/env python3
"""Run PT-1..PT-5 and write the privacy report (PRD section 12).

  .venv/bin/python -m privacy.run_privacy [--out runs/privacy]
"""
from __future__ import annotations
import argparse, datetime as dt, json, sys
from pathlib import Path
from privacy.pt import run_all


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    results = run_all()
    print("Mayfly privacy analysis (PT-1 .. PT-5)\n")
    for r in results:
        print("  " + r.line())
        print("        criterion: %s" % r.criterion)
    npass = sum(r.passed for r in results)
    print("\n%d/%d passed" % (npass, len(results)))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        report = {"generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                  "results": [{"name": r.name, "passed": r.passed, "criterion": r.criterion,
                               "metrics": r.metrics, "detail": r.detail} for r in results]}
        (args.out / "privacy_report.json").write_text(json.dumps(report, indent=2) + "\n")
        print("report: %s" % (args.out / "privacy_report.json"))
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
