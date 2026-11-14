#!/usr/bin/env python3
"""Join monitor alerts with the emulator's ground truth.

The monitor only knows pseudonym labels; the emulator's rotation log records
which device held which label. This script maps each alert back to a device,
so attribution can be checked (only the experimenter can do this join).

    .venv/bin/python lab/score_alerts.py runs/<monitor-run> [runs/<rotation-run> ...]
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List


def load(path: Path) -> List[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def label_owners(rotation_runs: List[Path]) -> Dict[str, str]:
    owners: Dict[str, str] = {}
    for run in rotation_runs:
        for r in load(run / "rotation.jsonl"):
            if r.get("event") == "enroll":
                owners[r["label"]] = r["device"]
    return owners


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    alerts = load(Path(argv[1]) / "alerts.jsonl")
    owners = label_owners([Path(p) for p in argv[2:]])
    if not alerts:
        print("no alerts")
        return 0
    tally: Counter = Counter()
    print("%-9s %-6s %-8s %-3s %-14s %-7s %-10s %s" % ("t", "sev", "detector", "msg", "label", "device", "port", "detail"))
    for a in alerts:
        dev = owners.get(a.get("label", ""), "-") if a.get("label") else "-"
        port_dev = a["port"][1:] if a["port"].startswith("v") else a["port"]
        detail = ",".join(a.get("rules", [])) or "%s/%s in 5s" % (a.get("count"), a.get("threshold"))
        print("%-9.2f %-6s %-8s %-3s %-14s %-7s %-10s %s" % (a["t"], a["severity"], a["detector"], a["msg_type"],
                                                            a.get("label", "-"), dev, a["port"], detail))
        if a.get("label"):
            tally["label alerts"] += 1
            tally["label matches port" if dev == port_dev else "label != port"] += 1
    print()
    for k, v in sorted(tally.items()):
        print("  %-20s %d" % (k, v))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
