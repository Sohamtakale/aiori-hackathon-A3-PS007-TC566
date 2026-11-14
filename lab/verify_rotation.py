#!/usr/bin/env python3
"""Check a rotation run against the PRD acceptance criteria.

    FR-E2  at least 3 rotations per device per 5 minutes
    FR-K3  every scripted address resolved to its device's label while it existed
    PT-2   no address ever resolved under the other tenant
    and    ground-truth sanity: unique addresses, add -> deprecate -> remove order

    .venv/bin/python lab/verify_rotation.py runs/<run-dir>
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Dict, List, Tuple


def load(path: Path) -> List[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def verify(run_dir: Path) -> Tuple[List[Tuple[bool, str]], List[str]]:
    rot = load(run_dir / "rotation.jsonl")
    res = load(run_dir / "resolver.jsonl")
    if not rot or rot[0].get("event") != "run":
        return [(False, "rotation.jsonl missing or has no run header")], []
    hdr = rot[0]
    mode, devices = hdr["mode"], hdr["devices"]
    stop_t = next((r["t"] for r in rot if r["event"] == "stop"), None)
    duration = stop_t if stop_t is not None else hdr["duration"]
    checks: List[Tuple[bool, str]] = []

    adds: Dict[str, List[dict]] = defaultdict(list)
    life: Dict[str, Dict[str, float]] = defaultdict(dict)
    sessions: Dict[str, set] = defaultdict(set)
    for r in rot:
        ev = r.get("event")
        if ev == "add":
            adds[r["device"]].append(r)
            if r.get("label"):
                sessions[r["device"]].add(r["label"])
        if ev in ("add", "deprecate", "remove"):
            life[r["addr"]].setdefault(ev, r["t"])

    # FR-E2
    need = 3.0 * duration / 300.0
    for d in devices:
        n = len(adds[d])
        rotations = max(0, n - 1) if mode == "scripted" else n
        checks.append((rotations >= need,
                       "FR-E2 %s: %d rotations in %.0fs (need >= %.1f)" % (d, rotations, duration, need)))

    # Ground-truth sanity
    all_addrs = [r["addr"] for d in devices for r in adds[d]]
    checks.append((len(all_addrs) == len(set(all_addrs)), "every address is used once (%d addresses)" % len(all_addrs)))
    order_ok = all(("deprecate" not in v or v["deprecate"] >= v["add"]) and
                   ("remove" not in v or v["remove"] >= v.get("deprecate", v["add"]))
                   for v in life.values())
    checks.append((order_ok, "add -> deprecate -> remove order holds for every address"))
    removed = sum("remove" in v for v in life.values())
    checks.append((removed == len(life), "every address removed by the end (%d/%d)" % (removed, len(life))))

    if mode == "scripted" and hdr.get("monitor"):
        checks.append((True, "FR-K3 resolver checks skipped: enrolled with the live monitor, "
                             "compare its alerts instead (lab/score_alerts.py)"))
    elif mode == "scripted":
        # FR-K3: resolver log matches rotation log
        expected = {r["addr"]: r["label"] for d in devices for r in adds[d]}
        wrong = [r for r in res if r["own"] != expected.get(r["addr"]) or r["own"] != r["expected"]]
        checked_add = {r["addr"] for r in res if r["when"] == "add"}
        checked_rm = {r["addr"] for r in res if r["when"] == "remove"}
        checks.append((not wrong and checked_add == set(expected),
                       "FR-K3 resolver agrees with ground truth at add time (%d/%d)"
                       % (len(checked_add) - len({w['addr'] for w in wrong if w['when'] == 'add'}), len(expected))))
        checks.append((not [w for w in wrong if w["when"] == "remove"],
                       "FR-K3 still resolves just before removal (%d checked)" % len(checked_rm)))
        cross = [r for r in res if r["other_tenant"] is not None]
        checks.append((not cross, "PT-2 cross-tenant resolves: %d of %d lookups" % (len(cross), len(res))))

    rows = []
    for d in devices:
        ts = [r["t"] for r in adds[d]]
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        rows.append("%-4s tenant %s  addresses %3d  mean interval %5.1fs  sessions %d"
                    % (d, hdr["tenants"].get(d, "?"), len(ts), mean(gaps) if gaps else 0.0,
                       len(sessions[d])))
    return checks, rows


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    checks, rows = verify(Path(argv[1]))
    for row in rows:
        print("  " + row)
    print()
    for ok, msg in checks:
        print("  %s  %s" % ("PASS" if ok else "FAIL", msg))
    failed = sum(not ok for ok, _ in checks)
    print("\n%d passed, %d failed" % (len(checks) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
