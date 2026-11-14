"""Scenario runner, scoring and aggregation (PRD section 11, FR-H1/H2/H3/H4).

Replays each scenario's events through Mayfly, B1 and B2, scores every alert
against ground truth, and aggregates over seeds with 95% confidence intervals.
Metrics: detection rate, time to detect, false positives/hour, attribution
accuracy (Mayfly), and overhead (packets/sec, microseconds/packet).
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Dict, List, Optional, Tuple

from eval.baselines import B1PerAddress, B2PerPort
from eval.scenarios import Episode, ScenarioConfig, build


DETECT_GRACE = 6.0        # seconds after an episode a first alert still counts
TICK = 1.0


@dataclass
class Mean:
    mean: float
    ci: float             # half-width of the 95% CI
    n: int

    def __str__(self) -> str:
        return "%.3f +/- %.3f" % (self.mean, self.ci)


def agg(values: List[float]) -> Mean:
    n = len(values)
    if n == 0:
        return Mean(0.0, 0.0, 0)
    m = mean(values)
    if n == 1:
        return Mean(m, 0.0, 1)
    sem = pstdev(values) * math.sqrt(n / (n - 1)) / math.sqrt(n)
    return Mean(m, 1.96 * sem, n)


def _in_window(t: float, ep: Episode) -> bool:
    return ep.start <= t <= ep.end + DETECT_GRACE


def _may_matches(a, ep: Episode, inv_labels) -> bool:
    if inv_labels.get(a.label) == ep.device:          # attacker is an enrolled device (S4/S7)
        return True
    if a.port == ep.port:                             # attacker identified by ingress port
        return True
    if ep.kind == "replay" and a.detector == "theft":  # victim address seen on two ports (S6)
        return True
    return False


def _base_matches(key: str, kind: str, ep: Episode, owners) -> bool:
    return (key == ep.port) if kind == "port" else (owners.get(key) == ep.device)


def run_once(name: str, seed: int, cfg: Optional[ScenarioConfig] = None) -> dict:
    cfg = cfg or ScenarioConfig()
    events, episodes, owners, mon, labels = build(name, seed, cfg)
    inv_labels = {v: k for k, v in labels.items()}
    b1, b2 = B1PerAddress(), B2PerPort()

    may: List = []
    base: Dict[str, List[Tuple[float, str]]] = {"B1": [], "B2": []}
    next_tick = 0.0
    t0 = time.perf_counter()
    for (t, pkt, port, tag) in events:
        if t >= next_tick:
            mon.tick(t)
            b1.prune(t)
            b2.prune(t)
            next_tick = t + TICK
        may.extend(mon.process_packet(pkt, port, t))
        ba = b1.observe(pkt, port, t)
        if ba:
            base["B1"].append((t, ba.key))
        ba = b2.observe(pkt, port, t)
        if ba:
            base["B2"].append((t, ba.key))
    elapsed = time.perf_counter() - t0
    benign_hours = cfg.duration / 3600.0
    out: Dict[str, dict] = {}

    # Mayfly
    detected, ttd = [], []
    for ep in episodes:
        hits = [a.t for a in may if _in_window(a.t, ep) and _may_matches(a, ep, inv_labels)]
        detected.append(1.0 if hits else 0.0)
        if hits:
            ttd.append(min(hits) - ep.start)
    fp = sum(1 for a in may if not any(_in_window(a.t, ep) and _may_matches(a, ep, inv_labels)
                                       for ep in episodes))
    enrolled_eps = [ep for ep in episodes if ep.device in labels]
    attr_total = attr_ok = 0
    for a in may:
        if not a.label:
            continue
        for ep in enrolled_eps:
            if _in_window(a.t, ep):
                attr_total += 1
                if a.label == labels[ep.device]:
                    attr_ok += 1
                break
    out["mayfly"] = {
        "detection_rate": mean(detected) if detected else None,
        "time_to_detect": mean(ttd) if ttd else None,
        "false_positives_per_hour": fp / benign_hours,
        "attribution_accuracy": (attr_ok / attr_total) if attr_total else None,
        "n_episodes": len(episodes),
        "pps": len(events) / elapsed if elapsed else 0.0,
        "us_per_packet": 1e6 * elapsed / len(events) if events else 0.0,
    }

    # baselines
    for det in ("B1", "B2"):
        kind = "address" if det == "B1" else "port"
        alist = base[det]
        detected = []
        for ep in episodes:
            hits = [t for (t, key) in alist if _in_window(t, ep) and _base_matches(key, kind, ep, owners)]
            detected.append(1.0 if hits else 0.0)
        fp = sum(1 for (t, key) in alist
                 if not any(_in_window(t, ep) and _base_matches(key, kind, ep, owners) for ep in episodes))
        out[det] = {
            "detection_rate": mean(detected) if detected else None,
            "time_to_detect": None,
            "false_positives_per_hour": fp / benign_hours,
            "attribution_accuracy": None,
            "n_episodes": len(episodes),
        }
    return out


def run_scenario(name: str, seeds: range, cfg: Optional[ScenarioConfig] = None) -> dict:
    runs = [run_once(name, s, cfg) for s in seeds]
    result: Dict[str, Dict[str, Mean]] = {}
    for det in ("mayfly", "B1", "B2"):
        metrics = {}
        for key in ("detection_rate", "time_to_detect", "false_positives_per_hour",
                    "attribution_accuracy", "pps", "us_per_packet"):
            vals = [r[det].get(key) for r in runs]
            vals = [v for v in vals if v is not None]
            if vals:
                metrics[key] = agg(vals)
        result[det] = metrics
    result["_meta"] = {"scenario": name, "seeds": len(list(seeds)),
                       "n_episodes": runs[0]["mayfly"]["n_episodes"]}
    return result


def rotation_sweep(seeds: range, intervals=(0.5, 1, 2, 3, 5, 15, 60),
                   base: Optional[ScenarioConfig] = None) -> List[dict]:
    """Headline (PRD 11): B1 detection degrades as the attacker rotates faster;
    Mayfly does not. Runs S4 across attacker rotation intervals."""
    base = base or ScenarioConfig()
    rows = []
    for iv in intervals:
        cfg = ScenarioConfig(**{**base.__dict__, "attack_rotate": float(iv)})
        res = run_scenario("S4", seeds, cfg)
        rows.append({"rotate": iv,
                     "mayfly": res["mayfly"]["detection_rate"],
                     "B1": res["B1"].get("detection_rate", Mean(0, 0, 0)),
                     "B2": res["B2"].get("detection_rate", Mean(0, 0, 0))})
    return rows


def threshold_sweep(name: str, seeds: range, factors=(0.25, 0.5, 1, 2, 4),
                    base: Optional[ScenarioConfig] = None) -> List[dict]:
    """Detection vs false-positive trade-off as the NS threshold is scaled."""
    from mayfly.detectors import DEFAULT_THRESHOLDS
    base = base or ScenarioConfig()
    rows = []
    for fac in factors:
        thr = {k: max(1, int(v * fac)) for k, v in DEFAULT_THRESHOLDS.items()}
        det, fp = [], []
        for seed in seeds:
            r = _run_with_threshold(name, seed, base, thr)
            if r["detection_rate"] is not None:
                det.append(r["detection_rate"])
            fp.append(r["false_positives_per_hour"])
        rows.append({"factor": fac, "ns_threshold": thr["NS"],
                     "detection_rate": agg(det), "fp_per_hour": agg(fp)})
    return rows


def _run_with_threshold(name, seed, cfg, thresholds) -> dict:
    events, episodes, owners, mon, labels = build(name, seed, cfg)
    inv_labels = {v: k for k, v in labels.items()}
    mon.rate.thresholds.update(thresholds)
    may = []
    next_tick = 0.0
    for (t, pkt, port, tag) in events:
        if t >= next_tick:
            mon.tick(t)
            next_tick = t + TICK
        may.extend(mon.process_packet(pkt, port, t))
    detected = []
    for ep in episodes:
        hits = [a.t for a in may if _in_window(a.t, ep) and _may_matches(a, ep, inv_labels)]
        detected.append(1.0 if hits else 0.0)
    fp = sum(1 for a in may if not any(_in_window(a.t, ep) and _may_matches(a, ep, inv_labels)
                                       for ep in episodes))
    return {"detection_rate": mean(detected) if detected else None,
            "false_positives_per_hour": fp / (cfg.duration / 3600.0)}
