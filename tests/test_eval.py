"""Evaluation harness: scenarios are reproducible and the headline holds."""

import pytest

from eval.harness import rotation_sweep, run_once, run_scenario
from eval.scenarios import SCENARIOS, ScenarioConfig, build

FAST = ScenarioConfig(duration=90.0)
SEEDS = range(8)


def test_scenarios_build_and_are_seeded():
    for name in SCENARIOS:
        e1, ep1, _, _, _ = build(name, 3, FAST)
        e2, ep2, _, _, _ = build(name, 3, FAST)
        e3, _, _, _, _ = build(name, 4, FAST)
        sig = lambda evs: [(round(t, 3), p.msg_type, port) for t, p, port, _ in evs]
        assert sig(e1) == sig(e2), "%s not reproducible for a fixed seed" % name
        assert sig(e1) != sig(e3), "%s identical across seeds" % name
        assert all(t2 >= t1 for (t1, *_), (t2, *_) in zip(e1, e1[1:])), "events not sorted"


@pytest.mark.parametrize("name", ["S3", "S4", "S5", "S6", "S7"])
def test_attacks_are_detected(name):
    res = run_scenario(name, SEEDS, FAST)
    assert res["mayfly"]["detection_rate"].mean >= 0.95, "Mayfly should detect " + name


@pytest.mark.parametrize("name", ["S0", "S1", "S2"])
def test_benign_scenarios_have_no_false_positives(name):
    res = run_scenario(name, SEEDS, FAST)
    assert res["mayfly"]["false_positives_per_hour"].mean == 0.0


def test_attribution_on_enrolled_attacker():
    res = run_scenario("S4", SEEDS, FAST)
    assert res["mayfly"]["attribution_accuracy"].mean == 1.0


def test_headline_b1_degrades_mayfly_does_not():
    rows = rotation_sweep(SEEDS, intervals=(1, 60), base=FAST)
    fast, slow = rows[0], rows[1]
    assert fast["mayfly"].mean == 1.0 and slow["mayfly"].mean == 1.0, "Mayfly detects at any rotation speed"
    assert fast["B1"].mean == 0.0, "B1 misses a fast-rotating flood"
    assert slow["B1"].mean >= 0.95, "B1 catches a slow-rotating flood"


def test_overhead_reported():
    r = run_once("S4", 0, FAST)
    assert r["mayfly"]["pps"] > 0 and r["mayfly"]["us_per_packet"] > 0
