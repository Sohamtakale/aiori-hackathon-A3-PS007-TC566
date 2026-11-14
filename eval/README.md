# eval/

In-process evaluation harness (PRD section 11). No root, no namespaces: a seeded
traffic model enrolls devices with a real Monitor, mints the same resolvable
addresses the lab would, and replays ND events through Mayfly and the two
baselines. Fully reproducible (FR-H1).

```sh
.venv/bin/python -m eval.run_eval --seeds 30 --out runs/eval
```

Outputs (under the run dir): `metrics.csv`, `rotation_sweep.csv`,
`threshold_sweep.csv`, `summary.json`, and PNG figures.

- `scenarios.py` — traffic model + scenarios S0–S7 (PRD section 11).
- `baselines.py` — B1 per-address rate, B2 per-port rate (FR-H2).
- `harness.py` — replay, scoring vs ground truth, 95% CIs, rotation/threshold sweeps.
- `plots.py` — detection-rate bars, the rotation headline, the threshold curve.

**Metrics** (mean ± 95% CI over seeds): detection rate, time to detect, false
positives/hour, attribution accuracy (Mayfly), overhead (packets/s, µs/packet).

**Headline** (`rotation_headline.png`): on S4, the per-address baseline B1's
detection collapses as the attacker rotates faster (1.0 → 0.0), while Mayfly
stays at 1.0 — it attributes the whole flood to one pseudonym.
