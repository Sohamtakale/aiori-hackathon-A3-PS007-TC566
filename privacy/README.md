# privacy/

Privacy tests PT-1 … PT-5 (PRD section 12). No root; deterministic.

```sh
.venv/bin/python -m privacy.run_privacy --out runs/privacy     # report
.venv/bin/pytest privacy/                                       # pass/fail
```

| Test | Checks | Pass criterion |
|---|---|---|
| PT-1 expiry | resolve N old addresses after TTL+grace; scan for key material | 0 resolve; no live key buffers |
| PT-2 cross-tenant | tenant B resolver on tenant A traffic; dual-enrolled device | 0 false resolves; unrelated labels |
| PT-3 passive linkability | keys-less timing adversary vs random baseline | advantage ≤ 0.20 in the concurrent/overlap regime (reported either way) |
| PT-4 log hygiene | audit alert logs for raw addresses / pcaps | none found |
| PT-5 forward secrecy | K_e resolving pre-(e-1) addresses | 0 resolve; K_e isolated from e-1 |

PT-3 is honest about the limit the PRD names: with sparse, well-separated
rotations a timing adversary links better than chance (advantage ≈ 0.20); with
overlapping validity and many concurrent devices it is indistinguishable from
guessing (advantage ≈ 0). `linkability.py` is the model.
