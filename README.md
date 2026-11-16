# Mayfly

**Project Intro:** [https://youtu.be/pRCsOexsugE](https://youtu.be/pRCsOexsugE)

Privacy-aware IPv6 IoT security monitoring across address rotation (AIORI-3, PS-007).
Spec: `docs/Mayfly — Product Requirements Document.pdf`.

```
lab/        namespace and bridge setup, rotation emulator, traffic generator
mayfly/     identity (enroll, ratchet, iid), resolver, detectors, response
attacks/    rogue RA, NDP flood, replay
eval/       scenario runner, baselines, plots
privacy/    PT-1 to PT-5 tests
dashboard/  Streamlit app
docs/       report PDF, architecture, pseudocode
tests/      unit tests (no root needed)
```

## Quick start (no root)

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,eval,dashboard]'
.venv/bin/pytest                               # 122 tests, no root
.venv/bin/python -m eval.run_eval --seeds 30   # evaluation + plots (no root)
.venv/bin/python -m privacy.run_privacy        # privacy report (no root)
```

The lab, monitor and attacks need root and Fedora packages (`radvd`); see
`lab/README.md`. Install those extras with `.venv/bin/pip install -e '.[lab]'`.

## Module map

| Module | PRD |
|---|---|
| `mayfly/identity/enroll.py` | FR-S1 X25519 + HKDF handshake, one-time token HMAC over the transcript, key confirmation |
| `mayfly/identity/ratchet.py` | FR-K1 `K_{e+1} = HKDF(K_e, 'mayfly/v1/ratchet')`, old key zeroized |
| `mayfly/identity/iid.py` | FR-K2 `IID = prand(32) ‖ HMAC(K_e, 'iid'‖prefix‖prand)[:4]` |
| `mayfly/identity/session.py` | FR-S2/S3/S4 labels, ENROLLING→ACTIVE→GRACE→EXPIRED, device resync ≤ 3 epochs |
| `mayfly/keystore.py`, `resolver.py` | FR-R1/R2/R3 one key store per tenant, resolve over epochs e, e-1 with per-epoch cache |
| `mayfly/nd.py` | ND frame parser (RS/RA/NS/NA/Redirect, extension headers, RA options) |
| `mayfly/detectors.py` | FR-D1/D3 rate per pseudonym/port; FR-D2 rogue RA R1–R4; FR-D4 address theft |
| `mayfly/enrollsvc.py` | enrollment endpoint (UNIX socket) carrying the FR-S1 handshake |
| `mayfly/monitor.py` | per-port capture, attribution, alert log (FR-U2 fields only), live state for the dashboard |
| `mayfly/response.py` | FR-X1/X2 L2 isolation via an nftables bridge rule; cooldown, auto-release |
| `lab/` | FR-E1/E2/E3 namespaces, rotation emulator, monitor launcher (steps 2–4; see `lab/README.md`) |
| `attacks/` | S3–S6 rogue RA, NDP flood, replay (lab only; see `attacks/README.md`) |
| `eval/` | FR-H1–H4 scenarios S0–S7, baselines B1/B2, metrics + plots (`eval/README.md`) |
| `privacy/` | PT-1 … PT-5 (`privacy/README.md`) |
| `dashboard/` | FR-U1 Streamlit app (`dashboard/README.md`) |

Key erasure is best-effort: keys live in `bytearray`s that are overwritten, but
Python and OpenSSL may keep transient copies (PRD §12).

## PRD coverage

Built and tested: the test environment (FR-E1–E3), identity and sessions
(FR-S1–S4, FR-K1–K3), resolver (FR-R1–R3), all detectors (FR-D1–D4), response
(FR-X1–X2), logging and harness (FR-U1–U2, FR-H1–H4), the S0–S7 evaluation with
B1/B2 baselines, and PT-1–PT-5. Stretch (P2) items not built: FR-K4 periodic
X25519 re-key, FR-D5 SVM baseline (B3), FR-U3 address-history view (off by
design). The report mapping (`docs/report.pdf`) awaits the structure file
(PRD open question 19.2).
