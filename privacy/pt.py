"""Privacy tests PT-1 .. PT-5 (PRD section 12).

Each returns a PTResult(passed, metrics, detail). They use the library directly
(no namespaces) so they are fast and deterministic. run_privacy.py runs them all
and writes a report; test_pt.py asserts the pass criteria.
"""

from __future__ import annotations

import gc

import re
from dataclasses import dataclass, field
from typing import Dict, List

from mayfly.identity import DeviceEnrollment, DeviceIdentity, Response, prefix_from_network
from mayfly.identity.iid import check_iid
from mayfly.identity.keys import is_zero
from mayfly.keystore import TenantKeyStore
from mayfly.params import Params
from mayfly.resolver import UNBOUND, Resolver
from privacy.linkability import measure

PREFIX = prefix_from_network("fd4d:6179:666c:1::/64")
PARAMS = Params(epoch_seconds=60, session_ttl_seconds=600, grace_epochs=1)
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]+\b")


@dataclass
class PTResult:
    name: str
    passed: bool
    criterion: str
    metrics: Dict[str, object] = field(default_factory=dict)
    detail: str = ""

    def line(self) -> str:
        return "%-5s %-4s %s" % (self.name, "PASS" if self.passed else "FAIL", self.detail)


def _enroll(store: TenantKeyStore, at: float = 0.0):
    tok = store.issue_token()
    d = DeviceEnrollment(tok)
    from mayfly.enrollsvc import EnrollmentService
    svc = EnrollmentService({"x": store}, lambda: at)
    _, resp = svc.handle(b"H", d.hello().to_bytes())
    confirm, k0 = d.finish(Response.from_bytes(resp))
    _, label = svc.handle(b"C", confirm.to_bytes())
    return label.decode(), DeviceIdentity(k0, at, PARAMS)


# --------------------------------------------------------------------------- PT-1

def pt1_expiry(n_samples: int = 200) -> PTResult:
    """After TTL+grace, none of N sampled old addresses resolve, and no key
    material remains in the store."""
    store = TenantKeyStore(b"tenant-A", PARAMS)
    res = Resolver(store)
    label, dev = _enroll(store)
    sampled = []
    for t in range(0, 600, 3):
        res.tick(float(t))
        iid = dev.new_iid(PREFIX, float(t))
        assert res.resolve(iid, PREFIX) == label
        sampled.append(iid)
        if len(sampled) >= n_samples:
            break
    res.tick(PARAMS.session_ttl_seconds + PARAMS.grace_seconds)
    still = sum(res.resolve(i, PREFIX) is not UNBOUND for i in sampled)
    key_bufs = store._buffers()
    live_key_material = [b for b in key_bufs if not is_zero(b)]
    passed = still == 0 and len(store) == 0 and not live_key_material and res.cache_size() == 0
    return PTResult("PT-1", passed, "0 of N resolve; no key material found",
                    {"sampled": len(sampled), "still_resolve": still, "sessions_left": len(store),
                     "live_key_buffers": len(live_key_material)},
                    "%d/%d old addresses resolve after expiry; %d sessions, %d live key buffers"
                    % (still, len(sampled), len(store), len(live_key_material)))


# --------------------------------------------------------------------------- PT-2

def pt2_cross_tenant(n: int = 300) -> PTResult:
    """Tenant B's resolver never resolves Tenant A traffic; a device enrolled in
    both tenants gets unrelated labels."""
    a = TenantKeyStore(b"tenant-A", PARAMS)
    b = TenantKeyStore(b"tenant-B", PARAMS)
    ra, rb = Resolver(a), Resolver(b)
    la, da = _enroll(a)
    lb, db = _enroll(b)
    false_resolves = 0
    for t in range(0, 300, 3):
        ra.tick(float(t))
        rb.tick(float(t))
        ia = da.new_iid(PREFIX, float(t))
        ib = db.new_iid(PREFIX, float(t))
        false_resolves += rb.resolve(ia, PREFIX) is not UNBOUND
        false_resolves += ra.resolve(ib, PREFIX) is not UNBOUND
    labels_unrelated = la != lb
    passed = false_resolves == 0 and labels_unrelated
    return PTResult("PT-2", passed, "0 false resolves; labels unrelated",
                    {"false_resolves": false_resolves, "label_a": la, "label_b": lb},
                    "%d cross-tenant resolves; labels %s / %s %s"
                    % (false_resolves, la, lb, "unrelated" if labels_unrelated else "RELATED"))


# --------------------------------------------------------------------------- PT-3

def pt3_linkability() -> PTResult:
    """Passive linkability under keys-less timing attack, vs a random baseline.
    Reported, with a 'hard' concurrent/overlap config that should sit near random."""
    easy = measure(num_devices=5, interval=30, jitter=10, overlap=5, window=2.0)
    hard = measure(num_devices=20, interval=15, jitter=1, overlap=12, window=2.0)
    # The honest claim: with overlap and many concurrent devices the adversary's
    # advantage over guessing is small.
    passed = hard.advantage <= 0.20
    return PTResult("PT-3", passed, "advantage over random reported (<=0.20 in the hard regime)",
                    {"easy_accuracy": round(easy.accuracy, 3), "easy_baseline": round(easy.random_baseline, 3),
                     "easy_advantage": round(easy.advantage, 3),
                     "hard_accuracy": round(hard.accuracy, 3), "hard_baseline": round(hard.random_baseline, 3),
                     "hard_advantage": round(hard.advantage, 3)},
                    "linkage advantage: sparse=%.2f (acc %.2f vs base %.2f), concurrent=%.2f (acc %.2f vs base %.2f)"
                    % (easy.advantage, easy.accuracy, easy.random_baseline,
                       hard.advantage, hard.accuracy, hard.random_baseline))


# --------------------------------------------------------------------------- PT-4

def pt4_log_hygiene() -> PTResult:
    """Audit a monitor alert/action log for raw addresses or pcaps."""
    import ipaddress as _ip
    from eval.scenarios import build
    from mayfly.monitor import AlertLog
    import tempfile
    import os
    events, episodes, owners, mon, labels = build("S7", 1)
    tmp = tempfile.mkdtemp()
    mon.sink = AlertLog(os.path.join(tmp, "alerts.jsonl"), 1e9, echo=False)
    nt = 0.0
    for t, pkt, port, tag in events:
        if t >= nt:
            mon.tick(t)
            nt = t + 1.0
        mon.process_packet(pkt, port, t)
    mon.sink.close()
    text = open(os.path.join(tmp, "alerts.jsonl")).read()
    # any token that parses as an IPv6 address (labels are colon-free 12-hex, ports are vdN)
    found = []
    for tok in IPV6_RE.findall(text):
        try:
            _ip.IPv6Address(tok)
            found.append(tok)
        except ValueError:
            pass
    pcaps = [w for w in ("pcap", ".cap", "payload") if w in text]
    n_alerts = text.count("\n")
    passed = not found and not pcaps and n_alerts > 0
    return PTResult("PT-4", passed, "no raw addresses or pcaps in logs",
                    {"alerts": n_alerts, "addresses_found": len(found), "pcap_tokens": pcaps},
                    "%d alert records, %d raw addresses, pcap tokens=%s" % (n_alerts, len(found), pcaps))


# --------------------------------------------------------------------------- PT-5

def pt5_forward_secrecy() -> PTResult:
    """The monitor's key at epoch e cannot resolve addresses from before e-1,
    and K_e alone cannot resolve an address minted at e-1."""
    store = TenantKeyStore(b"tenant-A", PARAMS)
    res = Resolver(store)
    label, dev = _enroll(store)
    old = []
    for t in range(0, 300, 10):
        res.tick(float(t))
        old.append(dev.new_iid(PREFIX, float(t)))
    res.tick(420.0)                                    # e = 7
    still = sum(res.resolve(i, PREFIX) is not UNBOUND for i in old)
    prev_iid = dev.new_iid(PREFIX, 360.0)              # epoch 6
    (e, k7), (_, k6) = store.get(label).live_keys()
    isolation = check_iid(k6, PREFIX, prev_iid) and not check_iid(k7, PREFIX, prev_iid)
    passed = still == 0 and isolation and e == 7
    return PTResult("PT-5", passed, "0 resolves of pre-(e-1) addresses; K_e cannot resolve e-1",
                    {"old_sampled": len(old), "still_resolve": still, "epoch": e,
                     "k_e_isolated_from_prev": isolation},
                    "%d/%d old addresses resolve at e=%d; K_e isolated from e-1: %s"
                    % (still, len(old), e, isolation))


ALL = [pt1_expiry, pt2_cross_tenant, pt3_linkability, pt4_log_hygiene, pt5_forward_secrecy]


def run_all() -> List[PTResult]:
    gc.collect()
    return [fn() for fn in ALL]
