"""Attack packet builders, fed through the real monitor without root."""

import ipaddress

import pytest

from attacks import ndp_flood, rogue_ra
from mayfly.detectors import HIGH, MEDIUM, RouterPolicy
from mayfly.identity import DeviceEnrollment, DeviceIdentity, Response, join_address
from mayfly.identity.iid import prefix_from_network
from mayfly.monitor import Monitor
from mayfly.params import Params

PARAMS = Params(epoch_seconds=60, session_ttl_seconds=600, grace_epochs=1)
PREFIX = prefix_from_network("fd4d:6179:666c:1::/64")
POLICY = RouterPolicy("vrouter", ipaddress.IPv6Address("fe80::1"),
                      (ipaddress.IPv6Network("fd4d:6179:666c:1::/64"),))
MAC = "02:4d:46:00:00:66"


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


@pytest.fixture
def mon():
    clock = Clock()
    m = Monitor({"A": b"tenant-A", "B": b"tenant-B"}, PARAMS, POLICY, clock=clock,
                wall=lambda: 1.7e9 + clock.t)
    m.clock_obj = clock
    return m


def enroll(mon, tenant):
    store = mon.stores[tenant]
    tok = store.issue_token()
    dev = DeviceEnrollment(tok)
    _, resp = mon.enrollment.handle(b"H", dev.hello().to_bytes())
    confirm, k0 = dev.finish(Response.from_bytes(resp))
    _, label = mon.enrollment.handle(b"C", confirm.to_bytes())
    return label.decode(), DeviceIdentity(k0, mon.clock(), PARAMS)


@pytest.mark.parametrize("variant,rules", [
    ("hijack", ["R1", "R2", "R3", "R4"]),
    ("kill", ["R1", "R2", "R4"]),
    ("flood", ["R1", "R2"]),
])
def test_rogue_ra_variants_detected(mon, variant, rules):
    spec = rogue_ra.VARIANTS[variant]
    frame = rogue_ra.build_ra("fe80::66", MAC, **spec)
    alerts = mon.process_frame(frame, "vattacker", now=1.0)
    rogue = [a for a in alerts if a.detector == "rogue_ra"]
    assert len(rogue) == 1 and rogue[0].rules == rules and rogue[0].severity == HIGH


def test_rotating_flood_one_pseudonym(mon):
    """S4: compromised enrolled device floods NS while rotating every second;
    all alerts carry its single pseudonym (what a per-address baseline misses)."""
    label, dev = enroll(mon, "A")
    builder = ndp_flood._builder("ns", "02:4d:46:00:00:01")
    for sec in range(120):
        mon.clock_obj.t = t = float(sec)
        mon.tick()
        src = str(join_address(PREFIX, dev.new_iid(PREFIX, t)))   # new address each second
        for k in range(40):
            mon.process_frame(builder(src, k), "vd1", now=t + k / 40)
    rate = [a for a in mon.sink.alerts if a.detector == "rate"]
    assert rate and {a.label for a in rate} == {label}
    assert all(a.severity == MEDIUM and a.tenant == "A" for a in rate)
    # a fresh enrollment confirms the attacker really cycled through many addresses
    _, fresh = enroll(mon, "A")
    n_addrs = len({str(join_address(PREFIX, fresh.new_iid(PREFIX, float(s)))) for s in range(60)})
    assert n_addrs == 60, "attacker rotates to a new address every mint"


def test_spoof_flood_per_port_high(mon):
    builder = ndp_flood._builder("ns", "02:4d:46:00:00:66")
    alerts = []
    for k in range(100):
        alerts += mon.process_frame(builder(ndp_flood._random_source(), k), "vattacker", now=k * 0.01)
    assert len(alerts) == 1
    assert alerts[0].label is None and alerts[0].severity == HIGH and alerts[0].port == "vattacker"


def test_na_and_rs_builders_parse():
    from mayfly.nd import NA, RS, parse_frame
    na = ndp_flood.build_na("fd4d:6179:666c:1::5", "fd4d:6179:666c:1::5", MAC)
    rs = ndp_flood.build_rs("fe80::5", MAC)
    assert parse_frame(na).msg_type == NA
    assert parse_frame(rs).msg_type == RS
