"""Monitor logic without root: frames are fed in directly instead of sniffed."""

import ipaddress
import json
import os
import threading

import pytest

from mayfly.detectors import HIGH, MEDIUM, RouterPolicy, SlidingCounter
from mayfly.enrollsvc import EnrollClient, listen
from mayfly.identity import DeviceEnrollment, DeviceIdentity, EnrollmentError, join_address
from mayfly.identity.iid import prefix_from_network
from mayfly.monitor import AlertLog, Monitor
from mayfly.params import Params

import ndframes as f

PARAMS = Params(epoch_seconds=60, session_ttl_seconds=600, grace_epochs=1)
PREFIX = prefix_from_network("fd4d:6179:666c:1::/64")
POLICY = RouterPolicy("vrouter", ipaddress.IPv6Address("fe80::1"),
                      (ipaddress.IPv6Network("fd4d:6179:666c:1::/64"),))


class Clock:
    def __init__(self):
        self.t = 0.0

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
    svc = mon.enrollment
    tok = store.issue_token()
    dev = DeviceEnrollment(tok)
    rtype, resp = svc.handle(b"H", dev.hello().to_bytes())
    assert rtype == b"R"
    from mayfly.identity import Response
    confirm, k0 = dev.finish(Response.from_bytes(resp))
    rtype, label = svc.handle(b"C", confirm.to_bytes())
    assert rtype == b"L"
    return label.decode(), DeviceIdentity(k0, mon.clock(), PARAMS)


def test_sliding_counter_window():
    c = SlidingCounter(5.0)
    for t in range(10):
        c.add(float(t))
    assert c.count(9.0) == 5            # events at 5..9
    assert c.count(20.0) == 0


def test_benign_traffic_raises_nothing(mon):
    label, dev = enroll(mon, "A")
    for i in range(120):                 # 2 minutes: periodic RA, a few NS/NA, DAD
        mon.clock_obj.t = float(i)
        mon.tick()
        addr = str(join_address(PREFIX, dev.new_iid(PREFIX, float(i))))
        if i % 5 == 0:
            mon.process_frame(f.ra(), "vrouter")
        mon.process_frame(f.ns("::", addr), "vd1")              # DAD
        mon.process_frame(f.ns(addr, "fd4d:6179:666c:1::1"), "vd1")
        mon.process_frame(f.na(addr, addr), "vd1")
    assert mon.sink.alerts == []
    assert mon.stats["vd1"]["bound"] == 240


def test_rotating_flood_is_attributed_to_one_pseudonym(mon):
    """FR-D1 / T2: a compromised enrolled device floods NS while changing its
    address every second; all alerts carry its single label."""
    label, dev = enroll(mon, "A")
    victim_label, _ = enroll(mon, "B")
    t = 0.0
    for sec in range(130):               # crosses two epoch boundaries
        mon.clock_obj.t = t = float(sec)
        mon.tick()
        src = str(join_address(PREFIX, dev.new_iid(PREFIX, t)))   # new address every second
        for k in range(40):              # 40 NS/s, threshold is 50 per 5 s
            mon.process_frame(f.ns(src, "fd4d:6179:666c:1::%x" % k), "vd1", now=t + k / 40)
    rate = [a for a in mon.sink.alerts if a.detector == "rate"]
    assert rate, "flood not detected"
    assert {a.label for a in rate} == {label}
    assert all(a.severity == MEDIUM and a.tenant == "A" and a.port == "vd1" for a in rate)
    assert rate[0].t < 2.0, "detection should happen within ~1.3 s at 40 pps"
    assert len(rate) <= 130 / 5 + 1, "one alert per window, not per packet"
    assert victim_label not in {a.label for a in mon.sink.alerts}


def test_unbound_spoof_flood_counted_per_port(mon):
    """FR-D3 / T3: random source addresses resolve to nothing -> per-port bucket, high."""
    alerts = []
    for k in range(100):
        src = "fd4d:6179:666c:1:" + ":".join(os.urandom(8).hex()[i:i + 4] for i in range(0, 16, 4))
        alerts += mon.process_frame(f.ns(src, "fd4d:6179:666c:1::1"), "vattacker", now=k * 0.01)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.label is None and a.port == "vattacker" and a.severity == HIGH and a.count == 51


@pytest.mark.parametrize("frame,port,rules", [
    (f.ra(src="fe80::66", mac="02:4d:46:00:00:66"), "vattacker", ["R1", "R2"]),       # hijack
    (f.ra(src="fe80::66", lifetime=0), "vattacker", ["R1", "R2", "R4"]),            # kill route
    (f.ra(src="fe80::66", prf=1), "vattacker", ["R1", "R2", "R4"]),                 # high pref
    (f.ra(prefix="2001:db8:bad::"), "vattacker", ["R1", "R3"]),                     # spoofed router LL
    (f.ra(src="fe80::66", ext=f.destopt()), "vattacker", ["R1", "R2"]),            # RA-guard evasion
    (f.ra(prefix="2001:db8:bad::"), "vrouter", ["R3"]),                             # router misconfig
])
def test_rogue_ra_rules(mon, frame, port, rules):
    alerts = mon.process_frame(frame, port, now=1.0)
    rogue = [a for a in alerts if a.detector == "rogue_ra"]
    assert len(rogue) == 1 and rogue[0].rules == rules and rogue[0].severity == HIGH


def test_legitimate_ra_is_quiet(mon):
    assert mon.process_frame(f.ra(), "vrouter", now=1.0) == []


def test_rogue_ra_flood_deduplicated(mon):
    alerts = []
    for k in range(200):
        alerts += mon.process_frame(f.ra(src="fe80::66"), "vattacker", now=k * 0.01)
    rogue = [a for a in alerts if a.detector == "rogue_ra"]
    rate = [a for a in alerts if a.detector == "rate"]
    assert len(rogue) == 1 and len(rate) == 1 and rate[0].msg_type == "RA"


def test_alert_has_no_addresses(mon, tmp_path):
    mon.sink = AlertLog(tmp_path / "alerts.jsonl", retention=600, echo=False)
    label, dev = enroll(mon, "A")
    src = str(join_address(PREFIX, dev.new_iid(PREFIX, 0.0)))
    for k in range(60):
        mon.process_frame(f.ns(src, "fd4d:6179:666c:1::1"), "vd1", now=k * 0.01)
    mon.process_frame(f.ra(src="fe80::66"), "vattacker", now=1.0)
    text = (tmp_path / "alerts.jsonl").read_text()
    recs = [json.loads(l) for l in text.splitlines()]
    assert {r["detector"] for r in recs} == {"rate", "rogue_ra"}
    allowed = {"t", "ts", "detector", "severity", "msg_type", "port", "label", "tenant",
               "epoch", "count", "threshold", "rules"}
    assert all(set(r) <= allowed for r in recs)
    assert "fd4d" not in text and "fe80" not in text and src not in text


def test_alert_retention(mon, tmp_path):
    mon.sink = AlertLog(tmp_path / "alerts.jsonl", retention=600, echo=False)
    mon.process_frame(f.ra(src="fe80::66"), "vattacker", now=1.0)
    mon.tick(500.0)
    assert len(mon.sink.alerts) == 1
    mon.tick(602.0)
    assert mon.sink.alerts == [] and (tmp_path / "alerts.jsonl").read_text() == ""


def test_expired_session_counters_forgotten(mon):
    label, dev = enroll(mon, "A")
    src = str(join_address(PREFIX, dev.new_iid(PREFIX, 0.0)))
    mon.process_frame(f.ns(src, "fd4d:6179:666c:1::1"), "vd1", now=0.0)
    assert any(k[0][0] == "label" for k in mon.rate._counters)
    mon.tick(PARAMS.session_ttl_seconds + PARAMS.grace_seconds)
    assert not any(k[0][0] == "label" for k in mon.rate._counters)
    assert mon.sessions() == {"A": 0, "B": 0}


def test_enrollment_over_unix_socket(mon, tmp_path):
    path = str(tmp_path / "m.sock")
    srv = listen(path)
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"

    def serve_once():
        srv.setblocking(True)
        conn, _ = srv.accept()
        mon.enrollment.serve_connection(conn)
    th = threading.Thread(target=serve_once)
    th.start()
    with EnrollClient(path) as c:
        tok, params = c.issue_token("B")
        assert params == PARAMS and tok.tenant_id == b"tenant-B"
        dev = DeviceEnrollment(tok)
        confirm, k0 = dev.finish(c.hello(dev.hello()))
        label = c.confirm(confirm)
        with pytest.raises(EnrollmentError):
            c.issue_token("Z")
    th.join(5)
    srv.close()
    assert mon.stores["B"].get(label) is not None
    ident = DeviceIdentity(k0, 0.0, PARAMS)
    src = str(join_address(PREFIX, ident.new_iid(PREFIX, 0.0)))
    from mayfly.nd import parse_frame
    who = mon.attribute(parse_frame(f.ns(src, src)), "vd4")
    assert who.label == label and who.tenant == "B"


def test_fr_d4_address_theft(mon):
    """FR-D4 / T4: a resolvable address replayed on a second port raises a HIGH
    theft alert naming the victim's pseudonym and isolating the replay port."""
    from mayfly.identity import join_address
    label, dev = enroll(mon, "A")
    addr = str(join_address(PREFIX, dev.new_iid(PREFIX, 0.0)))
    # victim's own traffic on its real port: no alert
    assert mon.process_frame(f.ns(addr, "fd4d:6179:666c:1::1"), "vd1", now=0.0) == []
    # same address replayed from the attacker's port within the epoch: theft
    alerts = mon.process_frame(f.ns(addr, "fd4d:6179:666c:1::1"), "vattacker", now=1.0)
    theft = [a for a in alerts if a.detector == "theft"]
    assert len(theft) == 1
    assert theft[0].severity == HIGH and theft[0].label == label and theft[0].port == "vattacker"
    assert theft[0].rules == ["seen_on:vd1"]


def test_fr_d4_ignores_unbound_and_same_port(mon):
    label, dev = enroll(mon, "A")
    addr = str(join_address(PREFIX, dev.new_iid(PREFIX, 0.0)))
    mon.process_frame(f.ns(addr, "fd4d:6179:666c:1::1"), "vd1", now=0.0)
    # same port again: fine
    assert [a for a in mon.process_frame(f.ns(addr, "fd4d:6179:666c:1::1"), "vd1", now=0.5)
            if a.detector == "theft"] == []
    # unbound (unresolvable) address on two ports: not theft (no owner to frame)
    import os
    spoof = "fd4d:6179:666c:1:" + ":".join(os.urandom(8).hex()[i:i+4] for i in range(0, 16, 4))
    mon.process_frame(f.ns(spoof, "fd4d:6179:666c:1::1"), "vd2", now=0.0)
    assert [a for a in mon.process_frame(f.ns(spoof, "fd4d:6179:666c:1::1"), "vattacker", now=0.1)
            if a.detector == "theft"] == []
