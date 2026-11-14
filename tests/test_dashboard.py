"""Monitor live-state / control plumbing and the dashboard data layer (FR-U1)."""

import ipaddress
import json


from dashboard import data
from mayfly.detectors import RouterPolicy
from mayfly.identity import DeviceEnrollment, DeviceIdentity, Response, join_address
from mayfly.identity.iid import prefix_from_network
from mayfly.monitor import ControlChannel, Monitor, write_state
from mayfly.params import Params

import ndframes as f

PARAMS = Params(epoch_seconds=60, session_ttl_seconds=600, grace_epochs=1)
PREFIX = prefix_from_network("fd4d:6179:666c:1::/64")
POLICY = RouterPolicy("vrouter", ipaddress.IPv6Address("fe80::1"),
                      (ipaddress.IPv6Network("fd4d:6179:666c:1::/64"),))


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def make_mon():
    clock = Clock()
    m = Monitor({"A": b"tenant-A", "B": b"tenant-B"}, PARAMS, POLICY, clock=clock,
                wall=lambda: 1.7e9 + clock.t)
    m.clock_obj = clock
    return m


def enroll(mon, tenant):
    store = mon.stores[tenant]
    dev = DeviceEnrollment(store.issue_token())
    _, resp = mon.enrollment.handle(b"H", dev.hello().to_bytes())
    confirm, k0 = dev.finish(Response.from_bytes(resp))
    _, label = mon.enrollment.handle(b"C", confirm.to_bytes())
    return label.decode(), DeviceIdentity(k0, mon.clock(), PARAMS)


def test_live_state_shows_current_mapping_only():
    mon = make_mon()
    label, dev = enroll(mon, "A")
    a1 = str(join_address(PREFIX, dev.new_iid(PREFIX, 0.0)))
    mon.process_frame(f.ns(a1, "fd4d:6179:666c:1::1"), "vd1", now=0.0)
    st = mon.live_state(0.0)
    sess = st["sessions"][0]
    assert sess["label"] == label and sess["tenant"] == "A" and sess["address"] == a1
    # a newer address replaces the mapping; no history is kept
    mon.clock_obj.t = 1.0
    a2 = str(join_address(PREFIX, dev.new_iid(PREFIX, 1.0)))
    mon.process_frame(f.ns(a2, "fd4d:6179:666c:1::1"), "vd1", now=1.0)
    st = mon.live_state(1.0)
    assert st["sessions"][0]["address"] == a2
    assert a1 not in json.dumps(st), "old address must not persist in the live view"


def test_expire_session_removes_mapping_and_keys():
    mon = make_mon()
    label, dev = enroll(mon, "A")
    addr = str(join_address(PREFIX, dev.new_iid(PREFIX, 0.0)))
    mon.process_frame(f.ns(addr, "fd4d:6179:666c:1::1"), "vd1", now=0.0)
    assert mon.expire_session("A", label) is True
    assert mon.live_state(0.0)["sessions"] == []
    assert mon.resolvers["A"].resolve_address(addr).__bool__() is False
    assert mon.expire_session("A", label) is False


def test_write_state_and_read_back(tmp_path):
    mon = make_mon()
    enroll(mon, "A")
    p = tmp_path / "state.json"
    write_state(mon, 3.0, p)
    st = data.read_state(tmp_path)
    assert st["t"] == 3.0 and len(st["sessions"]) == 1


def test_control_channel_expires(tmp_path):
    mon = make_mon()
    label, _ = enroll(mon, "B")
    ctrl = tmp_path / "control.jsonl"
    ctrl.touch()
    chan = ControlChannel(ctrl)
    data.request_expire(tmp_path, "B", label)
    assert chan.drain(mon, 1.0) == 1
    assert mon.live_state(1.0)["sessions"] == []
    # a duplicate / unknown request is a no-op and not reprocessed
    assert chan.drain(mon, 1.0) == 0
    data.request_expire(tmp_path, "B", "deadbeef")
    assert chan.drain(mon, 2.0) == 0


def test_control_ignores_partial_and_garbage_lines(tmp_path):
    mon = make_mon()
    label, _ = enroll(mon, "A")
    ctrl = tmp_path / "control.jsonl"
    ctrl.write_text("not json\n")
    chan = ControlChannel(ctrl)
    assert chan.drain(mon, 0.0) == 0
    with open(ctrl, "a") as fh:
        fh.write('{"expire": {"tenant": "A", "label": "%s"}}' % label)   # no newline yet
    assert chan.drain(mon, 1.0) == 0                                      # partial, not processed
    with open(ctrl, "a") as fh:
        fh.write("\n")
    assert chan.drain(mon, 2.0) == 1


def test_data_layer_reads_alerts_and_latest_run(tmp_path):
    run = tmp_path / "20260101-000000-monitor"
    run.mkdir()
    (run / "alerts.jsonl").write_text('{"detector":"rate","severity":"medium"}\n{"bad\n')
    assert data.latest_run(tmp_path) == run
    alerts = data.read_alerts(run)
    assert len(alerts) == 1 and alerts[0]["detector"] == "rate"
    assert data.read_state(run)["sessions"] == []
