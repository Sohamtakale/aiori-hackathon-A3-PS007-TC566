import pytest

from mayfly.identity import ResyncRequired, SessionExpired, SessionState
from mayfly.identity.keys import is_zero
from mayfly.params import Params

from conftest import FAST, PREFIX, enroll


def test_params_last_epoch():
    assert FAST.last_epoch == 9
    assert Params(epoch_seconds=60, session_ttl_seconds=90).last_epoch == 1
    with pytest.raises(ValueError):
        Params(epoch_seconds=60, session_ttl_seconds=30)


def test_state_machine_and_zeroization(store_a):
    label, _ = enroll(store_a, 0.0)
    s = store_a.get(label)
    store_a.tick(125.0)
    assert s.state is SessionState.ACTIVE and s.epoch == 2
    bufs = s._buffers()
    store_a.tick(600.0)                       # TTL reached
    assert s.state is SessionState.GRACE and s.epoch == FAST.last_epoch
    assert [e for e, _ in s.live_keys()] == [9, 8]
    assert all(is_zero(b) for b in bufs), "earlier epoch keys were overwritten"
    bufs = s._buffers()
    store_a.tick(660.0)                       # TTL + grace
    assert s.state is SessionState.EXPIRED and s.label is None
    assert all(is_zero(b) for b in bufs)
    assert len(store_a) == 0 and store_a._buffers() == []


def test_manual_expire(store_a):
    label, _ = enroll(store_a, 0.0)
    bufs = store_a.get(label)._buffers()
    assert store_a.expire(label)
    assert not store_a.expire(label)
    assert all(is_zero(b) for b in bufs) and len(store_a) == 0


def test_device_tracks_monitor_epoch(store_a):
    label, dev = enroll(store_a, 0.0)
    for t in (0.0, 59.9, 60.0, 179.0, 300.0):
        store_a.tick(t)
        assert dev.tick(t) == store_a.get(label).epoch


def test_device_resync_up_to_three_epochs(store_a):
    _, dev = enroll(store_a, 0.0)
    dev.tick(60.0)
    dev.tick(60.0 + 3 * 60.0)                 # slept 3 epochs: fine
    assert dev.epoch == 4


def test_device_must_reenroll_after_four_missed_epochs(store_a):
    _, dev = enroll(store_a, 0.0)
    with pytest.raises(ResyncRequired):
        dev.tick(4 * 60.0)
    assert dev.expired
    with pytest.raises(SessionExpired):
        dev.new_iid(PREFIX, 4 * 60.0)


def test_device_stops_at_ttl(store_a):
    _, dev = enroll(store_a, 0.0)
    for t in range(0, 600, 60):
        dev.tick(float(t))
    with pytest.raises(SessionExpired):
        dev.new_iid(PREFIX, 600.0)
