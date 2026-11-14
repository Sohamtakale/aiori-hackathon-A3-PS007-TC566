import pytest

from mayfly.identity.keys import hkdf, is_zero
from mayfly.identity.ratchet import EpochRatchet, KeyErased, ResyncRequired
from mayfly.params import INFO_RATCHET


def k0() -> bytearray:
    return bytearray(range(32))


def test_step_matches_spec():
    r = EpochRatchet(k0(), keep_previous=False)
    r.advance()
    expected = hkdf(bytes(range(32)), INFO_RATCHET)
    assert r.current() == (1, expected)


def test_device_overwrites_old_key():
    buf = k0()
    r = EpochRatchet(buf, keep_previous=False)
    r.advance()
    assert is_zero(buf), "K_0 must be zeroized after advancing"
    assert len(r.live_keys()) == 1


def test_monitor_keeps_exactly_one_previous():
    buf0 = k0()
    r = EpochRatchet(buf0, keep_previous=True)
    r.advance()
    _, k1 = r.current()
    assert [e for e, _ in r.live_keys()] == [1, 0]
    assert not is_zero(buf0)
    r.advance()
    assert is_zero(buf0), "K_0 must be erased once it is two epochs old"
    assert [e for e, _ in r.live_keys()] == [2, 1]
    assert r.live_keys()[1][1] is k1


def test_advance_to_matches_repeated_steps():
    a = EpochRatchet(k0(), keep_previous=True)
    b = EpochRatchet(k0(), keep_previous=True)
    a.advance_to(7)
    for _ in range(7):
        b.advance()
    assert a.live_keys() == b.live_keys()


def test_cannot_go_backwards():
    r = EpochRatchet(k0(), keep_previous=False)
    r.advance_to(3)
    with pytest.raises(ValueError):
        r.advance_to(2)


def test_resync_limit():
    r = EpochRatchet(k0(), keep_previous=False)
    r.advance_to(3, max_steps=3)
    with pytest.raises(ResyncRequired):
        r.advance_to(7, max_steps=3)
    assert r.epoch == 3, "a refused resync must not move the ratchet"


def test_erase_zeroizes_everything():
    r = EpochRatchet(k0(), keep_previous=True)
    r.advance_to(2)
    bufs = r._buffers()
    r.erase()
    assert all(is_zero(b) for b in bufs)
    assert r.live_keys() == []
    with pytest.raises(KeyErased):
        r.current()
    with pytest.raises(KeyErased):
        r.advance()


def test_rejects_bad_key():
    with pytest.raises(ValueError):
        EpochRatchet(bytearray(16), keep_previous=False)
    with pytest.raises(ValueError):
        EpochRatchet(bytes(32), keep_previous=False)  # immutable: could not be erased
