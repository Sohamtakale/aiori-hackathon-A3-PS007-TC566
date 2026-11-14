"""Resolver behaviour, plus unit-level versions of PT-1, PT-2 and PT-5.
The full privacy suite (memory/log scans, PT-3, PT-4) lives in privacy/."""

import os

from mayfly.identity.iid import join_address
from mayfly.keystore import TenantKeyStore
from mayfly.resolver import UNBOUND, Resolver

from conftest import FAST, OTHER_PREFIX, PREFIX, enroll, seeded_rand


def test_unbound_is_falsy_singleton():
    assert not UNBOUND and repr(UNBOUND) == "UNBOUND"
    assert (UNBOUND or "port3") == "port3"


def test_resolves_all_enrolled_addresses_across_rotation(store_a):
    """FR-K2 acceptance: 100% of enrolled addresses resolve, every epoch."""
    res = Resolver(store_a)
    devices = [enroll(store_a, 0.0) for _ in range(3)]
    total = 0
    for t in range(0, 600, 20):  # three rotations per epoch, all 10 epochs
        now = float(t)
        res.tick(now)
        for label, dev in devices:
            for prefix in (PREFIX, OTHER_PREFIX):
                iid = dev.new_iid(prefix, now)
                assert res.resolve(iid, prefix) == label
                total += 1
    assert total == 3 * 30 * 2


def test_previous_epoch_resolves_older_does_not(store_a):
    """FR-R1: epochs e and e-1 only."""
    res = Resolver(store_a)
    label, dev = enroll(store_a, 0.0)
    iid0 = dev.new_iid(PREFIX, 10.0)
    res.tick(70.0)
    dev.tick(70.0)
    assert res.resolve(iid0, PREFIX) == label          # e-1
    res.tick(130.0)
    assert res.resolve(iid0, PREFIX) is UNBOUND         # e-2


def test_random_addresses_are_unbound(store_a):
    res = Resolver(store_a)
    for _ in range(3):
        enroll(store_a, 0.0)
    assert all(res.resolve(os.urandom(8), PREFIX) is UNBOUND for _ in range(2000))


def test_resolve_address_and_wrong_prefix(store_a):
    res = Resolver(store_a)
    label, dev = enroll(store_a, 0.0)
    iid = dev.new_iid(PREFIX, 0.0)
    assert res.resolve_address(join_address(PREFIX, iid)) == label
    assert res.resolve_address(join_address(OTHER_PREFIX, iid)) is UNBOUND


def test_cache_purged_at_epoch_end_and_expiry(store_a):
    """FR-R3."""
    res = Resolver(store_a)
    label, dev = enroll(store_a, 0.0)
    for _ in range(5):
        res.resolve(dev.new_iid(PREFIX, 0.0), PREFIX)
    assert res.cache_size() == 5
    res.tick(60.0)
    assert res.cache_size() == 5                         # epoch 0 is now e-1, still live
    res.tick(120.0)
    assert res.cache_size() == 0
    res.resolve(dev.new_iid(PREFIX, 120.0), PREFIX)
    assert res.cache_size() == 1
    res.expire(label)
    assert res.cache_size() == 0


def test_pt1_expiry():
    """PT-1: after TTL + grace, 0 of N sampled old addresses resolve; no keys left."""
    store = TenantKeyStore(b"tenant-A", FAST, rand=seeded_rand(11))
    res = Resolver(store)
    sampled = []
    devices = [enroll(store, 0.0) for _ in range(3)]
    for t in range(0, 600, 30):
        res.tick(float(t))
        for label, dev in devices:
            iid = dev.new_iid(PREFIX, float(t))
            assert res.resolve(iid, PREFIX) == label
            sampled.append(iid)
    res.tick(FAST.session_ttl_seconds + FAST.grace_seconds)
    assert len(store) == 0 and store._buffers() == [] and res.cache_size() == 0
    assert sum(res.resolve(i, PREFIX) is not UNBOUND for i in sampled) == 0


def test_grace_still_resolves_last_epoch(store_a):
    res = Resolver(store_a)
    label, dev = enroll(store_a, 0.0)
    for t in range(0, 600, 60):
        dev.tick(float(t))
    iid = dev.new_iid(PREFIX, 599.0)
    res.tick(620.0)                                      # in GRACE
    assert res.resolve(iid, PREFIX) == label
    res.tick(660.0)
    assert res.resolve(iid, PREFIX) is UNBOUND


def test_pt2_cross_tenant(store_a, store_b):
    """PT-2: Tenant B's resolver never resolves Tenant A's traffic; a device enrolled
    in both tenants gets unrelated labels."""
    res_a, res_b = Resolver(store_a), Resolver(store_b)
    a_devs = [enroll(store_a, 0.0) for _ in range(3)]
    b_devs = [enroll(store_b, 0.0) for _ in range(2)]
    false_resolves = 0
    for t in range(0, 600, 15):
        now = float(t)
        res_a.tick(now)
        res_b.tick(now)
        for label, dev in a_devs:
            iid = dev.new_iid(PREFIX, now)
            assert res_a.resolve(iid, PREFIX) == label
            false_resolves += res_b.resolve(iid, PREFIX) is not UNBOUND
        for label, dev in b_devs:
            iid = dev.new_iid(PREFIX, now)
            assert res_b.resolve(iid, PREFIX) == label
            false_resolves += res_a.resolve(iid, PREFIX) is not UNBOUND
    assert false_resolves == 0

    # same physical device enrolled in both tenants
    la, dev_a = enroll(store_a, 0.0)
    lb, dev_b = enroll(store_b, 0.0)
    assert la != lb
    assert la not in store_b.labels() and lb not in store_a.labels()
    assert res_b.resolve(dev_a.new_iid(PREFIX, 0.0), PREFIX) is UNBOUND


def test_pt5_forward_secrecy(store_a):
    """PT-5: the monitor's state at epoch e cannot resolve addresses from before e-1,
    and K_e alone cannot resolve epoch e-1."""
    from mayfly.identity.iid import check_iid
    res = Resolver(store_a)
    label, dev = enroll(store_a, 0.0)
    old = [dev.new_iid(PREFIX, float(t)) for t in range(0, 300, 10)]   # epochs 0..4
    res.tick(420.0)                                                    # e = 7
    assert all(res.resolve(i, PREFIX) is UNBOUND for i in old)
    # an address minted at e-1 resolves only via K_{e-1}, never via K_e
    prev_iid = dev.new_iid(PREFIX, 360.0)                              # epoch 6
    (e, k7), (_, k6) = store_a.get(label).live_keys()
    assert e == 7
    assert check_iid(k6, PREFIX, prev_iid) and not check_iid(k7, PREFIX, prev_iid)
