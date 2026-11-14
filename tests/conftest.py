import random
from typing import Callable, Tuple

import pytest

from mayfly.identity import DeviceEnrollment, DeviceIdentity
from mayfly.identity.iid import prefix_from_network
from mayfly.keystore import TenantKeyStore
from mayfly.params import Params

PREFIX = prefix_from_network("2001:db8:1::/64")
OTHER_PREFIX = prefix_from_network("2001:db8:2::/64")

# Small, round numbers keep the time arithmetic readable: 10 epochs then 1 grace epoch.
FAST = Params(epoch_seconds=60.0, session_ttl_seconds=600.0, grace_epochs=1,
              max_resync_epochs=3, enroll_timeout_seconds=30.0)


def seeded_rand(seed: int) -> Callable[[int], bytes]:
    r = random.Random(seed)
    return lambda n: r.randbytes(n)


def enroll(store: TenantKeyStore, now: float, rand=None) -> Tuple[str, DeviceIdentity]:
    tok = store.issue_token()
    dev = DeviceEnrollment(tok) if rand is None else DeviceEnrollment(tok, rand)
    resp = store.handle_hello(dev.hello(), now)
    confirm, k0 = dev.finish(resp)
    label = store.handle_confirm(confirm, now)
    kw = {} if rand is None else {"rand": rand}
    return label, DeviceIdentity(k0, now, store.params, **kw)


@pytest.fixture
def store_a() -> TenantKeyStore:
    return TenantKeyStore(b"tenant-A", FAST)


@pytest.fixture
def store_b() -> TenantKeyStore:
    return TenantKeyStore(b"tenant-B", FAST)
