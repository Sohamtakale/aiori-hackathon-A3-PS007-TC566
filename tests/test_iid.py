import hmac
import ipaddress
from hashlib import sha256

import pytest

from mayfly.identity import iid as iidmod
from mayfly.identity.iid import (check_iid, compute_tag, is_reserved_iid, join_address, make_iid,
                                 prefix_from_network, split_address)

from conftest import OTHER_PREFIX, PREFIX, seeded_rand

KEY = bytearray(b"k" * 32)
KEY2 = bytearray(b"j" * 32)


def test_layout_matches_spec():
    prand = bytes.fromhex("01020304")
    tag = hmac.new(bytes(KEY), b"iid" + PREFIX + prand, sha256).digest()[:4]
    assert compute_tag(KEY, PREFIX, prand) == tag
    iid = make_iid(KEY, PREFIX, rand=lambda n: prand)
    assert iid == prand + tag and len(iid) == 8


def test_roundtrip_and_rejections():
    rand = seeded_rand(1)
    for _ in range(500):
        iid = make_iid(KEY, PREFIX, rand)
        assert check_iid(KEY, PREFIX, iid)
        assert not check_iid(KEY2, PREFIX, iid)
        assert not check_iid(KEY, OTHER_PREFIX, iid)
    assert not check_iid(KEY, PREFIX, b"short")


def test_fresh_prand_every_call():
    iids = {make_iid(KEY, PREFIX) for _ in range(200)}
    assert len(iids) == 200


def test_reserved_ranges():
    assert is_reserved_iid(bytes(8))
    assert is_reserved_iid(bytes.fromhex("fdffffffffffff80"))
    assert is_reserved_iid(bytes.fromhex("ffffffffffffffff"))
    assert is_reserved_iid(bytes.fromhex("02005efffe005213"))
    assert not is_reserved_iid(bytes.fromhex("fdffffffffffff7f"))
    assert not is_reserved_iid(bytes.fromhex("0123456789abcdef"))


def test_reserved_iid_is_redrawn(monkeypatch):
    calls = {"n": 0}
    real = iidmod.is_reserved_iid

    def first_is_reserved(iid):
        calls["n"] += 1
        return calls["n"] == 1 or real(iid)

    monkeypatch.setattr(iidmod, "is_reserved_iid", first_is_reserved)
    iid = make_iid(KEY, PREFIX, seeded_rand(2))
    assert calls["n"] == 2 and check_iid(KEY, PREFIX, iid)


def test_address_helpers():
    addr = join_address(PREFIX, bytes.fromhex("0123456789abcdef"))
    assert addr == ipaddress.IPv6Address("2001:db8:1::123:4567:89ab:cdef")
    assert split_address(str(addr)) == (PREFIX, bytes.fromhex("0123456789abcdef"))
    with pytest.raises(ValueError):
        prefix_from_network("2001:db8::/48")
    with pytest.raises(ValueError):
        compute_tag(KEY, b"\x00" * 7, b"\x00" * 4)
