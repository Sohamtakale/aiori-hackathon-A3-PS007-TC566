"""Resolvable ephemeral interface identifiers (FR-K2).

    IID = prand (32 bit) || HMAC-SHA256(K_e, 'iid' || prefix || prand)[:4]

Without K_e the IID is indistinguishable from a random 64-bit value. IIDs that
fall in reserved ranges (RFC 5453) are skipped by drawing a fresh prand.

Open question (PRD section 8 / 19.6): RFC 7136 says the u/g bits carry no
meaning in IIDs, so all 64 bits are used here. If review decides otherwise,
the fallback is a 30-bit prand with 2 fixed bits.
"""

from __future__ import annotations

import hmac
import ipaddress
from hashlib import sha256
from typing import Tuple, Union

from mayfly.identity.keys import RandFn, default_rand
from mayfly.params import IID_LEN, PRAND_LEN, PREFIX_LEN, TAG_DOMAIN, TAG_LEN

_PROXY_MIP6_PREFIX = bytes.fromhex("02005efffe00")  # 0200:5EFF:FE00:0000/48 block, RFC 5453
_SUBNET_ANYCAST_MIN = int("fdffffffffffff80", 16)   # RFC 2526 reserved anycast


def _check_prefix(prefix: bytes) -> None:
    if len(prefix) != PREFIX_LEN:
        raise ValueError("prefix must be %d bytes (a /64)" % PREFIX_LEN)


def compute_tag(key: bytes | bytearray, prefix: bytes, prand: bytes) -> bytes:
    _check_prefix(prefix)
    if len(prand) != PRAND_LEN:
        raise ValueError("prand must be %d bytes" % PRAND_LEN)
    return hmac.new(bytes(key), TAG_DOMAIN + prefix + prand, sha256).digest()[:TAG_LEN]


def is_reserved_iid(iid: bytes) -> bool:
    if len(iid) != IID_LEN:
        raise ValueError("iid must be %d bytes" % IID_LEN)
    value = int.from_bytes(iid, "big")
    return value == 0 or value >= _SUBNET_ANYCAST_MIN or iid[:6] == _PROXY_MIP6_PREFIX


def make_iid(key: bytes | bytearray, prefix: bytes, rand: RandFn = default_rand) -> bytes:
    """Fresh resolvable IID for the given key and /64 prefix."""
    while True:
        prand = rand(PRAND_LEN)
        iid = prand + compute_tag(key, prefix, prand)
        if not is_reserved_iid(iid):
            return iid


def check_iid(key: bytes | bytearray, prefix: bytes, iid: bytes) -> bool:
    if len(iid) != IID_LEN:
        return False
    prand, tag = iid[:PRAND_LEN], iid[PRAND_LEN:]
    return hmac.compare_digest(compute_tag(key, prefix, prand), tag)


AddressLike = Union[str, ipaddress.IPv6Address]


def split_address(addr: AddressLike) -> Tuple[bytes, bytes]:
    """IPv6 address -> (8-byte /64 prefix, 8-byte IID)."""
    packed = ipaddress.IPv6Address(addr).packed
    return packed[:PREFIX_LEN], packed[PREFIX_LEN:]


def join_address(prefix: bytes, iid: bytes) -> ipaddress.IPv6Address:
    _check_prefix(prefix)
    if len(iid) != IID_LEN:
        raise ValueError("iid must be %d bytes" % IID_LEN)
    return ipaddress.IPv6Address(prefix + iid)


def prefix_from_network(net: str) -> bytes:
    """'2001:db8:1::/64' -> 8 prefix bytes."""
    n = ipaddress.IPv6Network(net)
    if n.prefixlen != 64:
        raise ValueError("Mayfly IIDs need a /64 prefix")
    return n.network_address.packed[:PREFIX_LEN]
