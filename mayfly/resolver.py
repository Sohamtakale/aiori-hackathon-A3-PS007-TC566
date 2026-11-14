"""Resolver (FR-R1, FR-R2, FR-R3): address -> pseudonym label, or UNBOUND.

    resolve(iid, prefix):
        prand, tag = iid[:4], iid[4:]
        for (label, K) in store.live_keys(epochs=[e, e-1]):
            if HMAC(K, 'iid' || prefix || prand)[:4] == tag: return label
        return UNBOUND

One ``Resolver`` per tenant, bound to that tenant's key store only. A small
cache maps (prefix, iid) to the match; an entry is dropped as soon as the epoch
it matched leaves the live window {e, e-1} or its session expires.
"""

from __future__ import annotations

from typing import Dict, List, NamedTuple, Optional, Tuple, Union

from mayfly.identity.iid import AddressLike, check_iid, split_address
from mayfly.keystore import TenantKeyStore


class _Unbound:
    """Falsy sentinel so callers can write ``resolve(...) or port``."""

    _instance: Optional["_Unbound"] = None

    def __new__(cls) -> "_Unbound":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "UNBOUND"


UNBOUND = _Unbound()


class Match(NamedTuple):
    label: str
    epoch: int


class Resolver:
    def __init__(self, store: TenantKeyStore) -> None:
        self.store = store
        self._cache: Dict[Tuple[bytes, bytes], Match] = {}

    @property
    def tenant_id(self) -> bytes:
        return self.store.tenant_id

    def match(self, iid: bytes, prefix: bytes) -> Optional[Match]:
        key = (bytes(prefix), bytes(iid))
        hit = self._cache.get(key)
        if hit is not None:
            if self._valid(hit):
                return hit
            del self._cache[key]
        for label, epoch, k in self.store.live_keys():
            if check_iid(k, prefix, iid):
                m = Match(label, epoch)
                self._cache[key] = m
                return m
        return None

    def resolve(self, iid: bytes, prefix: bytes) -> Union[str, _Unbound]:
        m = self.match(iid, prefix)
        return UNBOUND if m is None else m.label

    def resolve_address(self, addr: AddressLike) -> Union[str, _Unbound]:
        prefix, iid = split_address(addr)
        return self.resolve(iid, prefix)

    def tick(self, now: float) -> List[str]:
        """Advance the key store, drop stale cache entries; returns expired labels."""
        gone = self.store.tick(now)
        self.purge()
        return gone

    def expire(self, label: str) -> bool:
        ok = self.store.expire(label)
        self.purge()
        return ok

    def purge(self) -> None:
        for k in [k for k, m in self._cache.items() if not self._valid(m)]:
            del self._cache[k]

    def cache_size(self) -> int:
        return len(self._cache)

    def _valid(self, m: Match) -> bool:
        s = self.store.get(m.label)
        return s is not None and any(e == m.epoch for e, _ in s.live_keys())
