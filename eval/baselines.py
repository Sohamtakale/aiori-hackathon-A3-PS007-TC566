"""Baseline detectors for comparison (PRD FR-H2, section 11).

B1 per-address rate: a sliding-window NS/NA/RS/RA counter keyed by the packet's
   source address. This is the naive detector Mayfly is measured against: it
   degrades as an attacker rotates addresses faster, because each short-lived
   address stays under the threshold while the aggregate does not.

B2 per-port rate: the same counter keyed by ingress port. It catches a flood
   from one port but cannot attribute it to a device and is blind to which of
   several devices behind a port is the offender.

Both use the same window and thresholds as Mayfly, so the comparison is fair.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from mayfly.detectors import DEFAULT_THRESHOLDS, SlidingCounter, WINDOW_SECONDS
from mayfly.nd import NA, NS, RA, RS, NDPacket, TYPE_NAMES


@dataclass
class BaseAlert:
    t: float
    key: str                # the address (B1) or port (B2) that tripped
    msg_type: str
    count: int


class _RateBaseline:
    COUNTED = (NS, NA, RS, RA)

    def __init__(self, thresholds=None, window: float = WINDOW_SECONDS,
                 cooldown: Optional[float] = None) -> None:
        self.thresholds = dict(DEFAULT_THRESHOLDS)
        self.thresholds.update(thresholds or {})
        self.window = window
        self.cooldown = window if cooldown is None else cooldown
        self._counters: Dict[tuple, SlidingCounter] = {}
        self._last: Dict[tuple, float] = {}

    def _key(self, pkt: NDPacket, port: str) -> Optional[str]:
        raise NotImplementedError

    def observe(self, pkt: NDPacket, port: str, now: float) -> Optional[BaseAlert]:
        if pkt.msg_type not in self.COUNTED:
            return None
        key = self._key(pkt, port)
        if key is None:
            return None
        ck = (key, pkt.msg_type)
        ctr = self._counters.get(ck)
        if ctr is None:
            ctr = self._counters[ck] = SlidingCounter(self.window)
        n = ctr.add(now)
        if n <= self.thresholds[TYPE_NAMES[pkt.msg_type]]:
            return None
        last = self._last.get(ck)
        if last is not None and now - last < self.cooldown:
            return None
        self._last[ck] = now
        return BaseAlert(now, key, TYPE_NAMES[pkt.msg_type], n)

    def prune(self, now: float) -> None:
        for k in [k for k, c in self._counters.items() if c.count(now) == 0]:
            del self._counters[k]
            self._last.pop(k, None)


class B1PerAddress(_RateBaseline):
    name = "B1-per-address"

    def _key(self, pkt: NDPacket, port: str) -> Optional[str]:
        src = pkt.src
        if src.is_unspecified or src.is_multicast:
            return None
        return str(src)


class B2PerPort(_RateBaseline):
    name = "B2-per-port"

    def _key(self, pkt: NDPacket, port: str) -> str:
        return port
