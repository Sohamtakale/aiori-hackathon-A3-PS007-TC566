"""Detectors (PRD section 9).

FR-D1  sliding-window NS/NA/RS/RA rate per pseudonym label, global thresholds
FR-D3  the same counters keyed by ingress port when the source is UNBOUND
FR-D2  rogue RA rules R1-R4
FR-D4  a resolvable address seen on a second port within its epoch (theft)

Thresholds are global and identical for every device. They are never learned
from a single device's history, since that would be behavioural profiling.
"""

from __future__ import annotations

import ipaddress
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Tuple

from mayfly.nd import NA, NS, RA, RS, NDPacket, TYPE_NAMES

WINDOW_SECONDS = 5.0

# Packets per 5 s window. Initial guesses, to be calibrated on benign traffic
# (benign p99.9 x safety factor, then a sweep) in the evaluation step.
DEFAULT_THRESHOLDS: Dict[str, int] = {"NS": 50, "NA": 50, "RS": 10, "RA": 10}

MEDIUM, HIGH = "medium", "high"


@dataclass
class Alert:
    """FR-U2: label (or port), epoch, message type, port, time. No addresses."""

    t: float                        # monitor clock, seconds since start
    ts: float                       # wall clock (UNIX time)
    detector: str                   # "rate" | "rogue_ra"
    severity: str
    msg_type: str
    port: str
    label: Optional[str] = None
    tenant: Optional[str] = None
    epoch: Optional[int] = None
    count: Optional[int] = None
    threshold: Optional[int] = None
    rules: List[str] = field(default_factory=list)

    @property
    def who(self) -> str:
        return self.label if self.label else "port:" + self.port

    def to_dict(self) -> dict:
        d = asdict(self)
        d["t"], d["ts"] = round(self.t, 3), round(self.ts, 3)
        return {k: v for k, v in d.items() if v not in (None, [])}


# --------------------------------------------------------------------------- rate

class SlidingCounter:
    """Exact count of events in the last ``window`` seconds."""

    __slots__ = ("window", "_times")

    def __init__(self, window: float = WINDOW_SECONDS) -> None:
        self.window = window
        self._times: Deque[float] = deque()

    def add(self, now: float) -> int:
        self._times.append(now)
        return self.count(now)

    def count(self, now: float) -> int:
        cutoff = now - self.window
        q = self._times
        while q and q[0] <= cutoff:
            q.popleft()
        return len(q)


Key = Tuple[str, str]   # ("label", "<tenant>/<label>") or ("port", "<port>")


@dataclass
class Attribution:
    port: str
    label: Optional[str] = None
    tenant: Optional[str] = None
    epoch: Optional[int] = None

    @property
    def key(self) -> Key:
        if self.label:
            return ("label", "%s/%s" % (self.tenant, self.label))
        return ("port", self.port)


class RateDetector:
    """One sliding counter per (pseudonym or port, message type)."""

    COUNTED = (NS, NA, RS, RA)

    def __init__(self, thresholds: Optional[Dict[str, int]] = None,
                 window: float = WINDOW_SECONDS, cooldown: Optional[float] = None) -> None:
        self.thresholds = dict(DEFAULT_THRESHOLDS)
        self.thresholds.update(thresholds or {})
        self.window = window
        self.cooldown = window if cooldown is None else cooldown
        self._counters: Dict[Tuple[Key, int], SlidingCounter] = {}
        self._last_alert: Dict[Tuple[Key, int], float] = {}

    def observe(self, pkt: NDPacket, who: Attribution, now: float, ts: float) -> Optional[Alert]:
        if pkt.msg_type not in self.COUNTED:
            return None
        k = (who.key, pkt.msg_type)
        ctr = self._counters.get(k)
        if ctr is None:
            ctr = self._counters[k] = SlidingCounter(self.window)
        n = ctr.add(now)
        name = TYPE_NAMES[pkt.msg_type]
        limit = self.thresholds[name]
        if n <= limit:
            return None
        last = self._last_alert.get(k)
        if last is not None and now - last < self.cooldown:
            return None
        self._last_alert[k] = now
        # A flood we can pin on a pseudonym is medium; one we can't (spoofed or
        # unenrolled source) is high and leads to port isolation.
        severity = MEDIUM if who.label else HIGH
        return Alert(t=now, ts=ts, detector="rate", severity=severity, msg_type=name,
                     port=who.port, label=who.label, tenant=who.tenant, epoch=who.epoch,
                     count=n, threshold=limit)

    def forget(self, label_keys: Iterable[str]) -> None:
        """Drop counters for expired pseudonyms (nothing outlives the session)."""
        dead = {("label", k) for k in label_keys}
        for k in [k for k in self._counters if k[0] in dead]:
            del self._counters[k]
            self._last_alert.pop(k, None)

    def prune(self, now: float) -> None:
        for k in [k for k, c in self._counters.items() if c.count(now) == 0]:
            del self._counters[k]
        for k in [k for k, t in self._last_alert.items() if now - t > self.cooldown]:
            del self._last_alert[k]


# --------------------------------------------------------------------------- rogue RA

@dataclass(frozen=True)
class RouterPolicy:
    router_port: str
    router_ll: ipaddress.IPv6Address
    allowed_prefixes: Tuple[ipaddress.IPv6Network, ...]


class RogueRADetector:
    """R1 RA from a non-router port; R2 RA source is not the router's link-local;
    R3 advertised prefix outside the allowed set; R4 router lifetime 0 or
    raised (high) preference from a non-router source."""

    def __init__(self, policy: RouterPolicy, cooldown: float = WINDOW_SECONDS) -> None:
        self.policy = policy
        self.cooldown = cooldown
        self._last: Dict[Tuple[str, Tuple[str, ...]], float] = {}
        self._suppressed: Dict[Tuple[str, Tuple[str, ...]], int] = {}

    def rules_hit(self, pkt: NDPacket, port: str) -> List[str]:
        ra = pkt.ra
        if pkt.msg_type != RA or ra is None:
            return []
        p = self.policy
        hits = []
        wrong_port = port != p.router_port
        wrong_src = pkt.src != p.router_ll
        if wrong_port:
            hits.append("R1")
        if wrong_src:
            hits.append("R2")
        if any(not any(pi.prefix.subnet_of(a) for a in p.allowed_prefixes)
               for pi in ra.prefixes if pi.prefix.version == 6):
            hits.append("R3")
        if (wrong_port or wrong_src) and (ra.router_lifetime == 0 or ra.preference == "high"):
            hits.append("R4")
        return hits

    def observe(self, pkt: NDPacket, who: Attribution, now: float, ts: float) -> Optional[Alert]:
        hits = self.rules_hit(pkt, who.port)
        if not hits:
            return None
        k = (who.port, tuple(hits))
        last = self._last.get(k)
        if last is not None and now - last < self.cooldown:
            self._suppressed[k] = self._suppressed.get(k, 0) + 1
            return None
        self._last[k] = now
        count = 1 + self._suppressed.pop(k, 0)
        return Alert(t=now, ts=ts, detector="rogue_ra", severity=HIGH, msg_type="RA",
                     port=who.port, label=who.label, tenant=who.tenant, epoch=who.epoch,
                     count=count, rules=hits)


# --------------------------------------------------------------------------- address theft

class AddressTheftDetector:
    """FR-D4 / T4: a resolvable address seen on a second ingress port within its
    epoch. The replayer floods a victim's address from another port to frame it;
    that the same address appears on two ports is the giveaway. HIGH severity ->
    isolation of the port the replay came from.

    Entries are keyed by (tenant, address) and dropped once the address can no
    longer resolve, so nothing outlives the epoch window it belongs to.
    """

    def __init__(self, hold: float = 2 * WINDOW_SECONDS, cooldown: float = WINDOW_SECONDS) -> None:
        self.cooldown = cooldown
        # (tenant, address) -> (first_port, label, epoch, expire_at)
        self._seen: Dict[Tuple[str, bytes], Tuple[str, str, int, float]] = {}
        self._last_alert: Dict[Tuple[str, bytes], float] = {}

    def observe(self, address: bytes, who: Attribution, epoch_end: float,
                now: float, ts: float) -> Optional[Alert]:
        if not who.label:                      # only resolvable (owned) addresses can be stolen
            return None
        key = (who.tenant, bytes(address))
        prev = self._seen.get(key)
        if prev is None:
            self._seen[key] = (who.port, who.label, who.epoch, epoch_end)
            return None
        first_port, label, epoch, _ = prev
        self._seen[key] = (first_port, label, epoch, max(prev[3], epoch_end))
        if who.port == first_port:
            return None
        last = self._last_alert.get(key)
        if last is not None and now - last < self.cooldown:
            return None
        self._last_alert[key] = now
        # The real device is on first_port; the replay arrives on who.port -> isolate who.port.
        return Alert(t=now, ts=ts, detector="theft", severity=HIGH, msg_type="NS",
                     port=who.port, label=label, tenant=who.tenant, epoch=epoch,
                     rules=["seen_on:" + first_port])

    def prune(self, now: float) -> None:
        for k in [k for k, v in self._seen.items() if now >= v[3]]:
            del self._seen[k]
            self._last_alert.pop(k, None)

    def forget(self, tenant_labels: Iterable[Tuple[str, str]]) -> None:
        drop = set(tenant_labels)
        for k in [k for k, v in self._seen.items() if (v[1] and (k[0], v[1]) in drop)]:
            del self._seen[k]
            self._last_alert.pop(k, None)
