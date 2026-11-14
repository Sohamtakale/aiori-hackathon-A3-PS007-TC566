"""Deterministic in-process ND traffic model and the S0-S7 scenarios (PRD 11).

No namespaces or root: the model enrolls devices with a real Monitor, mints the
same resolvable addresses the lab would, and emits NDPacket events straight to
the detectors. Everything is seeded, so a scenario is reproducible (FR-H1).

Each device's address rotations are planned in time order first (a DeviceIdentity
only ratchets forward), then benign and attack events reference the address that
was current at each moment.

build() yields:
  events   sorted [(t, NDPacket, port, EvTag)]        -- fed to Mayfly, B1, B2
  episodes [Episode(start, end, kind, device, port)]  -- attack ground truth
  owners   {address_str: device}                      -- for B1 attribution scoring
  mon      the Monitor the devices enrolled with       -- Mayfly under test
  labels   {device: pseudonym}
"""

from __future__ import annotations

import bisect
import ipaddress
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from mayfly.identity import DeviceEnrollment, DeviceIdentity, Response, join_address, prefix_from_network
from mayfly.monitor import Monitor
from mayfly.nd import NA, NS, RA, RS, NDPacket, PrefixInfo, RAInfo
from mayfly.detectors import RouterPolicy
from mayfly.params import Params

PREFIX_STR = "fd4d:6179:666c:1::/64"
PREFIX = prefix_from_network(PREFIX_STR)
ROUTER_LL = "fe80::1"
ROUTER_MAC = "02:4d:46:00:00:fe"
ATTACKER_MAC = "02:4d:46:00:00:66"
TENANTS = {"d1": "A", "d2": "A", "d3": "A", "d4": "B", "d5": "B"}
PORTS = {d: "v" + d for d in TENANTS}
PORTS["router"] = "vrouter"
PORTS["attacker"] = "vattacker"
TARGET = ipaddress.IPv6Address("fd4d:6179:666c:1::1")
MCAST = ipaddress.IPv6Address("ff02::1")


@dataclass
class EvTag:
    attack: bool = False
    device: Optional[str] = None


@dataclass
class Episode:
    start: float
    end: float
    kind: str
    device: Optional[str]
    port: str


@dataclass
class ScenarioConfig:
    duration: float = 120.0
    epoch: float = 60.0
    ttl: float = 1800.0
    benign_ns_rate: float = 0.2        # per device, NS/sec (address resolution)
    benign_rotate: Tuple[float, float] = (20.0, 40.0)
    ra_interval: float = 5.0
    attack_rate: float = 20.0          # attacker packets/sec
    attack_rotate: float = 1.0         # S4 attacker address rotation interval
    attack_start: float = 40.0
    attack_len: float = 50.0


def _mac(dev: str) -> str:
    return {"router": ROUTER_MAC, "attacker": ATTACKER_MAC}.get(dev, "02:4d:46:00:00:%02x" % int(dev[1:]))


def ns(src, mac, k=0) -> NDPacket:
    return NDPacket(NS, ipaddress.IPv6Address(src), MCAST, 255, mac,
                    target=ipaddress.IPv6Address(int(TARGET) + (k & 0xff)))


def na(src, mac) -> NDPacket:
    return NDPacket(NA, ipaddress.IPv6Address(src), MCAST, 255, mac, target=ipaddress.IPv6Address(src))


def rs(mac) -> NDPacket:
    return NDPacket(RS, ipaddress.IPv6Address("::"), ipaddress.IPv6Address("ff02::2"), 255, mac)


def ra(src_ll, mac, prefix, lifetime=1800, preference="medium") -> NDPacket:
    net = ipaddress.IPv6Network(prefix + "/64", strict=False)
    info = RAInfo(64, False, False, preference, lifetime,
                  (PrefixInfo(net, True, True, 3600, 1800),), mac)
    return NDPacket(RA, ipaddress.IPv6Address(src_ll), MCAST, 255, mac, ra=info)


class TrafficModel:
    def __init__(self, cfg: ScenarioConfig, seed: int) -> None:
        self.cfg = cfg
        self.rng = random.Random("mayfly-eval/%d" % seed)
        self.key_rng = random.Random("keys/%d" % seed)
        policy = RouterPolicy(PORTS["router"], ipaddress.IPv6Address(ROUTER_LL),
                              (ipaddress.IPv6Network(PREFIX_STR),))
        params = Params(epoch_seconds=cfg.epoch, session_ttl_seconds=cfg.ttl, grace_epochs=1)
        self._clock = 0.0
        self.mon = Monitor({"A": b"tenant-A", "B": b"tenant-B"}, params, policy,
                           clock=lambda: self._clock, wall=lambda: 1.7e9)
        self.params = params
        self.identities: Dict[str, DeviceIdentity] = {}
        self.enrolled_at: Dict[str, float] = {}
        self.labels: Dict[str, str] = {}
        self.schedule: Dict[str, List[Tuple[float, str]]] = {}   # sorted (t, addr)
        self.owners: Dict[str, str] = {}
        self.events: List[Tuple[float, NDPacket, str, EvTag]] = []

    # --------------------------------------------------- enrollment / addresses
    def enroll(self, dev: str, tenant: str, at: float = 0.0) -> None:
        self._clock = at
        store = self.mon.stores[tenant]
        tok = store.issue_token()
        d = DeviceEnrollment(tok, self.key_rng.randbytes)
        _, resp = self.mon.enrollment.handle(b"H", d.hello().to_bytes())
        confirm, k0 = d.finish(Response.from_bytes(resp))
        _, label = self.mon.enrollment.handle(b"C", confirm.to_bytes())
        self.labels[dev] = label.decode()
        self.identities[dev] = DeviceIdentity(k0, at, self.params, self.key_rng.randbytes)
        self.enrolled_at[dev] = at

    def plan_rotations(self, dev: str, times: List[float]) -> None:
        """Mint one address per rotation time (ascending), recording the schedule."""
        ident = self.identities[dev]
        sched = []
        for t in sorted(times):
            addr = str(join_address(PREFIX, ident.new_iid(PREFIX, t)))
            sched.append((t, addr))
            self.owners[addr] = dev
        self.schedule[dev] = sched

    def addr_at(self, dev: str, t: float) -> str:
        sched = self.schedule[dev]
        i = bisect.bisect_right([s[0] for s in sched], t) - 1
        return sched[max(0, i)][1]

    def benign_rotation_times(self, dev: str) -> List[float]:
        times = [self.enrolled_at.get(dev, 0.0)]
        t = times[0]
        while t < self.cfg.duration:
            t += self.rng.uniform(*self.cfg.benign_rotate)
            if t < self.cfg.duration:
                times.append(t)
        return times

    def emit(self, t: float, pkt: NDPacket, port: str, attack=False, device=None) -> None:
        self.events.append((t, pkt, port, EvTag(attack, device)))

    # --------------------------------------------------- benign background
    def benign_background(self, devices: List[str]) -> None:
        c = self.cfg
        t = 0.0
        while t < c.duration:
            self.emit(t, ra(ROUTER_LL, ROUTER_MAC, "fd4d:6179:666c:1::"), PORTS["router"])
            t += c.ra_interval * self.rng.uniform(0.8, 1.2)
        for dev in devices:
            self._benign_device(dev)

    def _benign_device(self, dev: str) -> None:
        c = self.cfg
        mac = _mac(dev)
        self.emit(0.2, rs(mac), PORTS[dev])
        for t, _ in self.schedule[dev]:
            self.emit(t, ns("::", mac), PORTS[dev])             # DAD on each new address
        t = self.rng.uniform(0, 2)
        while t < c.duration:
            self.emit(t, ns(self.addr_at(dev, t), mac, self.rng.randint(0, 5)), PORTS[dev])
            t += self.rng.expovariate(c.benign_ns_rate)


def _poisson_times(rng, rate, start, length):
    t = start
    while True:
        t += rng.expovariate(rate)
        if t >= start + length:
            return
        yield t


def _attack_rotation_times(start, length, interval):
    t, out = start, []
    while t < start + length:
        out.append(t)
        t += interval
    return out


# --------------------------------------------------------------------------- scenarios

def build(name: str, seed: int, cfg: Optional[ScenarioConfig] = None):
    cfg = cfg or ScenarioConfig()
    m = TrafficModel(cfg, seed)
    rng = m.rng
    s, L = cfg.attack_start, cfg.attack_len
    benign_devices = list(TENANTS)

    # enroll
    for dev, tenant in TENANTS.items():
        m.enroll(dev, tenant, at=(s if (name == "S4" and dev == "d1") else 0.0))

    # plan each device's address rotations (benign + any attacker rotations merged)
    attack_rot_times = _attack_rotation_times(s, L, cfg.attack_rotate)
    for dev in TENANTS:
        if name == "S4" and dev == "d1":
            m.plan_rotations(dev, attack_rot_times)      # pure attacker, fast rotation
            benign_devices.remove("d1")
        elif name == "S7" and dev == "d1":
            m.plan_rotations(dev, m.benign_rotation_times(dev) + attack_rot_times)
        else:
            m.plan_rotations(dev, m.benign_rotation_times(dev))

    m.benign_background(benign_devices)
    episodes: List[Episode] = []

    if name in ("S0", "S1", "S2"):
        if name == "S1":
            for burst in (s, s + 10, s + 20):
                for dev in benign_devices:
                    m.emit(burst + rng.uniform(0, 0.5), ns("::", _mac(dev)), PORTS[dev])
        if name == "S2":
            for dev in benign_devices:
                b = s + rng.uniform(0, 1)
                m.emit(b, rs(_mac(dev)), PORTS[dev])
                for _ in range(rng.randint(3, 6)):
                    m.emit(b + rng.uniform(0, 2), ns("::", _mac(dev)), PORTS[dev])

    elif name == "S3":
        for t in _poisson_times(rng, 5.0, s, L):
            v = rng.choice(["hijack", "kill", "flood"])
            if v == "hijack":
                pkt = ra("fe80::66", ATTACKER_MAC, "2001:db8:bad::", 1800, "high")
            elif v == "kill":
                pkt = ra("fe80::66", ATTACKER_MAC, "fd4d:6179:666c:1::", 0, "medium")
            else:
                pkt = ra("fe80::66", ATTACKER_MAC, "fd4d:6179:666c:1::", 1800, "medium")
            m.emit(t, pkt, PORTS["attacker"], attack=True, device="attacker")
        episodes.append(Episode(s, s + L, "rogue_ra", "attacker", PORTS["attacker"]))

    elif name == "S4":
        for t in _poisson_times(rng, cfg.attack_rate, s, L):
            m.emit(t, ns(m.addr_at("d1", t), _mac("d1"), rng.randint(0, 20)), PORTS["d1"],
                   attack=True, device="d1")
        episodes.append(Episode(s, s + L, "rotating_flood", "d1", PORTS["d1"]))

    elif name == "S5":
        for t in _poisson_times(rng, cfg.attack_rate, s, L):
            src = "fd4d:6179:666c:1:" + ":".join("%04x" % rng.randint(0, 0xffff) for _ in range(4))
            m.owners[src] = "attacker"
            m.emit(t, ns(src, ATTACKER_MAC, rng.randint(0, 20)), PORTS["attacker"],
                   attack=True, device="attacker")
        episodes.append(Episode(s, s + L, "spoof_flood", "attacker", PORTS["attacker"]))

    elif name == "S6":
        for t in _poisson_times(rng, cfg.attack_rate, s, L):
            m.emit(t, ns(m.addr_at("d2", t), ATTACKER_MAC, rng.randint(0, 20)), PORTS["attacker"],
                   attack=True, device="attacker")
        episodes.append(Episode(s, s + L, "replay", "attacker", PORTS["attacker"]))

    elif name == "S7":
        for t in _poisson_times(rng, 4.0, s, L):
            m.emit(t, ra("fe80::66", ATTACKER_MAC, "2001:db8:bad::", 1800, "high"),
                   PORTS["attacker"], attack=True, device="attacker")
        for t in _poisson_times(rng, cfg.attack_rate, s, L):
            m.emit(t, ns(m.addr_at("d1", t), _mac("d1"), rng.randint(0, 20)), PORTS["d1"],
                   attack=True, device="d1")
        episodes.append(Episode(s, s + L, "rogue_ra", "attacker", PORTS["attacker"]))
        episodes.append(Episode(s, s + L, "rotating_flood", "d1", PORTS["d1"]))
    else:
        raise ValueError("unknown scenario %r" % name)

    m.events.sort(key=lambda e: e[0])
    return m.events, episodes, m.owners, m.mon, m.labels


SCENARIOS = ["S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"]
SCENARIO_DESC = {
    "S0": "benign steady state", "S1": "benign rotation storm", "S2": "reboot/power-on storm",
    "S3": "rogue RA (hijack/kill/flood)", "S4": "compromised device floods while rotating",
    "S5": "unenrolled spoof flood", "S6": "address theft replay", "S7": "mixed benign + attack",
}
