#!/usr/bin/env python3
"""Address rotation emulator (FR-E2, FR-K3). Writes a ground-truth log.

Modes
-----
scripted (default)
    Each device enrolls with the monitor, then on a jittered timer mints a new
    resolvable Mayfly IID, adds it, and deprecates the previous address
    (RFC 8981 style overlap). Deprecated addresses are removed before they
    leave the resolver's {e, e-1} window. Kernel SLAAC is switched off on the
    device (autoconf=0) so its only global addresses are Mayfly addresses.

    Rotation interval ~ U[min_interval, max_interval] with max_interval <=
    epoch, so every address is resolvable for its whole life (decision (a)
    from step 1). Sessions that hit their TTL re-enroll with a new label.

kernel
    Linux privacy extensions (use_tempaddr=2) with shortened lifetimes do the
    rotating; the emulator only observes and logs. These addresses are plain
    random IIDs, so they are UNBOUND to the monitor by design.

Monitor
-------
Until the monitor exists (step 4) enrollment goes to an in-process monitor
(``LocalMonitor``) which also writes resolver.jsonl, so FR-K3 ("rotation log
matches resolver log") can be checked with lab/verify_rotation.py.

Output: runs/<timestamp>-<mode>-s<seed>/rotation.jsonl (+ resolver.jsonl).
These are evaluation ground truth and contain raw addresses; they are not
monitor logs and are git-ignored.

    sudo .venv/bin/python lab/rotation.py --duration 300 --seed 1
    .venv/bin/python lab/rotation.py --dry-run --duration 300     # no root, simulated
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import random
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, TextIO

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lab.netops import FakeNet, IpNetns, NetOps
from lab.topology import Topology
from mayfly.identity import (DeviceEnrollment, DeviceIdentity, ResyncRequired, SessionExpired,
                             join_address, prefix_from_network)
from mayfly.keystore import TenantKeyStore
from mayfly.params import Params
from mayfly.enrollsvc import EnrollClient
from mayfly.resolver import UNBOUND, Resolver

REPO = Path(__file__).resolve().parent.parent
REMOVE_MARGIN = 1.0      # remove deprecated addresses this long before they stop resolving
SAFETY_LFT = 2           # extra seconds on kernel lifetimes, in case the emulator dies
ROTATE_LEAD = 2.0        # rotate at least this long before the current address must go, so the
                         # successor has finished DAD (~1 s) before its predecessor is removed


# --------------------------------------------------------------------------- logging

class JsonlLog:
    def __init__(self, fh: Optional[TextIO]) -> None:
        self._fh = fh
        self.records: List[dict] = []

    def write(self, **rec) -> None:
        if "t" in rec:
            rec["t"] = round(rec["t"], 3)
        self.records.append(rec)
        if self._fh is not None:
            self._fh.write(json.dumps(rec, sort_keys=True) + "\n")
            self._fh.flush()


# --------------------------------------------------------------------------- monitor stand-in

class LocalMonitor:
    """In-process key stores + resolvers, one per tenant (replaced by the real
    monitor's enrollment endpoint in step 4)."""

    def __init__(self, params: Params, rand: Callable[[int], bytes]) -> None:
        self.params = params
        self._rand = rand
        self.stores = {t: TenantKeyStore(("tenant-" + t).encode(), params, rand) for t in ("A", "B")}
        self.resolvers = {t: Resolver(s) for t, s in self.stores.items()}

    def enroll(self, tenant: str, now: float):
        store = self.stores[tenant]
        dev = DeviceEnrollment(store.issue_token(), self._rand)
        resp = store.handle_hello(dev.hello(), now)
        confirm, k0 = dev.finish(resp)
        label = store.handle_confirm(confirm, now)
        return label, DeviceIdentity(k0, now, self.params, self._rand)

    def tick(self, now: float) -> None:
        for r in self.resolvers.values():
            r.tick(now)

    def resolve(self, tenant: str, addr: str) -> Optional[str]:
        res = self.resolvers[tenant].resolve_address(addr)
        return None if res is UNBOUND else res


class RemoteMonitor:
    """Enrolls devices with the running monitor over its UNIX socket. The device
    starts its epoch clock only after the handshake, so it never runs ahead of
    the monitor (which starts its clock at HELLO)."""

    def __init__(self, path: str, params: Params, rand: Callable[[int], bytes],
                 clock: Callable[[], float]) -> None:
        self.path, self.params, self._rand, self.clock = path, params, rand, clock

    def enroll(self, tenant: str, now: float):
        with EnrollClient(self.path) as client:
            token, mp = client.issue_token(tenant)
            mine = (self.params.epoch_seconds, self.params.session_ttl_seconds, self.params.grace_epochs)
            theirs = (mp.epoch_seconds, mp.session_ttl_seconds, mp.grace_epochs)
            if mine != theirs:
                raise ValueError("monitor uses epoch/ttl/grace %s but the emulator %s; pass the same "
                                 "--epoch/--ttl/--grace to both" % (theirs, mine))
            dev = DeviceEnrollment(token, self._rand)
            confirm, k0 = dev.finish(client.hello(dev.hello()))
            label = client.confirm(confirm)
        return label, DeviceIdentity(k0, max(now, self.clock()), self.params, self._rand)

    def tick(self, now: float) -> None:
        pass  # the monitor runs its own clock

    def resolve(self, tenant: str, addr: str) -> Optional[str]:
        return None  # not available: the monitor offers no resolve oracle


# --------------------------------------------------------------------------- scripted mode

@dataclass
class Addr:
    addr: str
    label: Optional[str]
    epoch: int
    minted: float
    remove_at: float
    deprecate_at: Optional[float] = None    # scheduled once a successor exists
    deprecated_at: Optional[float] = None


@dataclass
class Device:
    name: str
    tenant: str
    prefix: bytes = b""
    session: int = 0
    label: Optional[str] = None
    identity: Optional[DeviceIdentity] = None
    enrolled_at: float = 0.0
    current: Optional[Addr] = None
    old: List[Addr] = field(default_factory=list)
    next_rotation: float = 0.0


class ScriptedRotation:
    def __init__(self, topo: Topology, net: NetOps, monitor: "LocalMonitor | RemoteMonitor", params: Params,
                 log: JsonlLog, resolver_log: Optional[JsonlLog], seed: int,
                 min_interval: float, max_interval: float,
                 devices: Optional[List[str]] = None) -> None:
        if not 0 < min_interval <= max_interval:
            raise ValueError("need 0 < min_interval <= max_interval")
        if params.epoch_seconds < 3 * ROTATE_LEAD:
            raise ValueError("epoch must be at least %gs" % (3 * ROTATE_LEAD))
        if max_interval > params.epoch_seconds:
            raise ValueError("max_interval (%gs) must not exceed the epoch (%gs): addresses would "
                             "outlive the resolver's {e, e-1} window" % (max_interval, params.epoch_seconds))
        self.topo, self.net, self.monitor, self.params = topo, net, monitor, params
        self.log, self.rlog = log, resolver_log
        self.rng = random.Random("rotation/%d" % seed)
        self.min_interval, self.max_interval = min_interval, max_interval
        names = devices or topo.devices
        self.devices = [Device(n, topo.tenants[n]) for n in names]

    # ----------------------------------------------------------- lifecycle
    def start(self, now: float) -> None:
        for d in self.devices:
            self.net.set_sysctl(d.name, "net.ipv6.conf.eth0.autoconf", "0")
            self.net.set_sysctl(d.name, "net.ipv6.conf.eth0.use_tempaddr", "0")
            self.net.flush_global(d.name)
            prefix = self.net.ra_prefix(d.name) or self.topo.prefix
            d.prefix = prefix_from_network(prefix)
            self._enroll(d, now)
            self._rotate(d, now)

    def step(self, now: float) -> None:
        self.monitor.tick(now)
        for d in self.devices:
            assert d.identity is not None
            try:
                d.identity.tick(now)
            except (SessionExpired, ResyncRequired) as exc:
                self._end_session(d, now, "ttl" if isinstance(exc, SessionExpired) else "resync")
                self._enroll(d, now)
                self._rotate(d, now)
            if now >= d.next_rotation:
                self._rotate(d, now)
            for a in d.old:
                if a.deprecated_at is None and a.deprecate_at is not None and now >= a.deprecate_at:
                    self._deprecate(d, a, now)
            for a in [a for a in d.old if now >= a.remove_at]:
                self._remove(d, a, now, "window")

    def stop(self, now: float) -> None:
        for d in self.devices:
            for a in list(d.old) + ([d.current] if d.current else []):
                self._remove(d, a, now, "shutdown")
            d.current = None
            if d.identity is not None:
                d.identity.erase()
            try:
                self.net.flush_global(d.name)
                self.net.set_sysctl(d.name, "net.ipv6.conf.eth0.autoconf", "1")
            except (subprocess.CalledProcessError, ValueError):
                pass
        self.log.write(event="stop", t=now)

    # ----------------------------------------------------------- actions
    def _enroll(self, d: Device, now: float) -> None:
        d.label, d.identity = self.monitor.enroll(d.tenant, now)
        d.enrolled_at = d.identity.enrolled_at
        d.session += 1
        self.log.write(event="enroll", t=now, device=d.name, tenant=d.tenant, label=d.label,
                       session=d.session)

    def _end_session(self, d: Device, now: float, reason: str) -> None:
        # The last address stays current until the new session's first address is
        # ready; _rotate() then retires it like any other.
        self.log.write(event="session_end", t=now, device=d.name, label=d.label,
                       session=d.session, reason=reason)

    def _window_end(self, d: Device, epoch: int) -> float:
        p = self.params
        horizon = min((epoch + 2) * p.epoch_seconds, p.session_ttl_seconds + p.grace_seconds)
        return d.enrolled_at + horizon - REMOVE_MARGIN

    def _rotate(self, d: Device, now: float) -> None:
        assert d.identity is not None
        iid = d.identity.new_iid(d.prefix, now)
        epoch = d.identity.epoch
        addr = str(join_address(d.prefix, iid))
        remove_at = self._window_end(d, epoch)
        nxt = min(now + self.rng.uniform(self.min_interval, self.max_interval), remove_at - ROTATE_LEAD)
        self.net.add_addr(d.name, addr,
                          preferred=math.ceil(nxt - now) + SAFETY_LFT,
                          valid=math.ceil(remove_at - now) + SAFETY_LFT)
        new = Addr(addr, d.label, epoch, now, remove_at)
        self.log.write(event="add", t=now, device=d.name, tenant=d.tenant, label=d.label,
                       session=d.session, epoch=epoch, addr=addr, iid=iid.hex(),
                       next_rotation=round(nxt, 3), remove_at=round(remove_at, 3))
        self._check(d, addr, d.label, now, "add")
        if d.current is not None:
            # RFC 8981 overlap: keep the old address preferred until the new one has
            # finished DAD, then deprecate it; remove it when it leaves the window.
            d.current.deprecate_at = min(now + ROTATE_LEAD, d.current.remove_at)
            d.old.append(d.current)
        d.current = new
        d.next_rotation = nxt

    def _deprecate(self, d: Device, a: Addr, now: float) -> None:
        a.deprecated_at = now
        self.net.deprecate_addr(d.name, a.addr, valid=max(1, math.ceil(a.remove_at - now)) + SAFETY_LFT)
        self.log.write(event="deprecate", t=now, device=d.name, addr=a.addr)

    def _remove(self, d: Device, a: Addr, now: float, reason: str) -> None:
        if reason != "shutdown":
            self._check(d, a.addr, a.label, now, "remove")
        self.net.del_addr(d.name, a.addr)
        if a in d.old:
            d.old.remove(a)
        self.log.write(event="remove", t=now, device=d.name, addr=a.addr, reason=reason)

    def _check(self, d: Device, addr: str, expected: Optional[str], now: float, when: str) -> None:
        """Resolver log for FR-K3 / PT-2: own tenant must resolve, other must not."""
        if self.rlog is None:
            return
        other = "B" if d.tenant == "A" else "A"
        self.rlog.write(t=now, when=when, device=d.name, tenant=d.tenant, addr=addr,
                        expected=expected, own=self.monitor.resolve(d.tenant, addr),
                        other_tenant=self.monitor.resolve(other, addr))


# --------------------------------------------------------------------------- kernel mode

KERNEL_DEFAULTS = {"use_tempaddr": "0", "temp_prefered_lft": "86400",
                   "temp_valid_lft": "604800", "max_desync_factor": "600"}


class KernelRotation:
    def __init__(self, topo: Topology, net: NetOps, log: JsonlLog, preferred: int, valid: int,
                 desync: int, devices: Optional[List[str]] = None) -> None:
        if preferred < 10 or valid <= preferred:
            raise ValueError("need temp_prefered_lft >= 10 and temp_valid_lft > temp_prefered_lft")
        self.topo, self.net, self.log = topo, net, log
        self.preferred, self.valid, self.desync = preferred, valid, desync
        self.devices = devices or topo.devices
        self.seen: Dict[str, Dict[str, bool]] = {d: {} for d in self.devices}  # addr -> deprecated

    def _set(self, d: str, values: Dict[str, str]) -> None:
        for k, v in values.items():
            self.net.set_sysctl(d, "net.ipv6.conf.eth0." + k, v)

    def start(self, now: float) -> None:
        for d in self.devices:
            # desync first: the kernel rejects temp_prefered_lft <= desync + regen_advance
            self._set(d, {"autoconf": "1", "max_desync_factor": str(self.desync),
                          "temp_valid_lft": str(self.valid), "temp_prefered_lft": str(self.preferred),
                          "use_tempaddr": "2"})
            self.log.write(event="kernel_mode", t=now, device=d, tenant=self.topo.tenants[d],
                           temp_prefered_lft=self.preferred, temp_valid_lft=self.valid,
                           max_desync_factor=self.desync)

    def step(self, now: float) -> None:
        for d in self.devices:
            current = {a["local"]: bool(a.get("deprecated")) for a in self.net.list_global(d)
                       if a.get("temporary")}
            known = self.seen[d]
            for addr, dep in current.items():
                if addr not in known:
                    self.log.write(event="add", t=now, device=d, tenant=self.topo.tenants[d],
                                   label=None, addr=addr, source="kernel")
                if dep and not known.get(addr, False):
                    self.log.write(event="deprecate", t=now, device=d, addr=addr)
            for addr in [a for a in known if a not in current]:
                self.log.write(event="remove", t=now, device=d, addr=addr, reason="kernel")
            self.seen[d] = current

    def stop(self, now: float) -> None:
        for d in self.devices:
            try:
                self._set(d, {"use_tempaddr": "0"})
                for a in self.net.list_global(d):
                    if a.get("temporary"):
                        self.net.del_addr(d, a["local"])
                        self.log.write(event="remove", t=now, device=d, addr=a["local"],
                                       reason="shutdown")
                self._set(d, {k: v for k, v in KERNEL_DEFAULTS.items() if k != "use_tempaddr"})
            except (subprocess.CalledProcessError, ValueError):
                pass
        self.log.write(event="stop", t=now)


# --------------------------------------------------------------------------- CLI

def make_run_dir(out: Path, mode: str, seed: int) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run = out / ("%s-%s-s%d" % (stamp, mode, seed))
    run.mkdir(parents=True, exist_ok=False)
    return run


def chown_to_invoker(path: Path) -> None:
    """Files written under sudo should belong to the user who ran sudo."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid or not gid:
        return
    for p in [path, *path.rglob("*")]:
        os.chown(p, int(uid), int(gid))
    for parent in path.parents:
        if parent == REPO:
            break
        os.chown(parent, int(uid), int(gid))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mode", choices=("scripted", "kernel"), default="scripted")
    ap.add_argument("--duration", type=float, default=300.0, help="seconds (default 300)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--epoch", type=float, default=60.0, help="epoch length T in seconds")
    ap.add_argument("--ttl", type=float, default=1800.0, help="session TTL in seconds")
    ap.add_argument("--grace", type=int, default=1, help="grace period in epochs")
    ap.add_argument("--min-interval", type=float, default=1.0)
    ap.add_argument("--max-interval", type=float, default=None, help="default: the epoch length")
    ap.add_argument("--kernel-preferred", type=int, default=30, help="temp_prefered_lft (kernel mode)")
    ap.add_argument("--kernel-valid", type=int, default=60, help="temp_valid_lft (kernel mode)")
    ap.add_argument("--kernel-desync", type=int, default=2, help="max_desync_factor (kernel mode)")
    ap.add_argument("--devices", default=None, help="comma list, default: all of d1..d5")
    ap.add_argument("--out", type=Path, default=REPO / "runs")
    ap.add_argument("--monitor", default=None, metavar="SOCKET",
                    help="enroll with the running monitor (e.g. /run/mayfly-lab/monitor.sock) "
                         "instead of the in-process stand-in")
    ap.add_argument("--dry-run", action="store_true",
                    help="no root, no namespaces: simulated clock and in-memory addresses")
    return ap.parse_args(argv)


def run(args: argparse.Namespace) -> Path:
    topo = Topology.load()
    devices = args.devices.split(",") if args.devices else None
    if devices:
        unknown = set(devices) - set(topo.devices)
        if unknown:
            raise SystemExit("unknown devices: %s" % ", ".join(sorted(unknown)))
    if not args.dry_run and os.geteuid() != 0:
        raise SystemExit("needs root to change addresses in the lab namespaces "
                         "(sudo .venv/bin/python lab/rotation.py ...), or use --dry-run")
    params = Params(epoch_seconds=args.epoch, session_ttl_seconds=args.ttl, grace_epochs=args.grace)
    if args.mode == "scripted" and (args.max_interval or args.epoch) > args.epoch:
        raise ValueError("--max-interval must not exceed --epoch (each device must rotate at "
                         "least once per epoch); raise --epoch instead")
    if args.monitor and (args.dry_run or args.mode != "scripted"):
        raise ValueError("--monitor needs scripted mode on the real lab")
    if args.monitor and not os.path.exists(args.monitor):
        raise ValueError("no monitor socket at %s (start it: sudo lab/run_monitor.sh)" % args.monitor)
    net: NetOps = FakeNet(topo.prefix) if args.dry_run else IpNetns(set(topo.devices))
    run_dir = make_run_dir(args.out, args.mode + ("-dry" if args.dry_run else ""), args.seed)
    rot_fh = open(run_dir / "rotation.jsonl", "w")
    res_fh = open(run_dir / "resolver.jsonl", "w") if args.mode == "scripted" and not args.monitor else None
    log, rlog = JsonlLog(rot_fh), (JsonlLog(res_fh) if res_fh else None)
    log.write(event="run", mode=args.mode, seed=args.seed, duration=args.duration,
              epoch=args.epoch, ttl=args.ttl, grace=args.grace, dry_run=args.dry_run,
              min_interval=args.min_interval, max_interval=args.max_interval or args.epoch,
              devices=devices or topo.devices, tenants=topo.tenants, monitor=args.monitor,
              started=dt.datetime.now().astimezone().isoformat(timespec="seconds"))

    t0 = time.monotonic()
    if args.mode == "scripted":
        key_rng = random.Random("keys/%d" % args.seed)   # lab only: deterministic keys per seed
        monitor = (RemoteMonitor(args.monitor, params, key_rng.randbytes, lambda: time.monotonic() - t0)
                   if args.monitor else LocalMonitor(params, key_rng.randbytes))
        emu = ScriptedRotation(topo, net, monitor, params, log, rlog,
                               args.seed, args.min_interval, args.max_interval or args.epoch, devices)
    else:
        emu = KernelRotation(topo, net, log, args.kernel_preferred, args.kernel_valid,
                             args.kernel_desync, devices)

    stop = {"flag": False}

    def on_signal(signum, frame):
        stop["flag"] = True
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    tick = 0.25 if args.mode == "scripted" else 0.5
    now = 0.0
    try:
        emu.start(now)
        while now < args.duration and not stop["flag"]:
            if args.dry_run:
                now = round(now + tick, 6)
            else:
                time.sleep(tick)
                now = time.monotonic() - t0
            emu.step(now)
    except subprocess.CalledProcessError as exc:
        print("ip command failed (is the lab up?): %s\n%s" % (" ".join(exc.cmd), exc.stderr or ""),
              file=sys.stderr)
    finally:
        emu.stop(now)
        rot_fh.close()
        if res_fh:
            res_fh.close()
        chown_to_invoker(run_dir)
    return run_dir


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        run_dir = run(args)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    print("ground truth written to %s" % run_dir)
    print("check it with: .venv/bin/python lab/verify_rotation.py %s" % run_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
