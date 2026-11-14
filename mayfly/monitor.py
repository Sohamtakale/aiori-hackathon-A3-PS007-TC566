"""Mayfly monitor (C1 resolver + C2 detectors + C4 alert log).

    on_packet(frame, port):
        pkt = parse ND
        who = resolve(pkt.src) -> (tenant, label)   or   UNBOUND -> port
        rogue_ra_rules(pkt, port)          -> high alert
        rate[who][pkt.type] > THRESHOLD    -> medium (label) / high (unbound port)

One raw AF_PACKET socket per bridge port (the switch side of each veth), so
the ingress port of every frame is known without trusting anything in it.
Only frames the node *sent* are counted (outgoing frames on the port are
ignored). Enrollment arrives on a root-only UNIX socket (mayfly.enrollsvc).

Run it in the lab's switch namespace, via lab/run_monitor.sh.

Privacy (FR-U2): alerts carry label, tenant, epoch, message type, port and
time only. Raw addresses exist only in memory while a packet is processed and
in the resolver cache for the current epoch window. Alerts older than the
session TTL are dropped from the log file. No packets are stored.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import select
import socket
import struct
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable, Dict, List, Optional, TextIO

from mayfly.detectors import (DEFAULT_THRESHOLDS, HIGH, Alert, AddressTheftDetector, Attribution,
                              RateDetector, RogueRADetector, RouterPolicy)
from mayfly.enrollsvc import EnrollmentService, listen
from mayfly.keystore import TenantKeyStore
from mayfly.nd import NDPacket, parse_frame
from mayfly.params import Params
from mayfly.resolver import Resolver

ETH_P_IPV6 = 0x86DD
ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
SOL_PACKET = 263
PACKET_IGNORE_OUTGOING = 23
PACKET_OUTGOING = 4
TICK_SECONDS = 0.5
MAX_BURST = 512            # frames drained from one port before looking at the others


# --------------------------------------------------------------------------- alert sink

class AlertLog:
    """JSONL alert log with retention <= session TTL (FR-U2)."""

    def __init__(self, path: Optional[Path], retention: float, echo: bool = True,
                 out: TextIO = sys.stdout) -> None:
        self.path = path
        self.retention = retention
        self.echo = echo
        self.out = out
        self.alerts: List[Alert] = []
        self._fh = open(path, "a") if path else None

    def emit(self, a: Alert) -> None:
        self.alerts.append(a)
        if self._fh:
            self._fh.write(json.dumps(a.to_dict(), sort_keys=True) + "\n")
            self._fh.flush()
        if self.echo:
            extra = ("rules=" + ",".join(a.rules)) if a.rules else "count=%s/%s" % (a.count, a.threshold)
            tenant = (" tenant=" + a.tenant) if a.tenant else ""
            print("[%8.2f] %-6s %-8s %-3s who=%s%s port=%s %s"
                  % (a.t, a.severity.upper(), a.detector, a.msg_type, a.who, tenant, a.port, extra),
                  file=self.out, flush=True)

    def expire(self, now: float) -> None:
        keep = [a for a in self.alerts if now - a.t <= self.retention]
        if len(keep) == len(self.alerts):
            return
        self.alerts = keep
        if self._fh and self.path:
            self._fh.close()
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w") as fh:
                for a in keep:
                    fh.write(json.dumps(a.to_dict(), sort_keys=True) + "\n")
            os.replace(tmp, self.path)
            self._fh = open(self.path, "a")

    def close(self) -> None:
        if self._fh:
            self._fh.close()


# --------------------------------------------------------------------------- responder hook

class LogOnlyResponder:
    """Placeholder for C3 (step 6): records which ports a high alert would isolate."""

    def __init__(self) -> None:
        self.requests: Counter = Counter()

    def on_alert(self, a: Alert, now: float) -> None:
        if a.severity == HIGH:
            self.requests[a.port] += 1


# --------------------------------------------------------------------------- core

class Monitor:
    def __init__(self, tenants: Dict[str, bytes], params: Params, policy: RouterPolicy,
                 thresholds: Optional[Dict[str, int]] = None,
                 clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time,
                 sink: Optional[AlertLog] = None, responder=None) -> None:
        self.params = params
        self.clock, self.wall = clock, wall
        self.stores = {name: TenantKeyStore(tid, params) for name, tid in tenants.items()}
        self.resolvers = {name: Resolver(s) for name, s in self.stores.items()}
        self.enrollment = EnrollmentService(self.stores, clock)
        self.rate = RateDetector(thresholds)
        self.rogue = RogueRADetector(policy)
        self.theft = AddressTheftDetector(hold=2 * params.epoch_seconds)
        self.sink = sink or AlertLog(None, params.session_ttl_seconds, echo=False)
        self.responder = responder or LogOnlyResponder()
        self.stats: Dict[str, Counter] = defaultdict(Counter)
        self.current_addr: Dict[tuple, tuple] = {}     # (tenant,label) -> (addr, port, epoch, t)

    def live_state(self, now: float) -> dict:
        """Snapshot for the dashboard (FR-U1): sessions and the CURRENT address
        mapping only. No history, no past addresses."""
        sessions = []
        for name, store in self.stores.items():
            for label in store.labels():
                s = store.get(label)
                cur = self.current_addr.get((name, label))
                sessions.append({
                    "tenant": name, "label": label,
                    "state": s.state.value, "epoch": s.epoch,
                    "address": cur[0] if cur else None,
                    "port": cur[1] if cur else None,
                    "last_seen": round(now - cur[3], 1) if cur else None,
                })
        return {"t": round(now, 2), "sessions": sorted(sessions, key=lambda x: (x["tenant"], x["label"])),
                "nd_counts": {p: dict(c) for p, c in self.stats.items()},
                "isolated": sorted(getattr(getattr(self.responder, "isolator", None), "isolated", set)())
                if hasattr(self.responder, "isolator") else []}

    def expire_session(self, tenant: str, label: str) -> bool:
        """Operator action: end a session now and wipe its keys (FR-U1 button)."""
        ok = self.resolvers[tenant].expire(label)
        if ok:
            self.rate.forget(["%s/%s" % (tenant, label)])
            self.theft.forget([(tenant, label)])
            self.current_addr.pop((tenant, label), None)
        return ok

    def attribute(self, pkt: NDPacket, port: str) -> Attribution:
        src = pkt.src
        if src.is_unspecified or src.is_multicast or src.is_loopback:
            return Attribution(port)
        packed = src.packed
        prefix, iid = packed[:8], packed[8:]
        # Each tenant's resolver is asked on its own; they share no keys or state.
        for name, res in self.resolvers.items():
            m = res.match(iid, prefix)
            if m is not None:
                return Attribution(port, m.label, name, m.epoch)
        return Attribution(port)

    def process_packet(self, pkt: NDPacket, port: str, now: float) -> List[Alert]:
        self.stats[port][pkt.type_name] += 1
        who = self.attribute(pkt, port)
        if who.label:
            self.stats[port]["bound"] += 1
            # current address mapping only (FR-U1); volatile, for the live view
            self.current_addr[(who.tenant, who.label)] = (str(pkt.src), who.port, who.epoch, now)
        alerts = []
        ts = self.wall()
        a = self.rogue.observe(pkt, who, now, ts)
        if a is None and who.label and not (pkt.src.is_unspecified or pkt.src.is_multicast):
            a_theft = self.theft.observe(pkt.src.packed, who, now + 2 * self.params.epoch_seconds, now, ts)
            if a_theft is not None:
                self._emit(a_theft, now, alerts)
        if a is not None:
            self._emit(a, now, alerts)
        a = self.rate.observe(pkt, who, now, ts)
        if a is not None:
            self._emit(a, now, alerts)
        return alerts

    def _emit(self, a: Alert, now: float, alerts: List[Alert]) -> None:
        alerts.append(a)
        self.sink.emit(a)
        self.responder.on_alert(a, now)

    def process_frame(self, frame: bytes, port: str, now: Optional[float] = None) -> List[Alert]:
        pkt = parse_frame(frame)
        if pkt is None:
            return []
        return self.process_packet(pkt, port, self.clock() if now is None else now)

    def tick(self, now: Optional[float] = None) -> None:
        now = self.clock() if now is None else now
        for name, res in self.resolvers.items():
            gone = res.tick(now)
            if gone:
                self.rate.forget("%s/%s" % (name, label) for label in gone)
                self.theft.forget((name, label) for label in gone)
                for label in gone:
                    self.current_addr.pop((name, label), None)
        self.rate.prune(now)
        self.theft.prune(now)
        self.sink.expire(now)
        if hasattr(self.responder, "tick"):
            self.responder.tick(now)

    def sessions(self) -> Dict[str, int]:
        return {name: len(s) for name, s in self.stores.items()}


# --------------------------------------------------------------------------- capture

# Classic BPF: accept only frames whose EtherType is IPv6.
#   ldh [12]; jeq #0x86dd, accept, drop; accept: ret #0x40000; drop: ret #0
_BPF_IPV6 = [(0x28, 0, 0, 12), (0x15, 0, 1, ETH_P_IPV6), (0x06, 0, 0, 0x40000), (0x06, 0, 0, 0)]


def _attach_bpf(s: socket.socket, prog) -> None:
    import ctypes
    insns = b"".join(struct.pack("HBBI", *ins) for ins in prog)
    buf = ctypes.create_string_buffer(insns)
    fprog = struct.pack("HL", len(prog), ctypes.addressof(buf))
    s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


def open_port(iface: str) -> socket.socket:
    # ETH_P_ALL, not ETH_P_IPV6: on a bridge port the bridge takes the frame before
    # protocol-specific packet sockets see it; only ETH_P_ALL taps get it.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        s.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
    except OSError:
        pass  # older kernel: filtered by pkttype below
    try:
        _attach_bpf(s, _BPF_IPV6)
    except OSError:
        pass  # parse_frame() drops non-IPv6 anyway
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind((iface, 0))
    s.setblocking(False)
    return s


def write_state(mon: Monitor, now: float, path: Path) -> None:
    """Write the live view atomically (FR-U1). Overwritten every tick; not a log."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(mon.live_state(now), sort_keys=True))
    os.replace(tmp, path)


class ControlChannel:
    """Reads expire-session requests appended by the dashboard (FR-U1 button).

    Each line is {"expire": {"tenant": "A", "label": "..."}}. Processed lines are
    tracked by byte offset so each request fires once.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._offset = path.stat().st_size if path.exists() else 0

    def drain(self, mon: Monitor, now: float) -> int:
        if not self.path.exists():
            return 0
        done = 0
        with open(self.path) as fh:
            fh.seek(self._offset)
            for line in fh:
                if not line.endswith("\n"):
                    break                      # partial write; pick it up next tick
                self._offset += len(line.encode())
                line = line.strip()
                if not line:
                    continue
                try:
                    cmd = json.loads(line)
                    exp = cmd.get("expire")
                    if exp and mon.expire_session(exp["tenant"], exp["label"]):
                        done += 1
                        print("[%8.2f] CONTROL expire tenant=%s label=%s"
                              % (now, exp["tenant"], exp["label"]), flush=True)
                except (ValueError, KeyError, TypeError):
                    pass
        return done


def run_loop(mon: Monitor, ports: List[str], sock_path: Optional[str], duration: float,
             stats_every: float, stop: Callable[[], bool],
             state_path: Optional[Path] = None, control_path: Optional[Path] = None) -> None:
    socks = {open_port(p): p for p in ports}
    server = listen(sock_path) if sock_path else None
    readers: List = list(socks) + ([server] if server else [])
    t_end = mon.clock() + duration if duration > 0 else None
    next_tick = mon.clock()
    next_stats = next_tick + stats_every if stats_every > 0 else float("inf")
    control = ControlChannel(control_path) if control_path else None
    try:
        while not stop():
            now = mon.clock()
            if t_end is not None and now >= t_end:
                break
            if now >= next_tick:
                mon.tick(now)
                if control:
                    control.drain(mon, now)
                if state_path:
                    write_state(mon, now, state_path)
                next_tick = now + TICK_SECONDS
            if now >= next_stats:
                print_stats(mon, now)
                next_stats = now + stats_every
            timeout = max(0.0, min(next_tick, next_stats) - now)
            ready, _, _ = select.select(readers, [], [], timeout)
            for s in ready:
                if s is server:
                    try:
                        conn, _ = server.accept()
                    except BlockingIOError:
                        continue
                    mon.enrollment.serve_connection(conn)
                    continue
                port = socks[s]
                for _ in range(MAX_BURST):
                    try:
                        frame, addr = s.recvfrom(65535)
                    except BlockingIOError:
                        break
                    if addr[2] == PACKET_OUTGOING:
                        continue
                    mon.process_frame(frame, port)
    finally:
        for s in socks:
            s.close()
        if server:
            server.close()
            if sock_path and os.path.exists(sock_path):
                os.unlink(sock_path)


def print_stats(mon: Monitor, now: float) -> None:
    parts = []
    for port in sorted(mon.stats):
        c = mon.stats[port]
        parts.append("%s[%s]" % (port, " ".join("%s=%d" % (k, c[k]) for k in ("RS", "RA", "NS", "NA", "bound") if c[k])))
    print("[%8.2f] stats sessions=%s alerts=%d  %s"
          % (now, mon.sessions(), len(mon.sink.alerts), " ".join(parts)), flush=True)


# --------------------------------------------------------------------------- CLI

def _chown_tree(path: Path) -> None:
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid or not gid:
        return
    for p in [path, *path.rglob("*"), path.parent]:
        try:
            os.chown(p, int(uid), int(gid))
        except OSError:
            pass


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Mayfly ND monitor")
    ap.add_argument("--ports", required=True, help="comma list of bridge-port interfaces to capture")
    ap.add_argument("--router-port", required=True)
    ap.add_argument("--router-ll", required=True, help="the enrolled router's link-local address")
    ap.add_argument("--allowed-prefix", action="append", required=True)
    ap.add_argument("--tenant", action="append", default=None,
                    help="NAME=TENANT_ID (default: A=tenant-A, B=tenant-B)")
    ap.add_argument("--socket", default=None, help="UNIX socket for enrollment")
    ap.add_argument("--epoch", type=float, default=60.0)
    ap.add_argument("--ttl", type=float, default=1800.0)
    ap.add_argument("--grace", type=int, default=1)
    ap.add_argument("--threshold", action="append", default=[],
                    help="TYPE=N packets per 5 s window, e.g. NS=50 (defaults %s)" % DEFAULT_THRESHOLDS)
    ap.add_argument("--duration", type=float, default=0, help="seconds, 0 = until Ctrl-C")
    ap.add_argument("--stats", type=float, default=10.0, help="print stats every N s (0 = off)")
    ap.add_argument("--out", type=Path, default=Path("runs"))
    ap.add_argument("--isolate", action="store_true",
                    help="FR-X1: isolate the offending bridge port on high alerts (nftables bridge rule)")
    ap.add_argument("--dry-run-isolation", action="store_true",
                    help="log the nft commands isolation would run, without running them")
    ap.add_argument("--cooldown", type=float, default=30.0, help="seconds before auto-release")
    ap.add_argument("--escalate-windows", type=int, default=0,
                    help="also isolate a pseudonym after N consecutive rate-alert windows (0 = off)")
    ap.add_argument("--dashboard", action="store_true",
                    help="write state.json and read control.jsonl in the run dir (for the Streamlit app)")
    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    import signal
    args = parse_args(argv)
    tenants = {}
    for spec in args.tenant or ["A=tenant-A", "B=tenant-B"]:
        name, tid = spec.split("=", 1)
        tenants[name] = tid.encode()
    thresholds = {}
    for spec in args.threshold:
        k, v = spec.split("=", 1)
        if k.upper() not in DEFAULT_THRESHOLDS:
            raise SystemExit("unknown message type in --threshold: " + k)
        thresholds[k.upper()] = int(v)
    params = Params(epoch_seconds=args.epoch, session_ttl_seconds=args.ttl, grace_epochs=args.grace)
    policy = RouterPolicy(args.router_port, ipaddress.IPv6Address(args.router_ll),
                          tuple(ipaddress.IPv6Network(p) for p in args.allowed_prefix))

    run_dir = args.out / (dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-monitor")
    run_dir.mkdir(parents=True, exist_ok=False)
    t0 = time.monotonic()
    clock = lambda: time.monotonic() - t0  # noqa: E731
    sink = AlertLog(run_dir / "alerts.jsonl", params.session_ttl_seconds)
    ports = args.ports.split(",")

    wall = time.time
    action_fh = None
    if args.isolate or args.dry_run_isolation:
        from mayfly.response import LoggingIsolator, NftablesIsolator, PortResponder
        isolator = LoggingIsolator() if args.dry_run_isolation else NftablesIsolator()
        action_fh = open(run_dir / "actions.jsonl", "a")
        responder = PortResponder(isolator, cooldown=args.cooldown, clock=clock, wall=wall,
                                  protected={args.router_port}, escalate_windows=args.escalate_windows,
                                  sink=action_fh)
    else:
        responder = None
    mon = Monitor(tenants, params, policy, thresholds, clock=clock, wall=wall, sink=sink,
                  responder=responder)

    stopped = {"flag": False}
    signal.signal(signal.SIGINT, lambda *_: stopped.__setitem__("flag", True))
    signal.signal(signal.SIGTERM, lambda *_: stopped.__setitem__("flag", True))
    print("mayfly monitor: ports=%s router=%s@%s thresholds=%s"
          % (",".join(ports), args.router_ll, args.router_port, mon.rate.thresholds), flush=True)
    if args.socket:
        print("enrollment socket: %s" % args.socket, flush=True)
    if args.isolate:
        print("isolation: ON (nftables bridge rule, cooldown %gs%s)"
              % (args.cooldown, ", escalate after %d windows" % args.escalate_windows
                 if args.escalate_windows else ""), flush=True)
    elif args.dry_run_isolation:
        print("isolation: DRY RUN (logging nft commands only)", flush=True)
    try:
        state_path = run_dir / "state.json" if args.dashboard else None
        control_path = run_dir / "control.jsonl" if args.dashboard else None
        if args.dashboard:
            control_path.touch()
            print("dashboard state: %s" % state_path, flush=True)
        run_loop(mon, ports, args.socket, args.duration, args.stats, lambda: stopped["flag"],
                 state_path=state_path, control_path=control_path)
    finally:
        now = clock()
        has_responder = hasattr(mon.responder, "shutdown")
        if has_responder:
            drops = mon.responder.isolator.drops()
            mon.responder.shutdown(now)        # release any ports, remove the nft table
        else:
            drops = None
        print_stats(mon, now)
        summary = {
            "duration": round(now, 3), "ports": ports, "thresholds": mon.rate.thresholds,
            "enrolled": mon.enrollment.enrolled,
            "alerts": len(sink.alerts),
            "isolation_requests": dict(mon.responder.requests),
            "isolation_actions": len(getattr(mon.responder, "actions", [])),
            "frames_dropped_by_isolation": drops,
            "nd_counts": {p: dict(c) for p, c in mon.stats.items()},
        }
        (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        sink.close()
        if action_fh:
            action_fh.close()
        _chown_tree(run_dir)
        print("alerts written to %s" % (run_dir / "alerts.jsonl"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
