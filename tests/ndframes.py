"""Scapy-built ND frames for tests (independent of mayfly.nd)."""

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet6 import (ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6ND_RS,  # noqa: E402
                                ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, IPv6,
                                IPv6ExtHdrDestOpt, IPv6ExtHdrFragment)
from scapy.layers.l2 import Ether  # noqa: E402

LAB_PREFIX = "fd4d:6179:666c:1::"
ROUTER_LL = "fe80::1"
ROUTER_MAC = "02:4d:46:00:00:fe"


def ra(src=ROUTER_LL, prefix=LAB_PREFIX, lifetime=600, prf=0, mac=ROUTER_MAC, hlim=255, ext=None):
    pkt = IPv6(src=src, dst="ff02::1", hlim=hlim)
    if ext is not None:
        pkt = pkt / ext
    pkt = pkt / ICMPv6ND_RA(routerlifetime=lifetime, prf=prf) / ICMPv6NDOptSrcLLAddr(lladdr=mac)
    if prefix:
        pkt = pkt / ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=64)
    return bytes(Ether(src=mac, dst="33:33:00:00:00:01") / pkt)


def ns(src, target, mac="02:4d:46:00:00:01", hlim=255):
    return bytes(Ether(src=mac, dst="33:33:ff:00:00:01") /
                 IPv6(src=src, dst="ff02::1:ff00:1", hlim=hlim) / ICMPv6ND_NS(tgt=target))


def na(src, target, mac="02:4d:46:00:00:01"):
    return bytes(Ether(src=mac, dst="33:33:00:00:00:01") /
                 IPv6(src=src, dst="ff02::1", hlim=255) / ICMPv6ND_NA(tgt=target, R=0, S=0, O=1))


def rs(src="::", mac="02:4d:46:00:00:01"):
    return bytes(Ether(src=mac, dst="33:33:00:00:00:02") / IPv6(src=src, dst="ff02::2", hlim=255) / ICMPv6ND_RS())


def fragmented_ra():
    return bytes(Ether(src=ROUTER_MAC, dst="33:33:00:00:00:01") /
                 IPv6(src="fe80::66", dst="ff02::1", hlim=255) / IPv6ExtHdrFragment() / ICMPv6ND_RA())


def destopt():
    return IPv6ExtHdrDestOpt()
