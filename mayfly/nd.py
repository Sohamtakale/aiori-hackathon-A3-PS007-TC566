"""Minimal parser for IPv6 Neighbor Discovery frames (RFC 4861).

Takes a raw Ethernet frame and returns an ``NDPacket`` for RS, RA, NS, NA and
Redirect, or None for anything else. Hand-written instead of Scapy so the
monitor stays fast and has no libpcap dependency; tests cross-check it
against Scapy-built packets.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
IPPROTO_ICMPV6 = 58
EXT_HEADERS = {0, 43, 60}        # hop-by-hop, routing, destination options
IPPROTO_FRAGMENT = 44

RS, RA, NS, NA, REDIRECT = 133, 134, 135, 136, 137
TYPE_NAMES = {RS: "RS", RA: "RA", NS: "NS", NA: "NA", REDIRECT: "REDIRECT"}

OPT_SRC_LLA, OPT_TGT_LLA, OPT_PREFIX_INFO = 1, 2, 3

# RA router preference (RFC 4191), 2-bit field in the flags byte.
PRF_NAMES = {0b01: "high", 0b00: "medium", 0b11: "low", 0b10: "reserved"}


@dataclass(frozen=True)
class PrefixInfo:
    prefix: ipaddress.IPv6Network
    on_link: bool
    autonomous: bool
    valid_lifetime: int
    preferred_lifetime: int


@dataclass(frozen=True)
class RAInfo:
    cur_hop_limit: int
    managed: bool
    other: bool
    preference: str
    router_lifetime: int
    prefixes: Tuple[PrefixInfo, ...] = ()
    src_lla: Optional[str] = None


@dataclass(frozen=True)
class NDPacket:
    msg_type: int
    src: ipaddress.IPv6Address
    dst: ipaddress.IPv6Address
    hop_limit: int
    src_mac: str
    target: Optional[ipaddress.IPv6Address] = None
    ra: Optional[RAInfo] = None
    malformed: List[str] = field(default_factory=list)

    @property
    def type_name(self) -> str:
        return TYPE_NAMES[self.msg_type]


def _mac(b: bytes) -> str:
    return ":".join("%02x" % x for x in b)


def _options(buf: bytes) -> List[Tuple[int, bytes]]:
    out = []
    i = 0
    while i + 2 <= len(buf):
        otype, olen = buf[i], buf[i + 1]
        if olen == 0:
            raise ValueError("zero-length ND option")
        end = i + olen * 8
        if end > len(buf):
            raise ValueError("truncated ND option")
        out.append((otype, buf[i:end]))
        i = end
    return out


def _parse_ra(icmp: bytes) -> RAInfo:
    if len(icmp) < 16:
        raise ValueError("short RA")
    cur_hl, flags, lifetime = icmp[4], icmp[5], struct.unpack_from("!H", icmp, 6)[0]
    prefixes = []
    src_lla = None
    for otype, opt in _options(icmp[16:]):
        if otype == OPT_PREFIX_INFO and len(opt) >= 32:
            plen, pflags = opt[2], opt[3]
            valid, preferred = struct.unpack_from("!II", opt, 4)
            if plen > 128:
                raise ValueError("bad prefix length")
            net = ipaddress.IPv6Network((bytes(opt[16:32]), plen), strict=False)
            prefixes.append(PrefixInfo(net, bool(pflags & 0x80), bool(pflags & 0x40), valid, preferred))
        elif otype == OPT_SRC_LLA and len(opt) >= 8:
            src_lla = _mac(opt[2:8])
    return RAInfo(cur_hop_limit=cur_hl, managed=bool(flags & 0x80), other=bool(flags & 0x40),
                  preference=PRF_NAMES[(flags >> 3) & 0b11], router_lifetime=lifetime,
                  prefixes=tuple(prefixes), src_lla=src_lla)


def parse_frame(frame: bytes) -> Optional[NDPacket]:
    """Ethernet frame -> NDPacket, or None if it is not a (parsable) ND message."""
    if len(frame) < 14 + 40 + 4:
        return None
    src_mac = _mac(frame[6:12])
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    off = 14
    if ethertype == ETH_P_8021Q:
        ethertype = struct.unpack_from("!H", frame, 16)[0]
        off = 18
    if ethertype != ETH_P_IPV6 or len(frame) < off + 40:
        return None
    ip = frame[off:off + 40]
    if ip[0] >> 4 != 6:
        return None
    payload_len = struct.unpack_from("!H", ip, 4)[0]
    nxt, hop_limit = ip[6], ip[7]
    src = ipaddress.IPv6Address(bytes(ip[8:24]))
    dst = ipaddress.IPv6Address(bytes(ip[24:40]))
    body = frame[off + 40:off + 40 + payload_len]
    # Walk extension headers. ND over fragments is invalid (RFC 6980): ignore.
    for _ in range(8):
        if nxt in EXT_HEADERS:
            if len(body) < 8:
                return None
            hlen = (body[1] + 1) * 8
            nxt, body = body[0], body[hlen:]
        elif nxt == IPPROTO_FRAGMENT:
            return None
        else:
            break
    if nxt != IPPROTO_ICMPV6 or len(body) < 4:
        return None
    mtype = body[0]
    if mtype not in TYPE_NAMES:
        return None
    problems: List[str] = []
    if hop_limit != 255:
        problems.append("hop_limit_%d" % hop_limit)
    try:
        if mtype == RA:
            return NDPacket(mtype, src, dst, hop_limit, src_mac, ra=_parse_ra(body), malformed=problems)
        if mtype in (NS, NA, REDIRECT):
            if len(body) < 24:
                raise ValueError("short %s" % TYPE_NAMES[mtype])
            target = ipaddress.IPv6Address(bytes(body[8:24]))
            return NDPacket(mtype, src, dst, hop_limit, src_mac, target=target, malformed=problems)
        return NDPacket(mtype, src, dst, hop_limit, src_mac, malformed=problems)
    except ValueError as exc:
        problems.append(str(exc))
        return NDPacket(mtype, src, dst, hop_limit, src_mac, malformed=problems)
