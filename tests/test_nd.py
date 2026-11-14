import ipaddress

from mayfly.nd import NA, NS, RA, RS, parse_frame

import ndframes as f


def test_ra_fields():
    p = parse_frame(f.ra(lifetime=0, prf=1))
    assert p.msg_type == RA and p.type_name == "RA"
    assert p.src == ipaddress.IPv6Address("fe80::1") and p.hop_limit == 255
    assert p.ra.router_lifetime == 0 and p.ra.preference == "high"
    assert p.ra.src_lla == "02:4d:46:00:00:fe" and p.src_mac == "02:4d:46:00:00:fe"
    [pi] = p.ra.prefixes
    assert pi.prefix == ipaddress.IPv6Network("fd4d:6179:666c:1::/64")
    assert not p.malformed


def test_ns_na_rs():
    src = "fd4d:6179:666c:1:1234:5678:9abc:def0"
    p = parse_frame(f.ns(src, "fd4d:6179:666c:1::1"))
    assert p.msg_type == NS and str(p.src) == src and str(p.target) == "fd4d:6179:666c:1::1"
    assert parse_frame(f.na(src, src)).msg_type == NA
    p = parse_frame(f.rs())
    assert p.msg_type == RS and p.src.is_unspecified


def test_extension_header_does_not_hide_ra():
    """RA-Guard evasion (RFC 7113) puts a destination-options header first."""
    p = parse_frame(f.ra(src="fe80::66", ext=f.destopt()))
    assert p is not None and p.msg_type == RA and str(p.src) == "fe80::66"


def test_fragmented_nd_is_ignored():
    assert parse_frame(f.fragmented_ra()) is None  # hosts must drop it too (RFC 6980)


def test_bad_hop_limit_flagged():
    p = parse_frame(f.ns("fe80::5", "fe80::1", hlim=64))
    assert p.malformed == ["hop_limit_64"]


def test_non_nd_and_garbage():
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
    from scapy.layers.l2 import Ether
    assert parse_frame(bytes(Ether() / IPv6(dst="fe80::1") / ICMPv6EchoRequest())) is None
    assert parse_frame(b"\x00" * 10) is None
    assert parse_frame(b"\xff" * 200) is None
    truncated = f.ra()[:-10]
    p = parse_frame(truncated)
    assert p is None or p.malformed
