"""Shared helpers for the attack scripts (PRD section 10). Lab use only.

Safety
------
Every attack refuses to run unless it is inside a network namespace that is NOT
the host's. The check compares this process's net namespace with PID 1's: in a
lab namespace (entered with ``ip netns exec``) they differ; in the host they are
identical and the attack aborts. Attacks only ever send on the namespace's
``eth0`` (the veth to br0), never on a real interface.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from typing import Callable, List, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.sendrecv import sendp  # noqa: E402
from scapy.arch import get_if_hwaddr  # noqa: E402

IFACE = "eth0"


class NotInLab(SystemExit):
    pass


def _ns_id(pid: str) -> Optional[int]:
    try:
        return os.stat("/proc/%s/ns/net" % pid).st_ino
    except OSError:
        return None


def ensure_lab_namespace(iface: str = IFACE) -> None:
    """Abort unless we are in a non-host network namespace with the lab iface."""
    mine, host = _ns_id("self"), _ns_id("1")
    if mine is not None and host is not None and mine == host:
        raise NotInLab(
            "refusing to run in the host network namespace. Attacks run only inside the lab:\n"
            "  sudo ip netns exec d1 .venv/bin/python -m attacks.ndp_flood ...")
    if not os.path.isdir("/sys/class/net/%s" % iface):
        raise NotInLab("interface %r not found; are you inside a lab namespace?" % iface)
    # eth0 in a lab namespace is a veth; a real NIC would have a device driver symlink.
    if not os.path.exists("/sys/class/net/%s/master" % iface) and \
       os.path.exists("/sys/class/net/%s/device" % iface):
        raise NotInLab("%r looks like a physical interface; refusing to touch it" % iface)


def hwaddr(iface: str = IFACE) -> str:
    return get_if_hwaddr(iface)


def _addr_json(iface: str, *flags: str) -> list:
    out = subprocess.check_output(["ip", "-6", "-j", "addr", "show", "dev", iface, *flags])
    data = json.loads(out)
    return data[0].get("addr_info", []) if data else []


def preferred_global(iface: str = IFACE) -> Optional[str]:
    """The device's current preferred global address, or None."""
    for a in _addr_json(iface, "scope", "global"):
        if "local" in a and not a.get("deprecated") and not a.get("tentative"):
            return a["local"]
    return None


def all_global(iface: str = IFACE) -> List[str]:
    return [a["local"] for a in _addr_json(iface, "scope", "global") if "local" in a]


def link_local(iface: str = IFACE) -> Optional[str]:
    for a in _addr_json(iface, "scope", "link"):
        if "local" in a:
            return a["local"]
    return None


def send(frames, iface: str = IFACE) -> None:
    sendp(frames, iface=iface, verbose=False)


def run_rate_limited(duration: float, rate: float, make_batch: Callable[[float], list],
                     iface: str = IFACE, batch: int = 10, label: str = "") -> int:
    """Send ``make_batch(now)`` repeatedly at about ``rate`` packets/second for
    ``duration`` seconds. Returns the number of packets sent."""
    interval = batch / rate if rate > 0 else 0.1
    end = time.monotonic() + duration
    sent = 0
    try:
        while time.monotonic() < end:
            t0 = time.monotonic()
            frames = make_batch(t0)
            if frames:
                send(frames, iface)
                sent += len(frames)
            sleep = interval - (time.monotonic() - t0)
            if sleep > 0:
                time.sleep(sleep)
    except KeyboardInterrupt:
        pass
    print("%s: sent %d packets in %.1fs (~%.0f pps)"
          % (label or "attack", sent, duration, sent / duration if duration else 0),
          file=sys.stderr)
    return sent
