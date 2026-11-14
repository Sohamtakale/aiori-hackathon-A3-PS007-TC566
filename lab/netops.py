"""Address operations inside lab namespaces.

``IpNetns`` runs real ``ip -n <ns>`` / ``ip netns exec <ns> sysctl`` commands
(root needed). ``FakeNet`` records the same calls in memory so the emulator
logic can be unit-tested without root. Both only ever touch interface eth0
inside a named lab namespace, never the host namespace.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
from typing import Dict, List, Optional, Set

IFACE = "eth0"


class NetOps:
    def ra_prefix(self, ns: str) -> Optional[str]: ...
    def set_sysctl(self, ns: str, key: str, value: str) -> None: ...
    def flush_global(self, ns: str) -> None: ...
    def add_addr(self, ns: str, addr: str, preferred: int, valid: int) -> None: ...
    def deprecate_addr(self, ns: str, addr: str, valid: int) -> None: ...
    def del_addr(self, ns: str, addr: str) -> None: ...
    def list_global(self, ns: str) -> List[dict]: ...


class IpNetns(NetOps):
    def __init__(self, allowed_namespaces: Set[str]) -> None:
        self._allowed = set(allowed_namespaces)

    def _ns(self, ns: str) -> str:
        if ns not in self._allowed:
            raise ValueError("refusing to touch non-lab namespace %r" % ns)
        return ns

    def _ip(self, ns: str, *args: str, capture: bool = False) -> str:
        cmd = ["ip", "-n", self._ns(ns), *args]
        out = subprocess.run(cmd, check=True, text=True,
                             stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                             stderr=subprocess.PIPE)
        return out.stdout if capture else ""

    def ra_prefix(self, ns: str) -> Optional[str]:
        routes = json.loads(self._ip(ns, "-6", "-j", "route", "show", "proto", "ra", capture=True) or "[]")
        for r in routes:
            dst = r.get("dst", "")
            if dst not in ("default", "") and dst.endswith("/64"):
                return dst
        return None

    def set_sysctl(self, ns: str, key: str, value: str) -> None:
        subprocess.run(["ip", "netns", "exec", self._ns(ns), "sysctl", "-q", "-w", "%s=%s" % (key, value)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def flush_global(self, ns: str) -> None:
        self._ip(ns, "-6", "addr", "flush", "dev", IFACE, "scope", "global")

    def add_addr(self, ns: str, addr: str, preferred: int, valid: int) -> None:
        self._ip(ns, "-6", "addr", "add", addr + "/64", "dev", IFACE, "noprefixroute",
                 "valid_lft", str(valid), "preferred_lft", str(preferred))

    def deprecate_addr(self, ns: str, addr: str, valid: int) -> None:
        self._ip(ns, "-6", "addr", "change", addr + "/64", "dev", IFACE, "noprefixroute",
                 "valid_lft", str(valid), "preferred_lft", "0")

    def del_addr(self, ns: str, addr: str) -> None:
        try:
            self._ip(ns, "-6", "addr", "del", addr + "/64", "dev", IFACE)
        except subprocess.CalledProcessError:
            pass  # already expired by the kernel safety lifetime

    def list_global(self, ns: str) -> List[dict]:
        data = json.loads(self._ip(ns, "-6", "-j", "addr", "show", "dev", IFACE, "scope", "global",
                                   capture=True) or "[]")
        return [a for link in data for a in link.get("addr_info", []) if "local" in a]


class FakeNet(NetOps):
    """In-memory stand-in: namespace -> {addr: {"preferred": p, "valid": v}}."""

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.addrs: Dict[str, Dict[str, dict]] = {}
        self.sysctls: Dict[str, Dict[str, str]] = {}
        self.calls: List[tuple] = []

    def ra_prefix(self, ns: str) -> Optional[str]:
        return self.prefix

    def set_sysctl(self, ns: str, key: str, value: str) -> None:
        self.calls.append(("sysctl", ns, key, value))
        self.sysctls.setdefault(ns, {})[key] = value

    def flush_global(self, ns: str) -> None:
        self.calls.append(("flush", ns))
        self.addrs[ns] = {}

    def add_addr(self, ns: str, addr: str, preferred: int, valid: int) -> None:
        ipaddress.IPv6Address(addr)
        self.calls.append(("add", ns, addr))
        table = self.addrs.setdefault(ns, {})
        if addr in table:
            raise RuntimeError("address already present: " + addr)
        table[addr] = {"preferred": preferred, "valid": valid}

    def deprecate_addr(self, ns: str, addr: str, valid: int) -> None:
        self.calls.append(("deprecate", ns, addr))
        self.addrs[ns][addr].update(preferred=0, valid=valid)

    def del_addr(self, ns: str, addr: str) -> None:
        self.calls.append(("del", ns, addr))
        self.addrs.get(ns, {}).pop(addr, None)

    def list_global(self, ns: str) -> List[dict]:
        return [{"local": a, "temporary": False, "deprecated": v["preferred"] == 0}
                for a, v in self.addrs.get(ns, {}).items()]
