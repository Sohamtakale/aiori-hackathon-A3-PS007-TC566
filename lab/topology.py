"""Lab topology as seen from Python, read from lab/lab.env (single source of truth)."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

ENV_FILE = Path(__file__).with_name("lab.env")


def load_env(path: Path = ENV_FILE) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parts = shlex.split(value)
        env[key.strip()] = parts[0] if len(parts) == 1 else " ".join(parts)
    return env


@dataclass(frozen=True)
class Topology:
    sw_ns: str
    bridge: str
    devices: List[str]
    tenants: Dict[str, str]      # device -> tenant name ("A"/"B")
    router_ns: str
    attacker_ns: str
    prefix: str
    router_ll: str

    @classmethod
    def load(cls, path: Path = ENV_FILE) -> "Topology":
        e = load_env(path)
        tenants = {d: "A" for d in e["TENANT_A"].split()}
        tenants.update({d: "B" for d in e["TENANT_B"].split()})
        return cls(
            sw_ns=e["SW_NS"], bridge=e["BRIDGE"], devices=e["DEVICES"].split(),
            tenants=tenants, router_ns=e["ROUTER_NS"], attacker_ns=e["ATTACKER_NS"],
            prefix=e["LAB_PREFIX"], router_ll=e["ROUTER_LL"],
        )

    def port(self, node: str) -> str:
        return "v" + node
