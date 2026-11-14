"""C3 response: Layer-2 port isolation (FR-X1, FR-X2).

Isolation drops every frame that ingresses on the offender's veth, using an
nftables rule in the **bridge** family -- NOT `bridge link set ... isolated`
(kernel port isolation), which the PRD step rules out. The rule matches the
port's interface name against a named set and drops; isolating/releasing a port
is just adding/removing its ifname from the set, and a counter on the rule
measures the attack traffic that no longer reaches victims (FR-X2).

    table bridge mayfly {
        set isolated { type ifname; }
        chain block {
            type filter hook prerouting priority -300; policy accept;
            iifname @isolated counter drop
        }
    }

The monitor runs inside the switch namespace (`ip netns exec sw`), so nft acts
on that namespace's bridge only. This table is independent of firewalld (which
manages inet/ip tables in the host namespace) and of SELinux policy for the
host interfaces; nothing here touches a real NIC.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, TextIO

from mayfly.detectors import HIGH, Alert

TABLE = "mayfly"
SET = "isolated"
CHAIN = "block"
PRIORITY = -300
VALID_IFNAME = re.compile(r"\A[A-Za-z0-9_.-]{1,15}\Z")


def _check_ifname(port: str) -> str:
    if not VALID_IFNAME.match(port):
        raise ValueError("refusing unsafe interface name %r" % port)
    return port


# --------------------------------------------------------------------------- isolators

class Isolator:
    """Isolation backend interface."""

    def setup(self) -> None: ...
    def isolate(self, port: str) -> bool: ...        # True if newly isolated
    def release(self, port: str) -> bool: ...        # True if it had been isolated
    def isolated(self) -> Set[str]: ...
    def drops(self) -> Optional[int]:                # frames dropped so far (FR-X2)
        return None

    def teardown(self) -> None: ...


class FakeIsolator(Isolator):
    """In-memory isolator for tests and dry runs; records every call."""

    def __init__(self) -> None:
        self._isolated: Set[str] = set()
        self.calls: List[tuple] = []
        self.ok = True

    def setup(self) -> None:
        self.calls.append(("setup",))

    def isolate(self, port: str) -> bool:
        _check_ifname(port)
        self.calls.append(("isolate", port))
        if port in self._isolated:
            return False
        self._isolated.add(port)
        return True

    def release(self, port: str) -> bool:
        self.calls.append(("release", port))
        if port not in self._isolated:
            return False
        self._isolated.discard(port)
        return True

    def isolated(self) -> Set[str]:
        return set(self._isolated)

    def drops(self) -> Optional[int]:
        return len(self.calls)

    def teardown(self) -> None:
        self.calls.append(("teardown",))
        self._isolated.clear()


class LoggingIsolator(FakeIsolator):
    """Dry-run: behaves like FakeIsolator but prints the nft commands it would run."""

    def __init__(self, out: TextIO = sys.stderr) -> None:
        super().__init__()
        self.out = out

    def isolate(self, port: str) -> bool:
        new = super().isolate(port)
        if new:
            print("[would run] " + " ".join(NftablesIsolator.add_cmd(port)), file=self.out)
        return new

    def release(self, port: str) -> bool:
        had = super().release(port)
        if had:
            print("[would run] " + " ".join(NftablesIsolator.del_cmd(port)), file=self.out)
        return had


class NftablesIsolator(Isolator):
    """Real isolation via nft in the current (switch) network namespace."""

    def __init__(self, runner: Callable[[List[str], Optional[str]], str] = None) -> None:
        self._run = runner or self._default_runner
        self._isolated: Set[str] = set()

    @staticmethod
    def _default_runner(argv: List[str], stdin: Optional[str]) -> str:
        return subprocess.run(argv, input=stdin, check=True, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    # ----- command builders (pure, so tests can assert them) -----
    RULESET = (
        "add table bridge %(t)s\n"
        "delete table bridge %(t)s\n"
        "table bridge %(t)s {\n"
        "    set %(s)s { type ifname; }\n"
        "    chain %(c)s {\n"
        "        type filter hook prerouting priority %(p)d; policy accept;\n"
        "        iifname @%(s)s counter drop\n"
        "    }\n"
        "}\n"
    )

    @classmethod
    def ruleset(cls) -> str:
        return cls.RULESET % {"t": TABLE, "s": SET, "c": CHAIN, "p": PRIORITY}

    @staticmethod
    def add_cmd(port: str) -> List[str]:
        return ["nft", "add", "element", "bridge", TABLE, SET, "{ %s }" % _check_ifname(port)]

    @staticmethod
    def del_cmd(port: str) -> List[str]:
        return ["nft", "delete", "element", "bridge", TABLE, SET, "{ %s }" % _check_ifname(port)]

    # ----- backend -----
    def setup(self) -> None:
        self._run(["nft", "-f", "-"], self.ruleset())
        self._isolated.clear()

    def isolate(self, port: str) -> bool:
        if port in self._isolated:
            return False
        self._run(self.add_cmd(port), None)
        self._isolated.add(port)
        return True

    def release(self, port: str) -> bool:
        if port not in self._isolated:
            return False
        self._run(self.del_cmd(port), None)
        self._isolated.discard(port)
        return True

    def isolated(self) -> Set[str]:
        return set(self._isolated)

    def drops(self) -> Optional[int]:
        try:
            out = self._run(["nft", "-j", "list", "chain", "bridge", TABLE, CHAIN], None)
        except Exception:
            return None
        total = 0
        for item in json.loads(out).get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    total += expr["counter"].get("packets", 0)
        return total

    def teardown(self) -> None:
        try:
            self._run(["nft", "delete", "table", "bridge", TABLE], None)
        except Exception:
            pass
        self._isolated.clear()


# --------------------------------------------------------------------------- responder

@dataclass
class _Isolation:
    port: str
    since: float
    release_at: float
    reason: str


class PortResponder:
    """Turns alerts into isolation actions (FR-X1).

    HIGH alerts isolate the offending port immediately. With escalate_windows>0,
    a pseudonym that trips its rate threshold for that many consecutive windows
    is escalated and its port isolated too (contain a compromised enrolled
    device, G4). Each isolation auto-releases after ``cooldown`` seconds; a
    renewed alert re-isolates. The router port is never isolated.
    """

    def __init__(self, isolator: Isolator, cooldown: float = 30.0,
                 clock: Callable[[], float] = None, wall: Callable[[], float] = None,
                 protected: Optional[Set[str]] = None, escalate_windows: int = 0,
                 sink: Optional[TextIO] = None, echo: bool = True) -> None:
        import time
        self.isolator = isolator
        self.cooldown = cooldown
        self.clock = clock or time.monotonic
        self.wall = wall or time.time
        self.protected = set(protected or ())
        self.escalate_windows = escalate_windows
        self._active: Dict[str, _Isolation] = {}
        self._streak: Dict[str, int] = {}
        self._last_rate: Dict[str, float] = {}
        self.requests: Dict[str, int] = {}
        self.actions: List[dict] = []
        self._sink = sink
        self.echo = echo
        isolator.setup()

    def on_alert(self, alert: Alert, now: float) -> None:
        if alert.severity == HIGH:
            self._isolate(alert.port, now, alert, alert.detector)
            return
        if self.escalate_windows and alert.detector == "rate" and alert.label:
            key = alert.who
            last = self._last_rate.get(key)
            self._streak[key] = (self._streak.get(key, 0) + 1) if (last is not None and now - last <= 3 * 5.0) else 1
            self._last_rate[key] = now
            if self._streak[key] >= self.escalate_windows:
                self._isolate(alert.port, now, alert, "sustained")

    def tick(self, now: float) -> None:
        for port in [p for p, iso in self._active.items() if now >= iso.release_at]:
            self._release(port, now, "cooldown")

    def _isolate(self, port: str, now: float, alert: Alert, reason: str) -> None:
        if port in self.protected:
            self._log("skip", port, now, alert, reason="protected:" + reason)
            return
        existing = self._active.get(port)
        if existing is not None:
            existing.release_at = now + self.cooldown      # extend on renewed alert
            return
        try:
            newly = self.isolator.isolate(port)
        except Exception as exc:                            # don't let a failed nft kill the monitor
            self._log("error", port, now, alert, reason=str(exc))
            return
        if newly:
            self._active[port] = _Isolation(port, now, now + self.cooldown, reason)
            self.requests[port] = self.requests.get(port, 0) + 1
            self._log("isolate", port, now, alert, reason=reason)

    def _release(self, port: str, now: float, reason: str) -> None:
        iso = self._active.pop(port, None)
        try:
            self.isolator.release(port)
        except Exception as exc:
            self._log("error", port, now, None, reason="release:" + str(exc))
            return
        self._log("release", port, now, None, reason=reason,
                  held=round(now - iso.since, 2) if iso else None)

    def _log(self, action: str, port: str, now: float, alert: Optional[Alert], **extra) -> None:
        rec = {"t": round(now, 3), "ts": round(self.wall(), 3), "action": action, "port": port}
        if alert is not None:
            rec.update({k: v for k, v in
                        (("severity", alert.severity), ("detector", alert.detector),
                         ("label", alert.label), ("tenant", alert.tenant), ("epoch", alert.epoch))
                        if v is not None})
        rec.update({k: v for k, v in extra.items() if v is not None})
        drops = self.isolator.drops()
        if drops is not None and action in ("release", "isolate"):
            rec["drops_total"] = drops
        self.actions.append(rec)
        if self._sink:
            self._sink.write(json.dumps(rec, sort_keys=True) + "\n")
            self._sink.flush()
        if self.echo:
            held = (" held=%ss" % rec["held"]) if "held" in rec else ""
            print("[%8.2f] ACTION %-8s port=%s reason=%s%s" % (now, action, port, rec.get("reason", ""), held),
                  file=sys.stderr, flush=True)

    def shutdown(self, now: Optional[float] = None) -> None:
        now = self.clock() if now is None else now
        for port in list(self._active):
            self._release(port, now, "shutdown")
        self.isolator.teardown()
