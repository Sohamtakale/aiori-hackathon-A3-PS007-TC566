"""Isolation backends and the alert -> isolation policy (FR-X1), without root."""

import json

import pytest

from mayfly.detectors import Alert, HIGH, MEDIUM
from mayfly.response import (FakeIsolator, NftablesIsolator, PortResponder, SET, TABLE)


def high(port, detector="rate", label=None, t=0.0):
    return Alert(t=t, ts=1.7e9, detector=detector, severity=HIGH, msg_type="NS", port=port, label=label)


def medium_rate(port, label, tenant="A", t=0.0):
    return Alert(t=t, ts=1.7e9, detector="rate", severity=MEDIUM, msg_type="NS", port=port,
                 label=label, tenant=tenant, count=51, threshold=50)


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


# --------------------------------------------------------------- nft command shapes

def test_nft_commands():
    assert NftablesIsolator.add_cmd("vd1") == ["nft", "add", "element", "bridge", TABLE, SET, "{ vd1 }"]
    assert NftablesIsolator.del_cmd("vattacker")[:3] == ["nft", "delete", "element"]
    rs = NftablesIsolator.ruleset()
    assert "table bridge mayfly" in rs and "iifname @isolated counter drop" in rs
    assert "prerouting priority -300" in rs
    # must NOT use kernel port isolation
    assert "isolated" in rs and "bridge link" not in rs and "type bridge_slave" not in rs


def test_nft_rejects_bad_ifname():
    for bad in ["v; rm -rf", "eth0 drop", "a" * 16, ""]:
        with pytest.raises(ValueError):
            NftablesIsolator.add_cmd(bad)


def test_nftables_isolator_runs_expected_commands():
    cmds = []
    iso = NftablesIsolator(runner=lambda argv, stdin: cmds.append((argv, stdin)) or "")
    iso.setup()
    assert iso.isolate("vd1") is True
    assert iso.isolate("vd1") is False          # idempotent
    assert iso.release("vd1") is True
    assert iso.release("vd1") is False
    kinds = [c[0][1] if c[0][0] == "nft" and c[0][1] in ("add", "delete") else c[0][0] for c in cmds]
    assert kinds == ["nft", "add", "delete"]    # setup via -f, then add, then delete element


# --------------------------------------------------------------- responder policy

def test_high_alert_isolates_and_auto_releases():
    iso = FakeIsolator()
    r = PortResponder(iso, cooldown=10.0, echo=False)
    r.on_alert(high("vattacker", detector="rogue_ra"), now=1.0)
    assert iso.isolated() == {"vattacker"}
    assert r.requests["vattacker"] == 1
    r.tick(now=5.0)
    assert iso.isolated() == {"vattacker"}       # still within cooldown
    r.tick(now=11.5)
    assert iso.isolated() == set()               # auto-released
    assert [a["action"] for a in r.actions] == ["isolate", "release"]
    assert r.actions[1]["reason"] == "cooldown"


def test_renewed_alert_extends_cooldown():
    iso = FakeIsolator()
    r = PortResponder(iso, cooldown=10.0, echo=False)
    r.on_alert(high("vattacker"), now=0.0)
    r.on_alert(high("vattacker"), now=8.0)       # extends release to 18
    r.tick(now=11.0)
    assert iso.isolated() == {"vattacker"}
    r.tick(now=18.5)
    assert iso.isolated() == set()
    assert sum(a["action"] == "isolate" for a in r.actions) == 1   # not re-isolated


def test_reisolate_after_release():
    iso = FakeIsolator()
    r = PortResponder(iso, cooldown=5.0, echo=False)
    r.on_alert(high("vattacker"), now=0.0)
    r.tick(now=6.0)
    assert iso.isolated() == set()
    r.on_alert(high("vattacker"), now=7.0)
    assert iso.isolated() == {"vattacker"}
    assert r.requests["vattacker"] == 2


def test_router_port_is_protected():
    iso = FakeIsolator()
    r = PortResponder(iso, protected={"vrouter"}, echo=False)
    r.on_alert(high("vrouter", detector="rogue_ra"), now=1.0)
    assert iso.isolated() == set()
    assert r.actions[0]["action"] == "skip" and "protected" in r.actions[0]["reason"]


def test_medium_rate_does_not_isolate_by_default():
    iso = FakeIsolator()
    r = PortResponder(iso, echo=False)
    for t in range(10):
        r.on_alert(medium_rate("vd1", "abc", t=t * 5.0), now=t * 5.0)
    assert iso.isolated() == set()


def test_escalation_isolates_sustained_pseudonym_flood():
    iso = FakeIsolator()
    r = PortResponder(iso, escalate_windows=3, echo=False)
    r.on_alert(medium_rate("vd1", "abc", t=0.0), now=0.0)
    r.on_alert(medium_rate("vd1", "abc", t=5.0), now=5.0)
    assert iso.isolated() == set()               # 2 windows, not yet
    r.on_alert(medium_rate("vd1", "abc", t=10.0), now=10.0)
    assert iso.isolated() == {"vd1"}             # 3rd consecutive window -> escalate
    assert r.actions[-1]["reason"] == "sustained"


def test_escalation_streak_resets_on_gap():
    iso = FakeIsolator()
    r = PortResponder(iso, escalate_windows=3, echo=False)
    r.on_alert(medium_rate("vd1", "abc", t=0.0), now=0.0)
    r.on_alert(medium_rate("vd1", "abc", t=100.0), now=100.0)   # long gap resets streak
    r.on_alert(medium_rate("vd1", "abc", t=105.0), now=105.0)
    assert iso.isolated() == set()


def test_failed_isolation_does_not_crash():
    class Broken(FakeIsolator):
        def isolate(self, port):
            raise RuntimeError("nft boom")
    r = PortResponder(Broken(), echo=False)
    r.on_alert(high("vattacker"), now=1.0)        # must be swallowed
    assert r.actions[-1]["action"] == "error"


def test_action_log_written(tmp_path):
    iso = FakeIsolator()
    path = tmp_path / "actions.jsonl"
    with open(path, "w") as fh:
        r = PortResponder(iso, cooldown=5.0, clock=Clock(), wall=lambda: 1.7e9, sink=fh, echo=False)
        r.on_alert(high("vattacker", detector="rogue_ra"), now=1.0)
        r.tick(now=7.0)
        r.shutdown(now=8.0)
    recs = [json.loads(l) for l in path.read_text().splitlines()]
    assert [x["action"] for x in recs] == ["isolate", "release"]
    assert all({"t", "ts", "action", "port"} <= set(x) for x in recs)
    assert iso.calls[-1] == ("teardown",)


def test_shutdown_releases_all():
    iso = FakeIsolator()
    r = PortResponder(iso, echo=False)
    r.on_alert(high("vattacker"), now=0.0)
    r.on_alert(high("vd1"), now=0.0)
    assert iso.isolated() == {"vattacker", "vd1"}
    r.shutdown(now=1.0)
    assert iso.isolated() == set() and ("teardown",) in iso.calls
