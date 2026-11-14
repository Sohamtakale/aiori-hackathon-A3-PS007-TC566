"""Rotation emulator logic, run with --dry-run (simulated clock, in-memory addresses)."""

import json

import pytest

from lab import rotation
from lab.netops import FakeNet
from lab.topology import Topology
from lab.verify_rotation import verify
from mayfly.params import Params


def dry(tmp_path, *extra):
    args = rotation.parse_args(["--dry-run", "--out", str(tmp_path), *extra])
    return rotation.run(args)


def events(run_dir):
    return [json.loads(l) for l in (run_dir / "rotation.jsonl").read_text().splitlines()]


def test_topology_matches_lab_env():
    t = Topology.load()
    assert t.devices == ["d1", "d2", "d3", "d4", "d5"]
    assert [d for d in t.devices if t.tenants[d] == "A"] == ["d1", "d2", "d3"]
    assert t.prefix.endswith("::/64") and t.port("d1") == "vd1"


def test_five_minute_run_passes_acceptance(tmp_path):
    run_dir = dry(tmp_path, "--duration", "300", "--seed", "7")
    checks, _ = verify(run_dir)
    failed = [m for ok, m in checks if not ok]
    assert not failed, failed


def test_same_seed_same_ground_truth(tmp_path):
    a = events(dry(tmp_path / "a", "--duration", "120", "--seed", "3"))[1:]
    b = events(dry(tmp_path / "b", "--duration", "120", "--seed", "3"))[1:]
    c = events(dry(tmp_path / "c", "--duration", "120", "--seed", "4"))[1:]
    assert a == b
    assert a != c


def test_sessions_renew_at_ttl(tmp_path):
    run_dir = dry(tmp_path, "--duration", "200", "--epoch", "10", "--ttl", "60",
                  "--max-interval", "10", "--seed", "5")
    ev = events(run_dir)
    d1_labels = [e["label"] for e in ev if e["event"] == "enroll" and e["device"] == "d1"]
    assert len(d1_labels) >= 3 and len(set(d1_labels)) == len(d1_labels)
    assert any(e["event"] == "session_end" and e["reason"] == "ttl" for e in ev)
    checks, _ = verify(run_dir)
    assert all(ok for ok, _ in checks), [m for ok, m in checks if not ok]


@pytest.mark.parametrize("epoch", ["10", "60"])
def test_successor_ready_before_removal(tmp_path, epoch):
    """No gap: an address is only deprecated or removed once another address of the
    same device has existed for ROTATE_LEAD seconds (long enough to finish DAD)."""
    ev = events(dry(tmp_path, "--duration", "300", "--epoch", epoch, "--max-interval", epoch,
                    "--ttl", "120", "--seed", "9"))
    live = {}        # device -> {addr: added_at}
    deprecated = set()

    def has_ready_preferred(dev, t, exclude):
        return any(a != exclude and a not in deprecated and t - added >= rotation.ROTATE_LEAD - 0.01
                   for a, added in live[dev].items())

    for e in ev:
        if e["event"] == "add":
            live.setdefault(e["device"], {})[e["addr"]] = e["t"]
        elif e["event"] == "deprecate":
            assert has_ready_preferred(e["device"], e["t"], e["addr"]), e
            deprecated.add(e["addr"])
        elif e["event"] == "remove":
            del live[e["device"]][e["addr"]]
            if e["reason"] == "window":
                assert has_ready_preferred(e["device"], e["t"], e["addr"]), e


def test_interval_longer_than_epoch_rejected(tmp_path):
    with pytest.raises(ValueError):
        dry(tmp_path, "--max-interval", "120")
    assert not any(tmp_path.iterdir()), "no run directory for a rejected config"


def test_address_overlap_is_bounded():
    """At most a handful of addresses per device at once; all removed at stop."""
    topo = Topology.load()
    net = FakeNet(topo.prefix)
    params = Params()
    log = rotation.JsonlLog(None)
    mon = rotation.LocalMonitor(params, __import__("os").urandom)
    emu = rotation.ScriptedRotation(topo, net, mon, params, log, rotation.JsonlLog(None),
                                    seed=1, min_interval=1, max_interval=60)
    emu.start(0.0)
    peak = 0
    t = 0.0
    while t < 600:
        t += 0.25
        emu.step(t)
        peak = max(peak, max(len(net.addrs[d]) for d in topo.devices))
    assert 1 <= peak <= 120  # 1 s rotations could stack up to ~2 epochs' worth
    assert net.sysctls["d1"]["net.ipv6.conf.eth0.autoconf"] == "0"
    emu.stop(t)
    assert all(not net.addrs[d] for d in topo.devices)
    assert net.sysctls["d1"]["net.ipv6.conf.eth0.autoconf"] == "1"


def test_kernel_mode_validates_lifetimes():
    topo = Topology.load()
    with pytest.raises(ValueError):
        rotation.KernelRotation(topo, FakeNet(topo.prefix), rotation.JsonlLog(None), 5, 60, 2)
    with pytest.raises(ValueError):
        rotation.KernelRotation(topo, FakeNet(topo.prefix), rotation.JsonlLog(None), 30, 30, 2)
