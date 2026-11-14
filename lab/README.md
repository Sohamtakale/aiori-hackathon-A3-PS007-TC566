# lab/

Isolated IPv6 test LAN built from network namespaces (PRD FR-E1, section 10).

```sh
sudo dnf install radvd        # once
sudo lab/up.sh                # build (re-run to rebuild from scratch)
sudo lab/check.sh             # 43 checks: topology, SLAAC, reachability, no way out
sudo lab/down.sh              # remove everything
```

## Topology

```
 d1 d2 d3 (Tenant A)   d4 d5 (Tenant B)   router (radvd)   attacker
  |  |  |               |  |               |                 |
 eth0 in each namespace, veth pair to a port in namespace "sw"
  |  |  |               |  |               |                 |
 vd1 vd2 vd3           vd4 vd5           vrouter         vattacker
 '----------------------- br0 (namespace sw) --------------------'
```

- Prefix `fd4d:6179:666c:1::/64` (ULA), router `fe80::1` / `fd4d:6179:666c:1::1`.
- Devices use SLAAC with random IIDs (`addrgenmode random`, no MAC-derived EUI-64).
  Kernel temporary addresses are off; the rotation emulator (step 3) manages them.
- MACs are fixed: `02:4d:46:00:00:0N` for dN, `:fe` router, `:66` attacker.

## Why the bridge is in its own namespace

The PRD puts the monitor "on the host". Here the host side of the lab is the
`sw` namespace instead of the real host namespace, because then:

- nothing is added to the host's `ip link`, so the real interfaces,
  NetworkManager and firewalld never see the lab;
- if docker loads `br_netfilter`, bridged frames would otherwise go through
  firewalld's forward chain (default reject) and break ND in the lab;
- step 6's nftables bridge rules live in `sw` and can't clash with firewalld.

Run the monitor with `sudo ip netns exec sw ...`; it still sees one veth per
port (`vd1`..`vattacker`), so ingress port is known.

## Safety

- `up.sh` refuses to run if any lab namespace name already exists and wasn't created by it.
- `down.sh` only deletes namespaces recorded in `/run/mayfly-lab/namespaces` that
  have a lab name, and kills processes running inside them first.
- All sysctls are set inside lab namespaces, never on the host.
- SELinux: radvd runs confined (`radvd_t`); its config, pid and log go in
  `/run/radvd/`, which the policy labels `radvd_var_run_t`. If it fails to
  start: `sudo ausearch -m avc -ts recent`.

## Rotation emulator (step 3)

```sh
sudo lab/up.sh
sudo .venv/bin/python lab/rotation.py --duration 300 --seed 1        # scripted Mayfly addresses
sudo .venv/bin/python lab/rotation.py --mode kernel --duration 300   # Linux privacy extensions
.venv/bin/python lab/verify_rotation.py runs/<run-dir>               # check the acceptance criteria
.venv/bin/python lab/rotation.py --dry-run --duration 300            # no root: simulated clock
```

**Scripted mode** (FR-E2, FR-K3). Each device enrolls (new 48-bit label), turns
off kernel SLAAC (`autoconf=0`) and, every U[1 s, epoch] seconds, adds a fresh
resolvable Mayfly address. The previous address stays preferred for 2 s while
the new one finishes DAD, is then deprecated, and is removed just before it
leaves the resolver's {e, e-1} window, so every address resolves for its whole
life. At the session TTL the device re-enrolls with a new label. The kernel
lifetimes on each address are set as a safety net, so addresses expire even if
the emulator is killed. On exit all Mayfly addresses are removed and
`autoconf=1` is restored.

`--max-interval` may not exceed `--epoch` (decision (a) from step 1). To test
slower rotation, raise `--epoch` too.

**Kernel mode**. `use_tempaddr=2` with `temp_prefered_lft=30`, `temp_valid_lft=60`,
`max_desync_factor=2`; the emulator only observes and logs. Values below about
10 s are refused (the kernel needs preferred > desync + regen advance).
Defaults are restored on exit.

**Output** `runs/<time>-<mode>-s<seed>/`:

- `rotation.jsonl`: ground truth, one JSON event per line: `run` header,
  `enroll`, `add` (device, tenant, label, epoch, addr), `deprecate`, `remove`,
  `session_end`, `stop`. Times `t` are seconds from start.
- `resolver.jsonl` (scripted): at each add and before each removal, what the
  in-process monitor resolved under the device's own tenant and the other one.

Both contain raw addresses: they are the experimenter's ground truth, not
monitor logs (FR-U2 applies to the monitor), and `runs/` is git-ignored.
Until step 4, the emulator enrolls with an in-process stand-in monitor
(`LocalMonitor`); keys are derived from the seed so runs are reproducible.

## Monitor (step 4)

```sh
sudo lab/up.sh
sudo lab/run_monitor.sh                       # terminal 1: runs in namespace sw, Ctrl-C to stop
sudo .venv/bin/python lab/rotation.py --monitor /run/mayfly-lab/monitor.sock --duration 300   # terminal 2
.venv/bin/python lab/score_alerts.py runs/<…-monitor> runs/<…-scripted-s1>   # who was it really?
```

- One raw socket per bridge port (`ETH_P_ALL` + a BPF filter for IPv6; a
  bridge port hides frames from protocol-specific sockets). Only frames the
  node sent are counted, so the ingress port is known.
- Enrollment: devices do the X25519 handshake over `/run/mayfly-lab/monitor.sock`
  (mode 0600). `--epoch/--ttl/--grace` must match on monitor and emulator; the
  emulator refuses to run if they don't.
- Detectors (5 s sliding window, global thresholds, `--threshold NS=80` to change):
  - rate per pseudonym when the source resolves (medium), per port when it doesn't (high);
  - rogue RA rules R1 wrong port, R2 wrong source, R3 prefix not allowed, R4 lifetime 0 / high
    preference from a non-router (high).
- Output `runs/<time>-monitor/`: `alerts.jsonl` (label, tenant, epoch, type, port,
  time, count only; no addresses; entries older than the session TTL are dropped)
  and `summary.json` (per-port ND counts).
- High alerts are counted as isolation requests; actual isolation is step 6.

## Port isolation (step 6)

```sh
sudo lab/run_monitor.sh --isolate --cooldown 30                 # high alerts isolate
sudo lab/run_monitor.sh --isolate --escalate-windows 3          # also contain a sustained pseudonym flood
sudo lab/run_monitor.sh --dry-run-isolation                     # just log the nft commands
sudo lab/measure_isolation.sh 40                                # FR-X2: measure victim traffic before/after
```

Isolation uses an **nftables bridge rule**, not `bridge link set ... isolated`:

```
table bridge mayfly {
    set isolated { type ifname; }
    chain block {
        type filter hook prerouting priority -300; policy accept;
        iifname @isolated counter drop        # drops every frame ingressing on an isolated veth
    }
}
```

Isolating a port adds its ifname to the `isolated` set; releasing removes it.
The `counter` measures attack frames dropped (FR-X2). The monitor runs inside
the `sw` namespace, so the table lives there and never touches firewalld's host
tables or a real NIC; the table is removed on exit.

- High alerts (rogue RA, unbound flood) isolate the offending port at once.
- `--escalate-windows N`: a pseudonym that trips its rate threshold for N
  consecutive 5 s windows is escalated and its port isolated (contains a
  compromised enrolled device, whose per-pseudonym flood is otherwise medium).
- Auto-release after `--cooldown` seconds; a renewed alert extends it; a later
  alert re-isolates. The router port is never isolated.
- `runs/<…-monitor>/actions.jsonl` logs every isolate/release with the running
  drop counter; `summary.json` has `isolation_requests` and
  `frames_dropped_by_isolation`.
