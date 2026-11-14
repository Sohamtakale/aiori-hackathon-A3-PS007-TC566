# attacks/

Scapy attack scripts (PRD section 10). **Lab namespaces only** — every script
refuses to run in the host network namespace and only sends on the namespace's
`eth0` (the veth to `br0`). Run them with `sudo ip netns exec <ns>`.

Start the lab and monitor first (see `lab/README.md`), then:

| Script | PRD | What it does |
|---|---|---|
| `attacks.rogue_ra` | S3, T1 | forged Router Advertisements |
| `attacks.ndp_flood` | S4/S5, T2/T3 | NS/NA/RS floods |
| `attacks.replay` | S6, T4 | replay a stolen address on another port |

## Rogue RA (S3)

```sh
sudo ip netns exec attacker .venv/bin/python -m attacks.rogue_ra hijack --duration 10
sudo ip netns exec attacker .venv/bin/python -m attacks.rogue_ra kill   --duration 10
sudo ip netns exec attacker .venv/bin/python -m attacks.rogue_ra flood  --duration 10
```

- `hijack` bogus prefix, high preference → rules R1 R2 R3 R4
- `kill` real prefix, router lifetime 0 → R1 R2 R4
- `flood` 50 RA/s with the real prefix → R1 R2

All are HIGH severity → isolation request on the sending port.

## NDP flood (S4 / S5)

```sh
# S4: a compromised ENROLLED device. Floods NS while rotating its address every
# second; every packet still resolves to one pseudonym. Exclude it from the
# emulator: lab/rotation.py --devices d2,d3,d4,d5
sudo ip netns exec d1 .venv/bin/python -m attacks.ndp_flood rotating \
     --tenant A --rotate 1 --rate 150 --duration 60 --monitor /run/mayfly-lab/monitor.sock

# S5: an UNENROLLED spoofer. Random source IIDs -> UNBOUND -> per-port HIGH.
sudo ip netns exec attacker .venv/bin/python -m attacks.ndp_flood spoof --rate 150 --duration 30

# flood that follows the emulator's rotation, or a single fixed source:
sudo ip netns exec d1 .venv/bin/python -m attacks.ndp_flood follow --rate 150 --duration 30
sudo ip netns exec d1 .venv/bin/python -m attacks.ndp_flood fixed --source <addr> --rate 150
```

`--type ns|na|rs` picks the message type (default `ns`). `--rotate 1|5|15|60`
matches the PRD S4 sweep: a per-address baseline degrades as the attacker
rotates faster, Mayfly does not (one pseudonym throughout).

## Replay / address theft (S6)

```sh
sudo ip netns exec attacker .venv/bin/python -m attacks.replay --address <victim-addr> --duration 20
sudo ip netns exec attacker .venv/bin/python -m attacks.replay --sniff --duration 20   # grab one off the link
```

Replays a victim's still-resolvable address from the attacker's port. The
monitor resolves it to the **victim's** pseudonym while it arrives on the
**wrong port** — the address-on-two-ports signal FR-D4 is meant to catch
(FR-D4 is P1 and not wired into the monitor yet, so for now the replay shows up
as the victim's pseudonym flooding from the attacker's port).

## Checking results

```sh
.venv/bin/python lab/score_alerts.py runs/<…-monitor> runs/<…-scripted-sN>
```

joins the monitor's pseudonym-only alerts back to devices using the emulator's
ground truth. A self-enrolling attack (ndp_flood `rotating`) prints its own
label to stderr, since its enrollment is not in the emulator's log.
```
