#!/usr/bin/env python3
"""FR-X2 helper: count ND frames reaching a victim, per interval, as CSV.

Run inside a victim namespace; counts frames arriving on eth0 whose Ethernet
source matches --source-mac (the attacker). Prints `t,count` lines so the drop
after isolation is visible.

  sudo ip netns exec d2 .venv/bin/python lab/victim_counter.py \
       --source-mac 02:4d:46:00:00:66 --duration 60 --interval 1
"""

from __future__ import annotations

import argparse
import socket
import sys
import time

ETH_P_IPV6 = 0x86DD


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--source-mac", required=True, help="count frames from this Ethernet source")
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--interval", type=float, default=1.0)
    args = ap.parse_args(argv)
    want = bytes.fromhex(args.source_mac.replace(":", ""))

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IPV6))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
    s.bind((args.iface, 0))
    s.setblocking(False)

    print("t,count", flush=True)
    start = time.monotonic()
    end = start + args.duration
    bucket_end = start + args.interval
    count = 0
    while True:
        now = time.monotonic()
        if now >= bucket_end:
            print("%.1f,%d" % (bucket_end - start, count), flush=True)
            count = 0
            bucket_end += args.interval
            if bucket_end > end + args.interval:
                break
        try:
            while True:
                frame = s.recv(2048)
                if frame[6:12] == want:
                    count += 1
        except BlockingIOError:
            time.sleep(min(0.02, max(0.0, bucket_end - time.monotonic())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
