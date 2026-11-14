#!/usr/bin/env bash
# Start the Mayfly monitor inside the lab's switch namespace, capturing on every
# bridge port. Extra arguments go to the monitor, e.g. --duration 300 --threshold NS=80
#
#   sudo lab/run_monitor.sh
set -euo pipefail
. "$(dirname "$0")/lib.sh"
require_root
[[ -f $STATE_DIR/namespaces ]] || die "lab is not up: sudo lab/up.sh"

REPO="$(cd "$LAB_DIR/.." && pwd)"
PY="${PYTHON:-$REPO/.venv/bin/python}"
ports=$(for n in $(all_nodes); do port_for "$n"; done | paste -sd, -)

cd "$REPO"
exec ip netns exec "$SW_NS" "$PY" -m mayfly.monitor \
    --ports "$ports" \
    --router-port "$(port_for "$ROUTER_NS")" \
    --router-ll "$ROUTER_LL" \
    --allowed-prefix "$LAB_PREFIX" \
    --socket "$STATE_DIR/monitor.sock" \
    --out "$REPO/runs" \
    "$@"
