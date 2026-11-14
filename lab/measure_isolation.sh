#!/usr/bin/env bash
# FR-X2: measure attack traffic reaching a victim before and after L2 isolation.
#
# Starts the monitor with isolation on, floods from the attacker (unenrolled
# spoofer -> high severity -> isolation), and counts frames reaching victim d2.
# Writes a CSV time series and prints the before/after rates.
#
#   sudo lab/measure_isolation.sh [DURATION]
set -euo pipefail
. "$(dirname "$0")/lib.sh"
require_root
[[ -f $STATE_DIR/namespaces ]] || die "lab is not up: sudo lab/up.sh"

REPO="$(cd "$LAB_DIR/.." && pwd)"
PY="${PYTHON:-$REPO/.venv/bin/python}"
DURATION="${1:-40}"
VICTIM=d2
ATTACKER="$ATTACKER_NS"
ATT_MAC="$(printf '%s:66' "$MAC_PREFIX")"
OUT="$REPO/runs/measure-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

echo "[measure] monitor (isolation on, 5s cooldown) -> $OUT"
ip netns exec "$SW_NS" "$PY" -m mayfly.monitor \
    --ports "$(for n in $(all_nodes); do port_for "$n"; done | paste -sd, -)" \
    --router-port "$(port_for "$ROUTER_NS")" --router-ll "$ROUTER_LL" \
    --allowed-prefix "$LAB_PREFIX" --isolate --cooldown 5 \
    --duration "$((DURATION + 5))" --stats 0 --out "$OUT" >"$OUT/monitor.log" 2>&1 &
MON=$!
sleep 2

echo "[measure] counting frames from attacker ($ATT_MAC) reaching $VICTIM"
ip netns exec "$VICTIM" "$PY" "$LAB_DIR/victim_counter.py" \
    --source-mac "$ATT_MAC" --duration "$DURATION" --interval 1 >"$OUT/victim.csv" 2>/dev/null &
CTR=$!
sleep 3

echo "[measure] attacker floods for $((DURATION - 10))s (isolation should cut it off)"
ip netns exec "$ATTACKER" "$PY" -m attacks.ndp_flood spoof --rate 200 --duration "$((DURATION - 10))" || true

wait "$CTR" 2>/dev/null || true
kill "$MON" 2>/dev/null || true
wait "$MON" 2>/dev/null || true

ISO_T=$(grep -ho '"t": *[0-9.]*' "$OUT"/*-monitor/actions.jsonl 2>/dev/null | head -1 | grep -o '[0-9.]*' || true)
echo
echo "[measure] results in $OUT (victim.csv, actions.jsonl)"
"$PY" - "$OUT/victim.csv" <<'PYEOF'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1])))
vals = [(float(r["t"]), int(r["count"])) for r in rows if r["count"].isdigit()]
peak = max((c for _, c in vals), default=0)
# "after" = the tail once traffic has been cut
tail = [c for _, c in vals[-5:]]
print("  peak frames/s reaching victim : %d" % peak)
print("  last 5s frames/s              : %s" % tail)
print("  reduction after isolation     : %.0f%%" % (100 * (1 - (sum(tail)/len(tail))/peak)) if peak else "n/a")
PYEOF
echo "  isolation fired at t=${ISO_T:-?}s (see actions.jsonl)"
