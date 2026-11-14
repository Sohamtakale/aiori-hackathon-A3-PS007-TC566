#!/usr/bin/env bash
# Tear down the Mayfly lab. Only removes namespaces recorded by up.sh, and only
# if their names belong to this lab. Never touches host-namespace interfaces.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_root

if [[ ! -f $STATE_DIR/namespaces ]]; then
    log "no lab state in $STATE_DIR; nothing to do"
    exit 0
fi

ours=" $(all_namespaces) "
mapfile -t recorded < "$STATE_DIR/namespaces"

# Kill anything running inside the lab namespaces (radvd, emulator, attacks...).
for ns in "${recorded[@]}"; do
    [[ -n $ns && $ours == *" $ns "* ]] || continue
    ns_exists "$ns" || continue
    pids=$(ip netns pids "$ns" || true)
    if [[ -n $pids ]]; then
        log "stopping processes in '$ns': $(echo $pids)"
        kill $pids 2>/dev/null || true
        sleep 0.3
        pids=$(ip netns pids "$ns" || true)
        [[ -z $pids ]] || kill -9 $pids 2>/dev/null || true
    fi
done

# Deleting a namespace removes its end of each veth pair, and with it the peer.
for ns in "${recorded[@]}"; do
    [[ -n $ns ]] || continue
    if [[ $ours != *" $ns "* ]]; then
        warn "state lists unknown namespace '$ns'; leaving it alone"
        continue
    fi
    if ns_exists "$ns"; then
        log "deleting namespace '$ns'"
        ip netns del "$ns"
    fi
done

rm -f "$RADVD_CONF" "$RADVD_PID" "$RADVD_LOG"
rm -rf "$STATE_DIR"
log "lab is down"
