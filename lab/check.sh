#!/usr/bin/env bash
# Verify the lab: topology, SLAAC, on-link reachability, and that nothing can
# leave the lab. Read-only apart from a few pings inside the lab.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

require_root
pass=0; fail=0
ok()  { printf '  PASS  %s\n' "$*"; ((pass++)); }
bad() { printf '  FAIL  %s\n' "$*"; ((fail++)); }
check() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }

global_addr() { ip -n "$1" -6 -o addr show dev eth0 scope global -tentative | awk '{print $4}' | head -1 | cut -d/ -f1; }

echo "Host isolation"
check "no lab interfaces in the host namespace" \
    bash -c "! ip -o link show | awk -F': ' '{print \$2}' | cut -d@ -f1 | grep -qxE '$BRIDGE|v(d[1-5]|$ROUTER_NS|$ATTACKER_NS)'"

echo "Switch ($SW_NS)"
check "$BRIDGE exists and is up" bash -c "ip -n $SW_NS -o link show $BRIDGE | grep -q 'state UP\|,UP'"
nports=$(ip -n "$SW_NS" -o link show master "$BRIDGE" 2>/dev/null | wc -l)
[[ $nports -eq 7 ]] && ok "$BRIDGE has 7 ports" || bad "$BRIDGE has $nports ports, expected 7"
check "IPv6 disabled on $BRIDGE" bash -c "[[ \$(ip netns exec $SW_NS cat /proc/sys/net/ipv6/conf/$BRIDGE/disable_ipv6) == 1 ]]"
for node in $(all_nodes); do
    check "port $(port_for "$node") enslaved to $BRIDGE" \
        bash -c "ip -n $SW_NS -o link show $(port_for "$node") | grep -q 'master $BRIDGE'"
done

echo "Router ($ROUTER_NS)"
check "radvd running inside $ROUTER_NS" bash -c "[[ -s $RADVD_PID ]] && ip netns pids $ROUTER_NS | grep -qx \$(cat $RADVD_PID)"
check "router link-local is $ROUTER_LL" bash -c "ip -n $ROUTER_NS -6 -o addr show dev eth0 | grep -q ' $ROUTER_LL/64'"
links=$(ip -n "$ROUTER_NS" -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | sort | paste -sd' ')
[[ $links == "eth0 lo" ]] && ok "router has no uplink (links: $links)" || bad "router links: $links"

echo "Devices"
for node in $DEVICES $ATTACKER_NS; do
    a=$(global_addr "$node")
    if [[ $a == ${LAB_PREFIX%%::/*}:* ]]; then ok "$node SLAAC address $a"; else bad "$node has no SLAAC address in $LAB_PREFIX"; fi
    check "$node default route via $ROUTER_LL" bash -c "ip -n $node -6 route show default | grep -q 'via $ROUTER_LL'"
    check "$node pings router" nsx "$node" ping -6 -c1 -W2 "$ROUTER_ADDR"
done
d5=$(global_addr d5)
[[ -n $d5 ]] && check "d1 pings d5 ($d5) across the bridge" nsx d1 ping -6 -c1 -W2 "$d5"

echo "No external route"
for node in $(all_nodes); do
    other=$(ip -n "$node" -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -vxE 'lo|eth0' | paste -sd' ')
    [[ -z $other ]] && ok "$node has only lo + eth0" || bad "$node has extra links: $other"
done
check "router has no route to the Internet" \
    bash -c "! ip -n $ROUTER_NS -6 route get 2001:4860:4860::8888"
check "router has no IPv4 at all" bash -c "! ip -n $ROUTER_NS -4 -o addr show | grep -v ' lo '| grep -q inet"
check "d1 cannot reach 2001:4860:4860::8888" bash -c "! ip netns exec d1 ping -6 -c1 -W2 2001:4860:4860::8888"

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
