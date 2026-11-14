# Shared helpers for the lab scripts. Source, don't execute.
# shellcheck shell=bash

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab.env
. "$LAB_DIR/lab.env"

RADVD="${RADVD:-$(command -v radvd || true)}"

log()  { printf '[lab] %s\n' "$*"; }
warn() { printf '[lab] WARNING: %s\n' "$*" >&2; }
die()  { printf '[lab] ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "run as root: sudo $0"
}

# Every namespace this lab owns, switch first.
all_namespaces() {
    echo "$SW_NS $ROUTER_NS $DEVICES $ATTACKER_NS"
}

# Nodes attached to the bridge (each gets veth v<name> in $SW_NS <-> eth0 in <name>).
all_nodes() {
    echo "$ROUTER_NS $DEVICES $ATTACKER_NS"
}

ns_exists() {
    ip netns list | awk '{print $1}' | grep -qx -- "$1"
}

nsx() {            # run a command inside a namespace
    local ns=$1; shift
    ip netns exec "$ns" "$@"
}

nssysctl() {       # set sysctls inside a namespace (never on the host)
    local ns=$1; shift
    ip netns exec "$ns" sysctl -q -w "$@" >/dev/null
}

mac_for() {
    case "$1" in
        d[1-5])   printf '%s:%02x' "$MAC_PREFIX" "${1#d}" ;;
        "$ROUTER_NS")   printf '%s:fe' "$MAC_PREFIX" ;;
        "$ATTACKER_NS") printf '%s:66' "$MAC_PREFIX" ;;
        *) die "no MAC for $1" ;;
    esac
}

port_for() {       # host-side (switch-side) veth name for a node
    echo "v$1"
}
