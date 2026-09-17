#!/bin/sh
# Configure Linux tc/netem inside one OrionLink container.
#
# set-egress delays every packet leaving the selected interface. Applying the
# same delay to all OrionLink containers adds it once in each direction of a
# container-to-container exchange.
set -eu

iface="${ORION_NETEM_IFACE:-eth0}"

usage() {
    cat <<'EOF'
Usage:
  orion-netem set-egress DELAY [JITTER]
  orion-netem clear
  orion-netem status
  orion-netem apply-env

DELAY and JITTER are non-negative integer durations such as 40ms, 500us, or 1s.
A bare integer is interpreted as milliseconds.

Environment mode (used by the AE image entrypoint):
  ORION_NETEM_DELAY=20ms
  ORION_NETEM_JITTER=2ms              # optional
  ORION_NETEM_IFACE=eth0              # default

The container must have the NET_ADMIN capability.
EOF
}

die() {
    echo "orion-netem: $*" >&2
    exit 2
}

require_tools() {
    command -v tc >/dev/null 2>&1 || die "tc is unavailable; install iproute2"
    command -v ip >/dev/null 2>&1 || die "ip is unavailable; install iproute2"
    ip link show dev "$iface" >/dev/null 2>&1 || die "network interface '$iface' does not exist"
}

duration() {
    value="$1"
    case "$value" in
        *ms) number=${value%ms}; unit=ms ;;
        *us) number=${value%us}; unit=us ;;
        *s)  number=${value%s};  unit=s ;;
        *)   number=$value;      unit=ms ;;
    esac
    case "$number" in
        ""|*[!0-9]*) die "invalid duration '$value'" ;;
    esac
    printf '%s%s' "$number" "$unit"
}

clear_qdisc() {
    # Deleting the default/noqueue qdisc can legitimately fail; the desired
    # postcondition is simply that no OrionLink root qdisc remains.
    tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
}

set_egress() {
    delay=$(duration "$1")
    jitter="${2:-}"
    clear_qdisc
    if [ -n "$jitter" ]; then
        jitter=$(duration "$jitter")
        tc qdisc add dev "$iface" root netem delay "$delay" "$jitter"
    else
        tc qdisc add dev "$iface" root netem delay "$delay"
    fi
    echo "orion-netem: $iface all-egress delay=$delay${jitter:+ jitter=$jitter}"
}

apply_env() {
    set_egress "$ORION_NETEM_DELAY" "${ORION_NETEM_JITTER:-}"
}

case "${1:-}" in
    set-egress)
        [ "$#" -ge 2 ] && [ "$#" -le 3 ] || { usage >&2; exit 2; }
        require_tools
        set_egress "$2" "${3:-}"
        ;;
    clear)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        require_tools
        clear_qdisc
        echo "orion-netem: cleared $iface"
        ;;
    status)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        require_tools
        tc qdisc show dev "$iface"
        ;;
    apply-env)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        if [ -n "${ORION_NETEM_DELAY:-}" ]; then
            require_tools
            apply_env
        fi
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
