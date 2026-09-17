#!/usr/bin/env bash
# Apply or inspect tc/netem consistently across the four running AE containers.
set -euo pipefail

cd "$(dirname "$0")"

COMPOSE_FILE="${ORION_COMPOSE_FILE:-docker-compose.yml}"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

usage() {
  cat <<'EOF'
Usage:
  ./netem-compose.sh set-egress DELAY [JITTER]
  ./netem-compose.sh clear
  ./netem-compose.sh status

Examples:
  ./netem-compose.sh set-egress 20ms
  ./netem-compose.sh set-egress 50ms 5ms
  ./netem-compose.sh clear

set-egress adds DELAY to every packet leaving every OrionLink container. For
container-to-container traffic, the added network RTT is approximately 2 x
DELAY because the request and response leave different containers.
EOF
}

case "${1:-}" in
  set-egress)
    [[ $# -ge 2 && $# -le 3 ]] || { usage >&2; exit 2; }
    delay="$2"; jitter="${3:-}"
    for service in tca idp broker rp; do
      args=(orion-netem set-egress "$delay")
      [[ -n "$jitter" ]] && args+=("$jitter")
      "${COMPOSE[@]}" exec -T "$service" "${args[@]}"
    done
    ;;
  clear)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    for service in tca idp broker rp; do
      "${COMPOSE[@]}" exec -T "$service" orion-netem clear
    done
    ;;
  status)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    for service in tca idp broker rp; do
      echo "===== $service ====="
      "${COMPOSE[@]}" exec -T "$service" orion-netem status
    done
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
