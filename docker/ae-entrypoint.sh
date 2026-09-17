#!/bin/sh
set -eu

role="${1:-}"

case "$role" in
    idp|broker|rp)
        shift
        /usr/local/bin/orion-netem apply-env
        exec /app/orionlink -name="$role" "$@"
        ;;
    tca)
        shift
        /usr/local/bin/orion-render-tca
        /usr/local/bin/orion-netem apply-env
        exec nginx -g 'daemon off;' "$@"
        ;;
    "")
        echo "usage: orion-entrypoint {idp|broker|rp|tca|COMMAND ...}" >&2
        exit 2
        ;;
    *)
        # Preserve normal container ergonomics for debugging, e.g.
        #   docker run --rm IMAGE orion-netem --help
        shift
        exec "$role" "$@"
        ;;
esac
