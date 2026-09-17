#!/usr/bin/env bash
#
# OrionLink dev launcher — runs the Go code directly (no image build).
#   1. Loads .env (if present) so the shell, the Go servers and the TCA
#      container all see the same ORION_* deployment configuration.
#   2. Frees the configured ports (kills stray servers / old TCA container).
#   3. Starts TCA as a lightweight nginx container (static files, volume-mounted).
#   4. Builds the Go binary once and starts idp / broker / rp from it.
#   5. Waits until all four are reachable and prints the entry URL plus the
#      RP's registration state, which decides what you have to click first.
#
# Usage:  ./run.sh            # (re)start the whole stack
#         ./run.sh down       # stop everything
#         ./run.sh status      # what is up, and is the RP registered
#         ./run.sh logs       # follow idp/broker/rp output
#         ./run.sh reset      # stop + delete generated keys and registrations
#
# Servers run detached; logs go to /tmp/{idp,broker,rp}.log.
#
set -euo pipefail
cd "$(dirname "$0")"

BIN=/tmp/orionlink_app
TCA_NAME=orionlink-tca

# --- deployment configuration ------------------------------------------------
# .env is the single file an evaluator edits (see .env.example). Nothing else
# reads it — the Go binary takes plain environment variables — so the launcher
# is what turns it into process environment, for the servers and for the TCA
# container alike.
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
  echo "==> Loaded .env"
fi

export ORION_PROFILE="${ORION_PROFILE:-demo}"
export ORION_IDP_URL="${ORION_IDP_URL:-http://localhost:3000}"
export ORION_BROKER_URL="${ORION_BROKER_URL:-http://localhost:3001}"
export ORION_RP_URL="${ORION_RP_URL:-http://localhost:3002}"
export ORION_TCA_URL="${ORION_TCA_URL:-http://localhost:3003}"

# Ports are derived from the URLs rather than hardcoded, so moving the stack off
# 3000-3003 needs no edit here — exactly the property internal/config.ListenAddr
# provides on the Go side.
port_of() { # port_of <url> <default>
  local p
  p="$(printf '%s' "$1" | sed -nE 's#^https?://[^/:]+:([0-9]+).*#\1#p')"
  printf '%s' "${p:-$2}"
}
IDP_PORT="$(port_of "$ORION_IDP_URL" 3000)"
BROKER_PORT="$(port_of "$ORION_BROKER_URL" 3001)"
RP_PORT="$(port_of "$ORION_RP_URL" 3002)"
TCA_PORT="$(port_of "$ORION_TCA_URL" 3003)"
PORTS=("$IDP_PORT" "$BROKER_PORT" "$RP_PORT" "$TCA_PORT")

kill_port() {
  local port="$1" pids=""
  pids="$(ss -ltnpH "sport = :$port" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u || true)"
  if [ -z "$pids" ] && command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -ti "tcp:$port" -sTCP:LISTEN 2>/dev/null || true)"
  fi
  if [ -n "$pids" ]; then
    echo "  :$port  killing $(echo "$pids" | tr '\n' ' ')"
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
  fi
}

teardown() {
  echo "==> Stopping servers and freeing ports ${PORTS[*]}"
  pkill -9 -f "$BIN" 2>/dev/null || true
  pkill -9 -f 'go run main.go' 2>/dev/null || true
  docker rm -f "$TCA_NAME" >/dev/null 2>&1 || true
  for p in "${PORTS[@]}"; do kill_port "$p"; done
  sleep 1
}

registration_state() {
  curl -sf "$ORION_RP_URL/ssso/registration/status" 2>/dev/null || true
}

case "${1:-}" in
  down)
    teardown
    echo "Stopped."
    exit 0
    ;;

  reset)
    # Generated keys and registrations bind to the URLs that were configured
    # when they were written, so a stale set survives a URL change and produces
    # a permanently greyed-out Login button with nothing in the UI explaining
    # why. Deleting them is the supported way back to a clean deployment; they
    # are untracked by git precisely so this is safe.
    teardown
    echo "==> Deleting generated runtime state"
    rm -fv ./*/config/key_storage.json ./*/config/registration_data.json \
           IdP/config/Register_user.json 2>/dev/null || true
    [ -n "${ORION_DATA_DIR:-}" ] && [ -d "${ORION_DATA_DIR}" ] &&
      rm -rfv "${ORION_DATA_DIR}"/{IdP,Broker,RP} || true
    echo "Reset. Run ./run.sh to start fresh (the RP must register again)."
    exit 0
    ;;

  status)
    echo "profile=$ORION_PROFILE"
    for spec in "IdP:$ORION_IDP_URL/ssso/pubkeys" \
                "Broker:$ORION_BROKER_URL/ssso/.well-known/openid-configuration" \
                "RP:$ORION_RP_URL/ssso/login" \
                "TCA:$ORION_TCA_URL/dvf.html"; do
      name="${spec%%:*}"; url="${spec#*:}"
      if curl -sf -o /dev/null "$url"; then echo "  $name  up   ($url)"; else echo "  $name  DOWN ($url)"; fi
    done
    echo "  registration: $(registration_state)"
    exit 0
    ;;

  logs)
    # Live, colour-labelled combined output of the three servers.
    # Ctrl-C stops watching; the servers keep running.
    echo "Tailing idp / broker / rp — Ctrl-C to stop watching (servers keep running)."
    touch /tmp/idp.log /tmp/broker.log /tmp/rp.log
    tail -n 20 -f /tmp/idp.log    | sed -u $'s/^/\033[36m[idp]    \033[0m/' &
    tail -n 20 -f /tmp/broker.log | sed -u $'s/^/\033[33m[broker] \033[0m/' &
    tail -n 20 -f /tmp/rp.log     | sed -u $'s/^/\033[35m[rp]     \033[0m/' &
    trap 'kill $(jobs -p) 2>/dev/null' INT TERM
    wait
    exit 0
    ;;
esac

# --- preflight ---------------------------------------------------------------
# The TCA serves its cryptography from a committed, SRI-pinned bundle. A missing
# bundle or a stale hash fails at the network layer inside the iframe — the
# browser just refuses the script — so both are worth catching before launch
# rather than debugging as "consent page does nothing".
if [ ! -f tca/vendor/crypto-deps.js ]; then
  echo "==> tca/vendor/crypto-deps.js missing — building it"
  ./tca/build-vendor.sh
  ./tca/update-sri.sh
fi
./tca/update-sri.sh --check || {
  echo "    (run ./tca/update-sri.sh, then restart)" >&2
  exit 1
}

teardown

echo "==> Starting TCA (nginx :$TCA_PORT)"
# The entrypoint mount is not optional: it renders /orion-config.js (the pages
# read window.ORION at evaluation time) and the Content-Security-Policy, whose
# frame-ancestors names the IdP origin. Without it the TCA serves a 404 for its
# config and every login fails inside the iframe.
docker run -d --rm --name "$TCA_NAME" -p "$TCA_PORT:3003" \
  -e ORION_IDP_URL -e ORION_BROKER_URL -e ORION_RP_URL -e ORION_TCA_URL \
  -e ORION_PROFILE \
  -v "$PWD/tca:/usr/share/nginx/html:ro" \
  -v "$PWD/tca/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$PWD/tca/docker-entrypoint.d/40-orion-config.sh:/docker-entrypoint.d/40-orion-config.sh:ro" \
  nginx:alpine >/dev/null

echo "==> Building Go binary"
go build -o "$BIN" .

# start a role detached, surviving this script's exit
start_role() {
  local role="$1"
  echo "==> Starting $role"
  setsid nohup "$BIN" -name="$role" >"/tmp/${role}.log" 2>&1 < /dev/null &
}

wait_up() {
  local name="$1" url="$2"
  for _ in $(seq 1 60); do
    if curl -sf -o /dev/null "$url"; then echo "  $name  OK"; return 0; fi
    sleep 1
  done
  echo "  $name  TIMED OUT (see /tmp log)"; return 1
}

# Start order matters: the RP fetches the IdP's PS verification keys at startup
# and exits if they are unavailable, and the broker likewise needs the IdP.
start_role idp
wait_up "IdP    ($IDP_PORT)" "$ORION_IDP_URL/ssso/pubkeys"
start_role broker
wait_up "Broker ($BROKER_PORT)" "$ORION_BROKER_URL/ssso/.well-known/openid-configuration"
start_role rp
wait_up "RP     ($RP_PORT)" "$ORION_RP_URL/ssso/login"
curl -sf -o /dev/null "$ORION_TCA_URL/dvf.html" \
  && echo "  TCA    ($TCA_PORT)  OK" || echo "  TCA    ($TCA_PORT)  starting…"

# --- what to click -----------------------------------------------------------
# Under the demo profile the RP does NOT auto-register: registration is one of
# the protocol steps worth watching, so it is left as a click. Which means the
# first thing to say is whether it has already happened in this data directory.
REG="$(registration_state)"
case "$REG" in
  *'"registered":true'*) REG_LINE="RP already registered — go straight to Login." ;;
  *) REG_LINE="RP NOT registered yet — open $ORION_RP_URL/ssso/register and click
  \"Register to IdP\" then \"Register to Broker\" first (or restart with
  ORION_AUTO_REGISTER=1 ./run.sh to have it done at startup)." ;;
esac

cat <<EOF

============================================================
  OrionLink is up (profile=$ORION_PROFILE).

  $REG_LINE

  Then log in:   $ORION_RP_URL/ssso/login

  Demo account:  username = Alice   password = Alice-pass
  (any PIN works on first consent)

  Remote / port-forwarded? Forward ALL FOUR ports
  $IDP_PORT $BROKER_PORT $RP_PORT $TCA_PORT — the consent page loads the TCA
  iframe from :$TCA_PORT, so a missing forward shows "refused to connect"
  inside the iframe.

  Watch all three servers' output (colour-labelled, live):
      ./run.sh logs        (or: tail -f /tmp/rp.log)
  Check state:  ./run.sh status
  Start over:   ./run.sh reset     Stop:  ./run.sh down
============================================================
EOF
