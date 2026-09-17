#!/usr/bin/env bash
#
# E3 — stress test of the AnonyAKA interface (paper §6, Fig. 8).
#
#   ./benchmark/run-e3.sh                 # 10/200 RPS, 60 s each (~8 min)
#   ./benchmark/run-e3.sh --quick         # 10/200 RPS, 15 s each (~2 min, smoke)
#   ./benchmark/run-e3.sh --duration 30   # same rates, shorter stages
#   ./benchmark/run-e3.sh --line idp      # one line only (idp|rp|broker, comma-separated)
#   ./benchmark/run-e3.sh --rps 75        # a single 75 RPS stage
#   ./benchmark/run-e3.sh --rps 100,500,1000,1300,1500   # the paper's ladder (Fig. 8)
#
# The default stops at 200 RPS on purpose. AAKA is pairing-bound (~24 ms of CPU
# per IdP request), so the stages from 500 RPS up need a machine with cores to
# spare — on a smaller one they measure the queue and drop iterations. Ask for
# them explicitly with --rps when the hardware sustains them.
#
# Runs the three k6 scripts under benchmark/e3/ back to back — one per line of
# Fig. 8 (IdP, RP, Broker) — and writes benchmark/results/e3-<script>-<profile>.json.
# Each script bootstraps its own request bodies against the running stack, so no
# fixture has to be captured or refreshed by hand.
#
# Requires the stack in bench profile (the load-test endpoints are off in demo):
#
#   ORION_PROFILE=bench ./run.sh
#
# k6 is used from PATH, or from the grafana/k6 container if it is not installed.
#
# Caveat worth keeping in mind when reading the numbers: k6 and the servers share
# this machine's CPU, and AAKA is pairing-heavy. At the top rate the client is a
# plausible bottleneck — for figures that go in the paper, drive the load from a
# second host (set ORION_*_URL accordingly).
set -euo pipefail
cd "$(dirname "$0")/.."

E3_LINES=(idp rp broker)
QUICK=0
DURATION=""
RPS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --quick)    QUICK=1; shift ;;
    --duration) DURATION="${2:-}"; shift 2 ;;
    --rps)      RPS="${2:-}"
                [[ "$RPS" =~ ^[0-9]+(,[0-9]+)*$ ]] || {
                  echo "--rps takes comma-separated request rates, e.g. --rps 10,200 (got '${RPS}')" >&2
                  exit 2
                }
                shift 2 ;;
    --line)     IFS=',' read -r -a E3_LINES <<< "${2:-}"
                for l in "${E3_LINES[@]}"; do
                  case "$l" in
                    idp|rp|broker) ;;
                    *) echo "--line takes idp, rp or broker (comma-separated), not '${l}'." >&2
                       echo "  to change the request rates, use --rps 10,200" >&2
                       exit 2 ;;
                  esac
                done
                shift 2 ;;
    -h|--help)  sed -n '2,25p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *)          echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ "$QUICK" -eq 1 ]; then
  : "${RPS:=10,200}"
  : "${DURATION:=15}"
  export ORION_E3_WARMUP="${ORION_E3_WARMUP:-3}"
  export ORION_E3_COOLDOWN="${ORION_E3_COOLDOWN:-5}"
  export ORION_E3_FIXTURES="${ORION_E3_FIXTURES:-5}"
fi
[ -n "$RPS" ] && export ORION_E3_RPS="$RPS"
[ -n "$DURATION" ] && export ORION_E3_DURATION="$DURATION"

export ORION_PROFILE="${ORION_PROFILE:-bench}"
export ORION_IDP_URL="${ORION_IDP_URL:-http://localhost:3000}"
export ORION_BROKER_URL="${ORION_BROKER_URL:-http://localhost:3001}"
export ORION_RP_URL="${ORION_RP_URL:-http://localhost:3002}"

E3_OUT_DIR="${ORION_E3_OUT_DIR:-benchmark/results}"
mkdir -p "$E3_OUT_DIR"

# The bench-only endpoints are the precondition, not just the ports: a stack
# started in demo profile answers on all three ports and 404s here.
probe="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${ORION_BROKER_URL}/ssso/randomizeRPIDForTest" || true)"
case "$probe" in
  200) ;;
  000) echo "broker unreachable at ${ORION_BROKER_URL} — start the stack: ORION_PROFILE=bench ./run.sh" >&2; exit 1 ;;
  404) echo "broker is up but /ssso/randomizeRPIDForTest is not mounted — the stack is not in bench profile." >&2
       echo "  restart it with: ORION_PROFILE=bench ./run.sh" >&2; exit 1 ;;
  *)   echo "broker /ssso/randomizeRPIDForTest returned ${probe} — has an RP registered? (see /tmp/rp.log)" >&2; exit 1 ;;
esac

# Local k6 if present; otherwise the container, with the repo mounted so the
# scripts' relative imports and the report path resolve the same way.
if command -v k6 >/dev/null 2>&1; then
  k6_run() { k6 run "$@"; }
else
  echo "k6 not on PATH — using the grafana/k6 container"
  k6_run() {
    docker run --rm --network host \
      -v "$PWD:/repo" -w /repo --user "$(id -u):$(id -g)" \
      -e ORION_PROFILE -e ORION_IDP_URL -e ORION_BROKER_URL -e ORION_RP_URL \
      -e ORION_E3_RPS -e ORION_E3_DURATION -e ORION_E3_WARMUP -e ORION_E3_COOLDOWN \
      -e ORION_E3_FIXTURES -e ORION_E3_ASSUMED_MS -e ORION_E3_OUT_DIR \
      -e ORION_E3_MAX_WAIT_S -e ORION_E3_VU_CAP \
      grafana/k6 run "$@"
  }
fi

script_for() {
  case "$1" in
    idp)    echo benchmark/e3/idp_token.js ;;
    rp)     echo benchmark/e3/rp_pok.js ;;
    broker) echo benchmark/e3/broker_randomize.js ;;
    *)      echo "unknown line: $1 (want idp|rp|broker)" >&2; return 1 ;;
  esac
}

section() { printf '\n\033[1m===== %s =====\033[0m\n' "$1"; }

FAILED=()
for line in "${E3_LINES[@]}"; do
  script="$(script_for "$line")"
  section "E3 — ${line} line"
  # A threshold breach (dropped iterations, errors) exits 99. That is a result,
  # not a crash: the report is still written and the remaining lines still run.
  if ! k6_run --quiet --no-usage-report "$script"; then
    FAILED+=("$line")
  fi
done

section "E3 reports"
ls -1 "$E3_OUT_DIR"/e3-*.json 2>/dev/null || echo "  (none written)"
if [ ${#FAILED[@]} -gt 0 ]; then
  echo
  echo "thresholds breached for: ${FAILED[*]}" >&2
  echo "  most often dropped_iterations > 0 — the offered rate was not sustained;" >&2
  echo "  those stages must not be plotted as latency points." >&2
  exit 1
fi
