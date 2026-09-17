#!/usr/bin/env bash
#
# E2 — latency breakdown (paper §6 Table 4).
#
#   ./benchmark/run-e2.sh [iterations]   # default 10
#   ./benchmark/run-e2.sh 100            # the paper's setting
#   ORION_RP_URL=http://localhost:13002 ./benchmark/run-e2.sh 100
#
# All rows are measured by Playwright against the running stack. Token refresh
# is an authenticated fetch through the real RP -> Broker -> IdP path, so the
# container tc/netem settings are part of its measured latency.
#
# The suite prints only that it finished and where it wrote; the figures come
# from the consolidated table at the end (e2/summarize.py). Run that on its own
# for --markdown / --components.
#
# Unit tests are deliberately NOT here — they are not a paper experiment:
#   go test ./benchmark/unit/
set -euo pipefail
cd "$(dirname "$0")/.."

ITER=""
for arg in "$@"; do
  case "$arg" in
    --no-browser) echo "--no-browser is no longer available: all E2 rows use the live browser/container path" >&2; exit 2 ;;
    -h|--help)    sed -n '2,18p' "$0" | sed 's/^# \?//'; exit 0 ;;
    ''|*[!0-9]*)  echo "unknown option: $arg" >&2; exit 2 ;;
    *)            ITER="$arg" ;;
  esac
done
ITER="${ITER:-${ORION_PERF_ITERATIONS:-10}}"
if [ "$ITER" -lt 1 ]; then
  echo "usage: $0 [iterations]   (positive integer, default 10)" >&2
  exit 2
fi

section() { printf '\n\033[1m===== %s =====\033[0m\n' "$1"; }

# Keeps a harness's output to a couple of progress lines: which report it wrote
# and whether it passed. Failure lines are kept too, so a broken run is not
# silently reduced to nothing.
trim() {
  sed 's/\x1b\[[0-9;]*[A-Za-z]//g' \
    | grep -E 'wrote |[0-9]+ (passed|failed)|^(ok|FAIL) |--- FAIL|Error' \
    | sed -e 's|^ *||' -e 's|^wrote .*/|wrote |' -e 's|^|  |'
}

# Runs a pipeline whose first command's exit status is what matters, and fails
# the script on it. `set -e` does not do this for pipelines, and grep exiting 1
# on no-match would otherwise take the run down.
run_half() {
  local label="$1"; shift
  set +e
  "$@" 2>&1 | trim
  local rc=${PIPESTATUS[0]}
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "${label} failed (exit ${rc})" >&2
    exit "$rc"
  fi
}

browser_suite() {
  cd benchmark/e2/browser
  ORION_PERF_ITERATIONS="$ITER" npm run perf
}

IDP_URL="${ORION_IDP_URL:-http://localhost:3000}"
if ! curl -sf -o /dev/null --max-time 2 "${IDP_URL%/}/ssso/pubkeys"; then
  echo "the live stack is not available at ${IDP_URL}; all E2 rows require it" >&2
  exit 1
fi

section "E2 — live browser/container paths (${ITER} iterations)"
run_half "E2" browser_suite

section "Table 4"
SUMMARY_RC=0
./benchmark/e2/summarize.py || SUMMARY_RC=$?
echo
echo "reports: benchmark/results/"
exit "$SUMMARY_RC"
