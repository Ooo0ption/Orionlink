#!/usr/bin/env bash
#
# E1 — local computation overhead.
#
#   ./benchmark/run-e1.sh [iterations]   # default 100
#
# Wraps `go test -run TestAllPartsLocal ./benchmark/e1/` (benchmark/e1/wholeflow.go).
# Runs in-process: no server, no port, no network.
set -euo pipefail
cd "$(dirname "$0")/.."

ITER="${1:-${ORION_ITERATIONS:-100}}"
if ! [[ "$ITER" =~ ^[0-9]+$ ]] || [ "$ITER" -lt 1 ]; then
  echo "usage: $0 [iterations]   (positive integer, default 100)" >&2
  exit 2
fi

LOG="${ORION_E1_LOG:-/tmp/orionlink-e1.log}"

# The stack is not required, but a running one competes for CPU.
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE ':(3000|3001|3002)\b'; then
  echo "note: the dev stack is running and will compete for CPU (./run.sh down)."
fi

echo "log: ${LOG}"
echo "iterations: ${ITER}"
echo

# Full output goes to the log; live, only each section's name, its in-flight
# progress and its average are echoed, so the run shows progress without burying
# the table. The Complete Flow section is a state-leak check rather than a
# measurement, so it stays silent.
set +e
ORION_ITERATIONS="$ITER" go test -run TestAllPartsLocal -timeout 60m -v ./benchmark/e1/ 2>&1 \
  | tee "$LOG" \
  | awk '
      /^==========/ {
        label = $0
        sub(/^=* /, "", label); sub(/ =*$/, "", label)
        sub(/^Part [0-9]+: /, "", label); sub(/ *\[.*$/, "", label)
        skip = (label ~ /^Complete Flow/)
        if (!skip) { print "===== " label " ====="; fflush() }
        next
      }
      /^Average time:|\/[0-9]+ \([0-9]+%\)/ {
        if (!skip) { sub(/^ +/, "", $0); print $0; fflush() }
      }'
rc=${PIPESTATUS[0]}
set -e
if [ "$rc" -ne 0 ]; then
  echo "test failed, see ${LOG}:" >&2
  tail -n 20 "$LOG" >&2
  exit 1
fi
echo

# The harness prints, per section, a "========== Part N: <label> ==========" line
# followed by "Average time: <go duration> (N iterations)". Pair them up and
# convert the duration to milliseconds.
awk '
function toms(d) {
       if (d ~ /ms$/) { sub(/ms$/, "", d); return d + 0 }
  else if (d ~ /µs$/) { sub(/µs$/, "", d); return (d + 0) / 1000 }
  else if (d ~ /us$/) { sub(/us$/, "", d); return (d + 0) / 1000 }
  else if (d ~ /ns$/) { sub(/ns$/, "", d); return (d + 0) / 1000000 }
  else if (d ~ /s$/)  { sub(/s$/,  "", d); return (d + 0) * 1000 }
  return d + 0
}
BEGIN {
  fmt = "%-15s %-23s %11s\n"
  numfmt = "%-15s %-23s %8.2f ms\n"
  printf fmt, "Stage", "Operation", "measured"
  printf fmt, "---------------", "-----------------------", "-----------"
}
/==========/ {
  # "========== Part 3: Pseudonym generation [Table III: SSO] =========="
  #   -> operation "Pseudonym generation", stage "SSO"
  label = $0
  sub(/^.*========== /, "", label)
  sub(/ ==========.*$/, "", label)
  sub(/^Part [0-9]+: /, "", label)
  stage = ""
  if (label ~ /\[Table III: /) {
    stage = label
    sub(/^.*\[Table III: /, "", stage)
    sub(/\].*$/, "", stage)
  }
  operation = label
  sub(/ *\[.*$/, "", operation)
  next
}
/Average time:/ {
  for (i = 1; i <= NF; i++) if ($i == "time:") { dur = $(i + 1); break }
  ms = toms(dur)
  # Complete Flow rebuilds every server per iteration as a state-leak check;
  # it is not a measurement row, so it is dropped rather than printed.
  if (operation ~ /^Complete Flow/) { next }
  total += ms
  printf numfmt, stage, operation, ms
}
END {
  printf fmt, "---------------", "-----------------------", "-----------"
  printf numfmt, "Total", "(sum of rows)", total
}
' "$LOG"
