#!/usr/bin/env bash
# Build the code-containing AE image with networking disabled. The dependency
# base must have been built locally or imported with docker load first.
set -euo pipefail

cd "$(dirname "$0")/.."

BASE_IMAGE="${ORION_BASE_IMAGE:-orionlink-ae-linux-base:go1.25.1-k6-1.8.0}"
OUTPUT_IMAGE="${ORION_IMAGE:-orionlink-ae:ndss2027-v2}"
PLATFORM="${ORION_PLATFORM:-}"

if ! docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
  echo "missing local base image: $BASE_IMAGE" >&2
  echo "load it first: docker load -i dist/orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar" >&2
  exit 1
fi

BUILD=(docker build --pull=false --network=none)
if [[ -n "$PLATFORM" ]]; then
  BUILD+=(--platform "$PLATFORM")
fi
BUILD+=(
  --build-arg "ORION_BASE_IMAGE=$BASE_IMAGE"
  -f Dockerfile.offline
  -t "$OUTPUT_IMAGE"
  .
)
"${BUILD[@]}"

echo "offline code image: $OUTPUT_IMAGE"
docker image inspect "$OUTPUT_IMAGE" \
  --format 'id={{.Id}} arch={{.Architecture}} size={{.Size}} bytes'
