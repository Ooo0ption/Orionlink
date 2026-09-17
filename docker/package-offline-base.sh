#!/usr/bin/env bash
# Build the project-specific Linux dependency image while online and export it
# as a portable docker-load tar archive.
set -euo pipefail

cd "$(dirname "$0")/.."

BASE_IMAGE="${ORION_BASE_IMAGE:-orionlink-ae-linux-base:go1.25.1-k6-1.8.0}"
OUTPUT="${1:-dist/orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar}"
PLATFORM="${ORION_PLATFORM:-}"

if [[ -n "$PLATFORM" ]]; then
  docker buildx build --platform "$PLATFORM" --load \
    -f Dockerfile.base -t "$BASE_IMAGE" .
else
  docker build -f Dockerfile.base -t "$BASE_IMAGE" .
fi

mkdir -p "$(dirname "$OUTPUT")"
docker image save -o "$OUTPUT" "$BASE_IMAGE"
chmod 0644 "$OUTPUT"

echo "base image: $BASE_IMAGE"
docker image inspect "$BASE_IMAGE" \
  --format 'id={{.Id}} arch={{.Architecture}} size={{.Size}} bytes'
echo "archive: $OUTPUT"
shasum -a 256 "$OUTPUT" | tee "${OUTPUT}.sha256"
echo
echo "Offline machine: docker load -i $OUTPUT"
