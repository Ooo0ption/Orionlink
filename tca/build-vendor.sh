#!/usr/bin/env sh
#
# Bundles the TCA's pinned third-party cryptography into vendor/crypto-deps.js.
#
#   ./build-vendor.sh
#
# Run it after changing a dependency version in package.json. The output is
# committed to the repository on purpose: an evaluator with no network must
# still be able to serve the TCA and complete a login, and `npm install` at
# deploy time would reintroduce exactly the external dependency this replaces.
#
# The bundle is pinned by SRI in dvf.html, so regenerating it means
# regenerating the hashes too — update-sri.sh does both if you run it after
# this script. See SRI.md.
set -eu
cd "$(dirname "$0")"

OUT=vendor/crypto-deps.js

if [ ! -d node_modules ]; then
  echo "==> installing pinned dependencies"
  npm ci --no-audit --no-fund
fi

echo "==> bundling $OUT"
npx --no-install esbuild vendor/deps.entry.js \
  --bundle \
  --format=esm \
  --target=es2022 \
  --platform=browser \
  --legal-comments=inline \
  --outfile="$OUT"

echo "==> $OUT  $(wc -c < "$OUT") bytes"
echo "    remember to refresh the SRI hashes: ./update-sri.sh"
