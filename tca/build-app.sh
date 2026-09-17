#!/usr/bin/env sh
#
# Bundles each TCA page's module graph into a single file.
#
#   ./build-app.sh
#
# Why this exists, rather than serving the modules as authored: the TCA is
# loaded inside a cross-origin iframe in the middle of the login flow, and paper
# Table 4's "Consent check" row is exactly the time that load takes. Served as
# separate modules, the graph is three round trips deep —
#
#   dvf.html -> dvf.js -> cryptolib.js -> vendor/crypto-deps.js
#
# each layer discoverable only once the previous response has arrived, so the
# row grows by ~3x RTT on a real network. Bundled, the page costs one request
# and the row scales with a single round trip, which is what the published
# measurements show.
#
# The sources stay as they are — this only changes what the browser fetches.
# Both outputs are committed, for the same reason vendor/crypto-deps.js is: an
# evaluator with no network must still be able to serve the TCA.
#
# The bundles are pinned by SRI in the HTML, so regenerating them means
# regenerating the hashes: run ./update-sri.sh afterwards. See SRI.md.
set -eu
cd "$(dirname "$0")"

if [ ! -d node_modules ]; then
  echo "==> installing pinned dependencies"
  npm ci --no-audit --no-fund
fi

# vendor/crypto-deps.js is an input here, not a dependency to rebuild: esbuild
# inlines it along with cryptolib.js. Run build-vendor.sh first if a third-party
# version changed.
for entry in dvf dvf_authorize; do
  out="$entry.bundle.js"
  echo "==> bundling $out"
  npx --no-install esbuild "$entry.js" \
    --bundle \
    --format=esm \
    --target=es2022 \
    --platform=browser \
    --legal-comments=inline \
    --outfile="$out"
  echo "    $out  $(wc -c < "$out") bytes"
done

echo "    remember to refresh the SRI hashes: ./update-sri.sh"
