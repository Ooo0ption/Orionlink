#!/bin/sh
# Renders tca/orion-config.js.tmpl into a served /orion-config.js using the
# ORION_* environment variables, so the TCA's static assets carry no compiled-in
# service addresses (NDSS AE "Artifacts Functional": no hardcoded addresses).
#
# The nginx base image runs every executable /docker-entrypoint.d/*.sh before
# starting nginx. The html root is bind-mounted read-only, so the output goes to
# a separate writable directory that nginx.conf exposes at /orion-config.js.
set -eu

: "${ORION_PROFILE:=demo}"
: "${ORION_IDP_URL:=http://localhost:3000}"
: "${ORION_BROKER_URL:=http://localhost:3001}"
: "${ORION_RP_URL:=http://localhost:3002}"
: "${ORION_TCA_URL:=http://localhost:3003}"
export ORION_PROFILE ORION_IDP_URL ORION_BROKER_URL ORION_RP_URL ORION_TCA_URL

TEMPLATE=/usr/share/nginx/html/orion-config.js.tmpl
OUTDIR=/usr/share/nginx/orion
OUTFILE="$OUTDIR/orion-config.js"

if [ ! -f "$TEMPLATE" ]; then
    echo "[orion] $TEMPLATE not found — is tca/ mounted at /usr/share/nginx/html?" >&2
    exit 1
fi

mkdir -p "$OUTDIR"
# Restrict substitution to the ORION_* names so nothing else in the template
# (or a stray shell-looking string) gets rewritten.
envsubst '${ORION_PROFILE} ${ORION_IDP_URL} ${ORION_BROKER_URL} ${ORION_RP_URL} ${ORION_TCA_URL}' \
    < "$TEMPLATE" > "$OUTFILE"

echo "[orion] rendered $OUTFILE (profile=$ORION_PROFILE idp=$ORION_IDP_URL broker=$ORION_BROKER_URL)"

# --- Content-Security-Policy -------------------------------------------------
#
# Emitted from here rather than written literally into nginx.conf because
# frame-ancestors must name the IdP origin, which is deployment-dependent.
#
# The TCA issues no requests of its own: its cryptography is vendored and
# SRI-pinned, and it communicates with the embedding IdP page exclusively via
# postMessage. So everything except same-origin scripts is denied outright.
# style-src allows inline because dvf.html carries its stylesheet in a <style>
# block; no secret ever reaches CSS, and scripts stay hash-pinned regardless.
#
# frame-ancestors is the TCA side of the isolation the paper relies on: only
# the IdP may embed this origin. The 127.0.0.1/localhost twin is included
# because a browser reaching the stack by the other name would otherwise be
# refused, exactly as internal/config.BrowserOrigins does for CORS.
idp_twin=$(printf '%s' "$ORION_IDP_URL" | sed -e 's#//localhost#//127.0.0.1#' -e 't' -e 's#//127\.0\.0\.1#//localhost#')
if [ "$idp_twin" = "$ORION_IDP_URL" ]; then
    frame_ancestors="$ORION_IDP_URL"
else
    frame_ancestors="$ORION_IDP_URL $idp_twin"
fi

CSPDIR=/etc/nginx/orion
mkdir -p "$CSPDIR"
cat > "$CSPDIR/csp.conf" <<EOF
add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors $frame_ancestors" always;
EOF

echo "[orion] rendered $CSPDIR/csp.conf (frame-ancestors: $frame_ancestors)"
