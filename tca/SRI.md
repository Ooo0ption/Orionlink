# Regenerating TCA SRI hashes

The browser fetches one script per TCA page: `dvf.bundle.js` and
`dvf_authorize.bundle.js`, each built by `./tca/build-app.sh` from the sources
(`dvf.js` / `dvf_authorize.js`, `cryptolib.js`, `vendor/crypto-deps.js`). Only
those two bundles carry `integrity=`; the sources are never fetched directly and
need no hashes.

After editing **any** TCA source, rebuild and then re-pin:

```bash
./tca/build-app.sh           # rebuild both bundles from the sources
./tca/update-sri.sh          # rewrite the integrity attributes in place
./tca/update-sri.sh --check  # verify without writing (use in CI)
```

If a third-party version changed in `tca/package.json`, run
`./tca/build-vendor.sh` before `build-app.sh` — the app bundle inlines
`vendor/crypto-deps.js` as an input and does not rebuild it.

To compute a hash by hand:

```bash
for f in tca/dvf.bundle.js tca/dvf_authorize.bundle.js; do
  printf "%s  sha384-%s\n" "$f" \
    "$(openssl dgst -sha384 -binary "$f" | openssl base64 -A)"
done
```

## Why one bundle per page rather than a module graph

Served as authored, the graph is three round trips deep — `dvf.html` → `dvf.js`
→ `cryptolib.js` → `vendor/crypto-deps.js` — because each layer is only
discoverable once the previous response has arrived. That load happens inside a
cross-origin iframe in the middle of the login, and it is exactly what paper
Table 4's "Consent check" row measures, so the depth showed up directly in the
numbers (~105 ms locally, and ~3x RTT on a real network). Bundled, the page
costs one request beyond the HTML.

It also simplifies the pinning. Previously each page needed a
`<link rel="modulepreload" integrity=...>` for every module it pulled in
transitively, because an ES module `import` carries no integrity of its own —
and a missing `<link>` failed silently: nothing broke, the guarantee was just
absent. With a single entry there is one hash per page and nothing to forget.

## `orion-config.js` is deliberately not pinned

`/orion-config.js` is rendered per deployment from `orion-config.js.tmpl` by
`tca/docker-entrypoint.d/40-orion-config.sh`, so its bytes legitimately differ
between an author's laptop and a reviewer's machine — a fixed hash could not
match both. It is the only unpinned TCA script.

That is safe because of what it contains: public service origins and the
profile name, nothing else. No key, no PIN, no user identifier passes through
it. The bundles, which hold every line that touches a secret, stay hash-pinned,
so a tampered crypto implementation is still rejected by the browser.

It is loaded with `defer` alongside the module bundle, so the two download
concurrently while still executing in document order — the bundle reads
`window.ORION` at evaluation time and must see it already set. Dropping the
`defer` makes this classic script block the parser, which pushes the bundle's
request into a second round trip and shows up in the Consent check row.

Before the third-party cryptography was vendored, the pinning claim had a hole:
`cryptolib.js` was itself hash-pinned, but the four `https://esm.sh` modules it
imported at runtime were not, and one specifier was `@latest`. The bytes that
actually performed the OPRF and the pairing check could therefore change without
any hash changing. See `tca/vendor/deps.entry.js`.

## Failure mode

If a hash doesn't match the runtime file, Chrome refuses to load the script:

```
Failed to find a valid digest in the 'integrity' attribute for resource
'http://localhost:3003/dvf.bundle.js' with computed SHA-384 integrity '...'.
```

Nothing else fails first, so it looks like the TCA simply never initialises: the
PIN button stays disabled. Every harness under `benchmark/e2/browser/perf/` drives a
real login through the TCA iframe, so a stale hash fails all three.
