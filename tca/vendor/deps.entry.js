// Bundle entry for the TCA's third-party cryptography.
//
// cryptolib.js used to import these four modules straight from
// https://esm.sh at page load. That had three costs:
//
//   1. Latency — four independent module graphs fetched from a public CDN on
//      every cold load, on the critical path of the PIN step. Measured at
//      roughly half a second, dwarfing the protocol operations the paper
//      reports (benchmark/results/).
//   2. Reproducibility — an evaluator on an offline or restricted machine
//      cannot complete a login at all, which is a direct risk to the NDSS
//      "Artifacts Functional" badge.
//   3. Integrity — the TCA is the isolated origin the paper's threat model
//      leans on hardest, yet its actual cryptographic implementation arrived
//      from a third party with no subresource integrity, and one of the
//      specifiers was `@latest`, so the code being executed could change
//      between the measured run and the reviewed one.
//
// Everything is now pinned in package.json and bundled into vendor/crypto-deps.js
// by build-vendor.sh, which the container build runs. The generated bundle is
// committed so that a clean, network-less checkout still works.
//
// Versions match what esm.sh resolved to when the switch was made, so no
// cryptographic behaviour changed: @noble/bls12-381@1.4.0,
// @noble/hashes@2.3.0, ristretto255@0.1.3 (the npm release of
// facebook/ristretto255-js).

export * as bls from '@noble/bls12-381';
export { default as Ristretto255 } from 'ristretto255';
export { sha512 } from '@noble/hashes/sha2.js';
export { hkdf } from '@noble/hashes/hkdf.js';
