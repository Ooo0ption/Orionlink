# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ground rule: do NOT modify code without explicit permission

Never edit, add, or delete source code (any `*.go`, `*.js`, `*.html`, configs,
build files, etc.) unless the user has **explicitly** asked you to change code in
that turn. Analysis, review, and documentation requests are **not** permission to
touch code. When you believe a code change is warranted, describe the change and
**ask first**; only proceed after the user says yes. Writing to docs
(`docs/*.md`, `PROGRESS.md`, this file) when asked to document/analyze is fine.

## What this is

Prototype implementation of the NDSS 2026 paper *OrionLink: Single Sign-On with
Oblivious Identity Brokers* (branch `dev-v4`). It is a privacy-preserving SSO
scheme built on BLS12-381 pairings, Pointcheval–Sanders randomizable signatures,
and an OPRF, where an **oblivious broker** routes login flows without learning the
user's cross-RP identity. The code is the empirical support for paper §6
(Implementation & Evaluation), so correctness against the paper and the
threat model matters more than production polish.

Companion documents (read these before making protocol changes):
- `PROGRESS.md` — change log of the earlier dev-v4 revision effort (P0/P1/P2 units). Historical background only; it is no longer maintained, so do not update it and do not treat it as current.
- `docs/wire-format.md` — the authoritative paper↔code mapping (paper symbols ↔ Go types ↔ HTTP endpoints) plus the "Known drift" list of intentional paper/code mismatches.
- `docs/broker-visibility.md` — generated table of exactly what the broker can observe at each step.
- Paper repo: `/home/yijia/projects/orionlink/`; revision plan: `/home/yijia/projects/orionlink/revision-plan.md` (the authority for "should party X see value Y" — its "Broker Functionality Preservation" table).

## Architecture

Single Go module (`secure-sso`), one binary, role selected at runtime by
`-name`. `main.go` dispatches to `idp.StartIdpServer()` /
`broker.StartBrokerServer()` / `rp.StartRpServer()`, or to benchmark entry points.

Three server roles, each a directory with the same internal shape
(`*.go`: `<role>.go` entry + `handler.go`, `aake.go`/`aaka.go`, `storage.go`,
`persist.go`, `register.go`, `token.go`, `refresh.go`, `bench_support.go`),
served with Fiber:
- **IdP** (`:3000`) — issues DC/SC credentials at registration, runs user auth & consent, issues tokens. `IdP/idp.go`.
- **Broker** (`:3001`) — the oblivious router. Randomizes RP identity (`acid`), relays PoK/token requests IdP↔RP, unblinds `auid`→`uid_rp` for per-RP routing, but cannot link users across RPs or read PII. `Broker/broker.go`.
- **RP** (`:3002`) — relying party; holds SecretCredential, builds AAKA proofs, redeems codes for tokens. `RP/rp.go`.
- **TCA** (`:3003`) — separate static origin (nginx container) hosting `tca/dvf.html`, `tca/dvf_authorize.html`, `tca/cryptolib.js`. Deliberately **not** IdP-origin (isolation hardening, P0-A); IdP pages embed it via iframe + CSP `frame-src`, and cross-window messaging uses pinned `targetOrigin` / `event.origin` checks.

Shared code:
- `lib/` — cryptography: `PSSig.go` (Pointcheval–Sanders sigs), `anonyCred.go` (anonymous credentials / blind sign), `NIZK.go` (Σ-protocol proofs, Fiat–Shamir), `utils.go`. `lib/oprf/server.go` is the OPRF server logic (moved out of IdP in P0-B).
- `internal/protocol/` — wire message struct types (`rpBroker.go`, `rpIdp.go`, `brokerIdP.go`, `refresh.go`). Changing these = changing the wire; follow the update protocol at the bottom of `docs/wire-format.md`.
- `internal/common/` — shared types, `serialize.go` (BLS12-381 ↔ base64), `code.go`, `refresh_ks.go`.

### Protocol / crypto invariants to preserve

- **PSSignMsg must not be a nested JSON struct field.** It has no `MarshalJSON`/`UnmarshalJSON` (only `ToJSON`/`FromJSON`), so Go's reflection marshaller silently drops its G1 points. On the wire, PS signatures travel as **flat `[]byte`** (e.g. `Sign1`/`Sign2`), produced by `.ToJSON()` and decoded with `(&PSSignMsg{}).FromJSON(bytes)`. See PROGRESS.md "dev-eval 协议扁平化".
- **K_S encryption of PII (P1-A).** IdP encrypts id_token `sub`/`name`/`email` and access_token `sub`/`scope` with AES-GCM under the X3DH-derived `K_S`; envelope claims (`iss`, `aud=acid`, `exp`, `iat`, `kid`) stay plaintext so the broker can route and re-sign. Broker never holds `K_S`. RP decrypts with the same `K_S` in `handleCallback`. Don't put PII in plaintext claims.
- **BLS12-381 serialization** is fixed: Scalar via `MarshalBinary`, G1/G2 via `BytesCompressed`, then base64. Client side uses `@noble/bls12-381`.
- Before deciding any party may/may not see a value, check the revision-plan's Broker Functionality Preservation table — not intuition.

### Removed / dead code

The OIDC compatibility layer (`/oauth2/*`, `oidc_*.html`, `*/oidc.go`) was
**deleted** in the dev-eval alignment. Restore from git history if interop is
needed. The active protocol is `/ssso/*` on every server.

## Commands

```bash
# Build / test (Go)
go mod tidy
go build ./...
go test ./...
go test -run TestGenerateTokensEncryptsClaims ./benchmark/unit/  # single test
```

`main.go` starts a server role only (`-name=idp|broker|rp`). Every measurement
harness is reached through `go test ./benchmark/...` — see `benchmark/README.md`.

Run the full stack locally (`./run.sh` does all of this; the long form below is
TCA in Docker plus servers via `go run`, IdP first):

```bash
docker run -d --rm --name orionlink-tca -p 3003:3003 \
  -v "$PWD/tca:/usr/share/nginx/html:ro" \
  -v "$PWD/tca/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  nginx:alpine
nohup go run main.go -name=idp    > /tmp/idp.log 2>&1 &
until curl -sf http://localhost:3000/ssso/pubkeys > /dev/null; do sleep 1; done
nohup go run main.go -name=broker > /tmp/broker.log 2>&1 &
sleep 2
nohup go run main.go -name=rp     > /tmp/rp.log 2>&1 &
```

Full stack from the prebuilt image: `docker compose up -d --wait` (idp:3000, broker:3001, rp:3002, tca:3003).

Benchmarks / paper data reproduction:

```bash
# E1 — paper §6 Table III local overhead. Prints the six rows next to the
# published values. Default 100 rounds (~30 s) is enough for every structural
# claim; pass 1000 for the paper's exact setting (~5 min).
./benchmark/run-e1.sh
./benchmark/run-e1.sh 1000

# equivalent bare command
ORION_ITERATIONS=1000 go test -run TestAllPartsLocal -timeout 60m -v ./benchmark/e1/
```

The HTTP registration-latency probe and the k6 stress suite are parked in
`tmp/` while they are repaired — `tmp/README.md` says what is broken in each.

Browser end-to-end (Playwright) — **all tests live under `benchmark/`**:

```bash
cd benchmark/e2/browser && npm run perf
```

All three Table 4 rows, including token refresh, are measured by that Playwright
suite: token refresh is an authenticated browser fetch through the live
RP → Broker → IdP path (`perf/token_refresh.spec.ts`). The older Go loopback
harness in `benchmark/e2/tokenrefresh/` still builds but is no longer part of
E2 (`run-e2.sh` rejects `--no-browser`).

E2 in one go: `./benchmark/run-e2.sh [iterations]`. Unit tests are deliberately
in neither runner: `go test ./benchmark/unit/`.

## Working conventions

- **After editing any TCA JS (`tca/*.js`), regenerate the SRI hashes** — the HTML pins them via `integrity=`. Commands in `tca/SRI.md`. Stale hashes silently break loading.
- Every browser-side change must be validated with Playwright; crypto invariants also get a Go unit test.
- Top-level directories are kept minimal: `Broker/ IdP/ RP/ internal/ lib/ tca/ docs/ benchmark/`. All tests (Go + Playwright) go under `benchmark/`.
- All measurement scaffolding for a role lives in one file, `*/bench_support.go`: load-test endpoints that bypass session/code checks, the `*ForTest` exports the `benchmark` package needs, and bench-only fixtures. It cannot move under `benchmark/` because Go ties a package to a directory and these need unexported identifiers. Keep the endpoints gated on `Config.TestEndpointsEnabled()` and out of production request paths.
- Keep exactly one long-running container (`orionlink-tca`); `docker stop --rm` others when done.
- Per-unit workflow: implement → verify (`go build`/`go test` + Playwright) → report.
- Python is `python3`; Go is 1.25 with Cloudflare CIRCL for BLS12-381.
