# `benchmark/` — the three paper experiments

| | measures | paper | stack needed? |
|---|---|---|---|
| **E1** | local computation overhead | Table III | no |
| **E2** | latency breakdown | Table 4 | yes, for the browser half |
| **E3** | AAKA interface under load | Fig. 8 | yes, **bench profile** |

Unit tests are not an experiment: `go test ./benchmark/unit/`.

Windows evaluators should use PowerShell with Docker Desktop in Linux-container
mode. E1 and E2 have native `.ps1` runners; E3's `.sh` runner executes inside
the submitted Linux image. If required, enable repository scripts for the
current process with `Set-ExecutionPolicy -Scope Process Bypass`.

Start the stack when an experiment needs it:

```bash
ORION_PROFILE=bench ./run.sh     # bench works for E2 as well; demo does not work for E3
./run.sh down                    # required before unit tests (they bind :3000)
```

On Windows, start and stop the prebuilt AE stack with the PowerShell Compose
commands in Sections 1.2 and 1.4 of the root `README.md`; `run.sh` is only the
Unix source-development launcher.

---

## E1 — local computation overhead (Table III)

Times the six Table III operations in-process: no server, no network. Pure CPU
cost of the cryptography.

```bash
./benchmark/run-e1.sh                        # 100 iterations, ~30 s
./benchmark/run-e1.sh 1000                   # the paper's setting, ~5 min
ORION_ITERATIONS=1000 ./benchmark/run-e1.sh  # same, via env
ORION_PROFILE=bench ./benchmark/run-e1.sh    # writes results/e1-wholeflow-bench.json
```

PowerShell:

```powershell
.\benchmark\run-e1.ps1          # 100 iterations, ~30 s
.\benchmark\run-e1.ps1 1000     # the paper's setting, ~5 min
```

Output — a progress line per section while it runs, then the six rows plus
their sum:

```
log: /tmp/orionlink-e1.log
iterations: 100

===== Key generation =====
Average time: 196.13ms (100 iterations)
...

Stage           Operation                  measured
--------------- ----------------------- -----------
Initialization  Key generation            196.13 ms
Registration    RP registers to IdP        13.37 ms
SSO             Pseudonym generation        6.46 ms
SSO             AnonyAKE execution         32.01 ms
Extension       Authorization revoke        0.24 ms
Extension       Token refresh               2.33 ms
--------------- ----------------------- -----------
Total           (sum of rows)             250.55 ms
```

Also written: `results/e1-wholeflow-<profile>.json` — the same six rows
(`stage`, `operation`, `iterations`, `mean_ms`) plus `total_ms`, with `profile`
taken from `ORION_PROFILE` (default `demo`). The full `go test` log goes to
`/tmp/orionlink-e1.log` (`ORION_E1_LOG`).

**Possible errors**

| what you see | why |
|---|---|
| `note: the dev stack is running and will compete for CPU` | the stack is up and stealing cores from the thing being timed. Not fatal, but the numbers will be high — `./run.sh down` first. |
| `Part 6 (refresh): rp decrypt failed: message authentication failed` | `session_ks` differs between `RP/config/key_storage.json` and `IdP/config/key_storage.json`. One complete browser login re-syncs them. |

---

## E2 — latency breakdown (Table 4)

What a user actually waits for, measured by Playwright against the live stack.
Token refresh uses an authenticated browser request through the real
RP → Broker → IdP → Broker → RP path, so container netem delay is included.

```bash
ORION_PROFILE=bench ./benchmark/run-e2.sh        # 10 iterations
ORION_PROFILE=bench ./benchmark/run-e2.sh 100    # the paper's setting
./benchmark/e2/summarize.py                      # re-print the table without re-measuring
                                                 #   --markdown | --components | --profile | --results-dir
```

PowerShell:

```powershell
$env:ORION_PROFILE="bench"
.\benchmark\run-e2.ps1             # 10 iterations
.\benchmark\run-e2.ps1 100         # the paper's setting
python .\benchmark\e2\summarize.py # re-print without re-measuring
```

Set `ORION_PROFILE` explicitly — it is the suffix of the output filenames, and
it is read from *your shell*, not from the running servers.

Output — the consolidated Table 4:

```
OrionLink — paper Table 4 (tab:latency-breakdown), profile=demo
reports: login 08-10 15:14  authz 08-10 10:09  refresh 08-10 10:09

Stage      Operation                          mean (ms)   n
---------  ---------------------------------  ---------  --
SSO Flow   Click "Login"                         630.00   1
           Consent check                         242.70   1
           Authorization code exchange           246.63   1
           Login successful (Total)             2019.00   1
Extension  Authorization management (server)       2.02  10
           Authorization management (client)      81.61  10
           Token refresh                            2.95  10
```

The rows do not sum — the four SSO Flow figures are on a mixed basis, and the
two Authorization management figures are nested. Token refresh is one complete
browser request/response, with login excluded as setup. Details are in
`e2/summarize.py` and the individual JSON reports.

**Possible errors**

| what you see | why |
|---|---|
| `the live stack is not available` | start the four containers; all E2 rows now use live protocol paths. |
| rows marked `not run` | that browser report has not been produced for the selected profile. |
| `Executable doesn't exist at .../chromium` | first run on this box: `cd benchmark/e2/browser && npm ci && npx playwright install chromium`. |
| timestamps in the `reports:` line hours apart | the reports were measured at different times — rerun E2 before reading the table as one experiment. |

---

## E3 — AAKA interface stress test (Fig. 8)

Three k6 scripts, one per line of Fig. 8, loading the AAKA work each role does
during a login: IdP verification + token issuance, RP proof construction,
broker credential randomization. Request bodies are generated against the
running stack at startup, so nothing has to be captured by hand.

**Requires bench profile** — the endpoints it drives do not exist in demo. k6
itself is not required for a source-tree run; the runner falls back to the
`grafana/k6` container. The prebuilt AE image already contains pinned k6 and the
E3 scripts. Section 1.4.3 of the root `README.md` shows both Bash and PowerShell
commands for its optional `e3` Compose service without downloading another
image.

```bash
ORION_PROFILE=bench ./run.sh
./benchmark/run-e3.sh                 # 10/200 RPS, 60 s per stage, ~8 min
./benchmark/run-e3.sh --quick         # 10/200 RPS, 15 s per stage, ~2 min (smoke)
./benchmark/run-e3.sh --duration 30   # same rates, shorter stages
./benchmark/run-e3.sh --rps 10,200,500,1000   # custom rates (comma-separated)
./benchmark/run-e3.sh --line idp,rp   # selected lines only: idp | rp | broker
```

Output — one table per line, plus `benchmark/results/e3-<line>-bench.json`:

```
E3 — broker: GET http://localhost:3001/ssso/randomizeRPIDForTest  (profile=bench)
  target   achieved    p50      p95      p99   server p95   errors   dropped
      10      10.0   1.37    3.11    5.74        2.99    0.00%         0
     200     200.0   1.34    3.59    7.04        3.32    0.00%         0
```

**A stage counts only if `dropped` is 0 and `achieved` matches `target`.**
Otherwise the system did not sustain that rate and its latency is meaningless.
Plot `p95`.

**Possible errors**

| what you see | why |
|---|---|
| `broker unreachable at http://localhost:3001` | the stack is not running. |
| `/ssso/randomizeRPIDForTest is not mounted — not in bench profile` | the stack is up but in demo profile. Restart with `ORION_PROFILE=bench ./run.sh`. |
| `WARNING: iterations were dropped` (exit code 1) | that rate exceeded what this machine sustains. Expected here for IdP and RP at 200 RPS — a 4-vCPU box saturates around 150. Lower the rate or use a bigger machine. |
| `Insufficient VUs, reached N active VUs` | the *load generator* ran out of virtual users, so the drops are k6's fault, not the server's. Raise `ORION_E3_MAX_WAIT_S` or `ORION_E3_VU_CAP`. |
| `--line takes idp, rp or broker` | `--line` selects which of the three lines to run; rates go in `--rps`. |

Every environment variable E3 understands is documented at the top of
`e3/lib/common.js`.

---

## Unit tests

Primitives and invariants the experiments rely on — PS signatures, NIZK, OPRF,
X3DH, wire round-trips, token encryption, config gating.

```bash
./run.sh down                  # they bind :3000-:3003
go test ./benchmark/unit/
```

```
ok  	secure-sso/benchmark/unit	1.686s
```

**Possible errors**

| what you see | why |
|---|---|
| `listen tcp4 :3000: bind: address already in use` → `FAIL` | the stack is running. Stop it, or give the suite other ports: `ORION_IDP_URL=http://localhost:13000 ORION_BROKER_URL=http://localhost:13001 ORION_RP_URL=http://localhost:13002 ORION_TCA_URL=http://localhost:13003 ORION_DATA_DIR=/tmp/orion-test go test ./benchmark/unit/` |

---

## `results/`

Regenerated on every run, not precious.

Every file is `e<N>-<harness>-<profile>.json`: the experiment it belongs to,
then the script that produced it.

| file | from |
|---|---|
| `e1-wholeflow-<profile>.json` | E1 `e1/wholeflow.go` — the six Table III rows |
| `e2-login_latency-<profile>.json` | E2 `e2/browser/perf/login_latency.spec.ts` |
| `e2-authorization_mgmt-<profile>.json` | E2 `e2/browser/perf/authorization_mgmt.spec.ts` |
| `e2-token_refresh-<profile>.json` | E2 `e2/browser/perf/token_refresh.spec.ts` |
| `micro-refresh_loopback-<profile>.json` | optional local refresh microbenchmark; not E2/container RTT |
| `e3-idp_token-<profile>.json` | E3 `e3/idp_token.js` |
| `e3-rp_pok-<profile>.json` | E3 `e3/rp_pok.js` |
| `e3-broker_randomize-<profile>.json` | E3 `e3/broker_randomize.js` |

`tca_crypto_iphone_ios18.json` and `tca_crypto_server_baseline.json` are **not**
harness output — they come from a microbenchmark on a physical iPhone and its
server-side baseline, and cannot be regenerated here.
