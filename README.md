OrionLink
------
OrionLink is a privacy-enhancing SSO pipeline for existing brokered SSO architectures that combines unlinkable per-RP pseudonyms with anonymous key exchange to prevent cross-service tracking and protect user data from broker visibility. 

# 1. Overview

OrionLink is single sign-on through an **oblivious identity broker**: the
broker routes every login but never learns who the user is, which apps they
use, or their personal data. This repository is the prototype measured in the
paper's evaluation. It implements the four roles, the full protocol with its
two extensions (authorization management, forward-secure token refresh), and
the harnesses for experiments E1–E3.

## 1.1 Architecture

| Role | Port | Purpose |
|------|------|---------|
| **RP** | 3002 | The app the user signs in to. The page a reviewer opens. |
| **Broker** | 3001 | Oblivious router between RP and IdP; sees only pseudonyms and ciphertext. |
| **IdP** | 3000 | Authenticates the user, issues credentials and tokens, hosts the authorization-management page. |
| **TCA** | 3003 | Browser-side cryptography on its own origin, embedded by the IdP as an iframe. |

The three servers are one Go binary (`main.go -name=idp|broker|rp`); the TCA
is static HTML/JS behind nginx. One Docker image contains all four, and
`docker-compose.yml` runs one container per role. Profile `demo` is the
clickable deployment; profile `bench` adds pre-registration, synthetic users
and load-test endpoints for the measurements.

## 1.2 Repository layout

| Directory | Contents |
|-----------|----------|
| `IdP/`, `Broker/`, `RP/`, `tca/` | One directory per role |
| `lib/`, `internal/` | Shared cryptography and wire/config code |
| `benchmark/` | E1 (Table III), E2 (Table IV), E3 (Fig. 8), unit tests, results, runners |
| `docker/`, `Dockerfile*`, `docker-compose.yml` | Image build and deployment |

Full tree in §6.

## 1.3 Recommended path

1. **Deploy** (§2): pull the image and start the containers. To build the
   image yourself instead, see §5, then continue at §2.3.
2. **Evaluate** (§3): §3.1 is the end-to-end command sequence; §3.2–§3.6 detail
   each step. Everything runs from the host shell.
3. **Click through the demo** (§4): optional; shows what E2 measures.
4. **Source** (§6): tree, dependencies, running without Docker.

# 2. Deploy with Docker

On Windows, use Docker Desktop in Linux-container mode and PowerShell. If local
policy blocks repository scripts, enable them for the current PowerShell
process only:
``` powershell
Set-ExecutionPolicy -Scope Process Bypass
```

## 2.1 Prerequisites

| Tool | Version | Needed for |
|------|---------|-----------|
| Docker with the Compose v2 plugin | ≥ 24 | everything in §2, §4 and E3 |
| Go, Node.js, Python 3 | see §3.2 | the host-side halves of E1 and E2 only |

Nothing else is installed on the host for the prototype itself; the image
resolves no package from the network at run time.

## 2.2 Pull the image
Tell Compose which image to use, once per shell, then pull it. All later
commands in this README rely on this variable being set.
``` bash
export ORION_IMAGE=walnutd/orionlink-ae:ndss2027-v2
docker image pull "$ORION_IMAGE"
```
PowerShell equivalent:
``` powershell
$env:ORION_IMAGE="walnutd/orionlink-ae:ndss2027-v2"
docker image pull $env:ORION_IMAGE
```
Expected output (last line):
```
Status: Downloaded newer image for walnutd/orionlink-ae:ndss2027-v2
```
If the image is already present, the last line reads
`Status: Image is up to date for walnutd/orionlink-ae:ndss2027-v2` instead.

Instead of exporting the variable you can copy `.env.example` to `.env` and set
`ORION_IMAGE` there; Compose reads `.env` automatically.

## 2.3 Start the containers
``` bash
docker compose -f docker-compose.yml up -d --wait
```
PowerShell equivalent:
``` powershell
docker compose -f docker-compose.yml up -d --wait
```
Expected output (the order of the lines varies):
```
 Container orionlink-ae-tca-1 Healthy
 Container orionlink-ae-idp-1 Healthy
 Container orionlink-ae-broker-1 Healthy
 Container orionlink-ae-rp-1 Healthy
```
Check the status:
``` bash
docker compose -f docker-compose.yml ps
```
Expected output: four rows, `tca`, `idp`, `broker` and `rp`, each with
`Up ... (healthy)` in the STATUS column. The optional `e3` load generator is
not started unless the Compose `benchmark` profile is selected explicitly (§3.5).

The four services bind to the following host ports. Make sure they are free
before starting the containers.

| Service | Address | Role in the demo | Open it yourself? |
|---------|---------|------------------|-------------------|
| **RP** | **http://localhost:3002/ssso/** | **The app. Start here** — this is the page §4 walks through. | **Yes** |
| IdP | http://localhost:3000 | Login and consent pages. The RP redirects you here during sign-in. | No |
| Broker | http://localhost:3001 | Oblivious relay between RP and IdP. No user interface. | No |
| TCA | http://localhost:3003 | Browser-side cryptography page, embedded as an iframe by the IdP. | No |

**Open only the RP link.** The other three addresses are reached
automatically while you sign in; opening their root URL directly shows a bare
`404` (IdP, Broker) or an isolated cryptography page (TCA), which is expected.

Two deployment profiles exist, selected with `ORION_PROFILE`:
- `demo` (default): the deployment a reviewer clicks through in §4. The RP is
  **not** registered at startup, because registration is one of the protocol
  steps worth watching.
- `bench`: the deployment the measurements come from (E2, E3). Same binary and
  same pages; the RP registers itself at startup, thousands of synthetic
  accounts are seeded, and the load-test endpoints are mounted.

## 2.4 Stop and reset
``` bash
docker compose -f docker-compose.yml down        # stop; keys and registrations survive in the orion-data volume
docker compose -f docker-compose.yml down -v     # stop and wipe them; the RP must register again
```

# 3. Evaluation

The paper's three experiments, and what each reproduces:

| Experiment | Paper | Reproduces | Runs where | Containers | Host tools |
|-----------|-------|-----------|------------|-----------|-----------|
| E1 | Table III | local computation cost of the six protocol operations | host Go process | **stopped** | Go |
| E2 | Table IV | user-visible latency of login, authorization management and token refresh | host Playwright + Go, driving the containers | running, `bench` profile | Go, Node.js, Python 3 |
| E3 | Fig. 8 | AAKA-interface throughput/latency under k6 load | k6 **inside** the `e3` container, started from the host | running, `bench` profile, no netem delay | Docker only |

**Every command in this section is typed in the host shell at the repository
root. You never need `docker exec` or a shell inside a container.** The E3
load generator is a container, but Compose starts and removes it for you.

For the standard OIDC baseline that Table IV compares against, see
[benchmark/oidc-baseline/README.md](benchmark/oidc-baseline/README.md); it is
a separate stack with its own image and ports.

## 3.1 End-to-end reproduction

The complete path from a fresh checkout to all three result sets. Each step
names the section that explains it; run the steps in this order.

| # | Step | Command | Containers | Done when | Details |
|---|------|---------|------------|-----------|---------|
| 0 | Install host tools (Docker, Go, Node.js, Python 3) | see §3.2 | — | `go version`, `node -v`, `python3 --version` print the required versions | §3.2 |
| 1 | Pull the image | `export ORION_IMAGE=walnutd/orionlink-ae:ndss2027-v2 && docker image pull "$ORION_IMAGE"` | — | `Status: Downloaded newer image ...` | §2.2 |
| 2 | Fetch Go modules and the Playwright browser | `go mod download && (cd benchmark/e2/browser && npm ci && npx playwright install chromium)` | — | both commands return without error | §3.2 |
| 3 | Unit tests + E1 | `docker compose -f docker-compose.yml down && go test ./benchmark/unit/ && ./benchmark/run-e1.sh` | stopped | the six-row table with a `Total` line | §3.3 |
| 4 | Start the stack in `bench` mode | `ORION_PROFILE=bench docker compose -f docker-compose.yml up -d --wait` | starting | four `Healthy` lines | §2.3 |
| 5 | E2 | `ORION_PROFILE=bench ./benchmark/run-e2.sh` | running | the `Table 4` section is printed | §3.4 |
| 6 | E3 (quick) | `docker compose -f docker-compose.yml --profile benchmark run --rm --user "$(id -u):$(id -g)" e3 --quick` | running | k6 summary; `benchmark/results/e3-*.json` written | §3.5 |
| 7 | Stop | `docker compose -f docker-compose.yml down` | stopped | `docker compose ps` lists nothing | §2.4 |

The same sequence as one copy-and-paste block (Bash; PowerShell below):
``` bash
# 1. image
export ORION_IMAGE=walnutd/orionlink-ae:ndss2027-v2
docker image pull "$ORION_IMAGE"

# 2. host-side dependencies (once)
go mod download
(cd benchmark/e2/browser && npm ci && npx playwright install chromium)

# 3. E1 — needs the stack stopped (the unit tests bind :3000 themselves)
docker compose -f docker-compose.yml down
go test ./benchmark/unit/
./benchmark/run-e1.sh            # 100 iterations; 1000 for the paper's setting

# 4.–6. E2 and E3 — need the stack running in bench mode
export ORION_PROFILE=bench
docker compose -f docker-compose.yml up -d --wait
./benchmark/run-e2.sh            # 10 iterations; 100 for the paper's setting
docker compose -f docker-compose.yml --profile benchmark \
  run --rm --user "$(id -u):$(id -g)" e3 --quick

# 7. stop
docker compose -f docker-compose.yml down
```
``` powershell
$env:ORION_IMAGE="walnutd/orionlink-ae:ndss2027-v2"
docker image pull $env:ORION_IMAGE

go mod download
Push-Location benchmark\e2\browser; npm ci; npx playwright install chromium; Pop-Location

docker compose -f docker-compose.yml down
go test ./benchmark/unit/
.\benchmark\run-e1.ps1

$env:ORION_PROFILE="bench"
docker compose -f docker-compose.yml up -d --wait
.\benchmark\run-e2.ps1
docker compose -f docker-compose.yml --profile benchmark run --rm e3 --quick

docker compose -f docker-compose.yml down
```

The paper's exact settings are E1 with 1000 iterations, E2 with 100 iterations
at each of four network delays (§3.6), and E3 with the full offered-load ladder
(§3.5). They take hours rather than minutes and are not needed to check any
structural claim.

## 3.2 Host prerequisites for E1 and E2
> **Where to run:** host shell. E1 and E2 are host-side harnesses that drive
> the containers from outside, so these tools are needed on the host even
> under Docker. E3 needs nothing here.

| Tool | Version | Used by | Check |
|------|---------|---------|-------|
| Go | ≥ 1.25 | E1 and the unit tests | `go version` |
| Node.js | ≥ 18 | E2 browser half (Playwright, installs its own Chromium) | `node -v` |
| Python 3 | ≥ 3.8 | E2 only, `benchmark/e2/summarize.py` (standard library only) | `python3 --version` |

[`requirements.txt`](requirements.txt) is the authoritative list, with the
versions the authors tested.

Install commands. Ubuntu 24.04:
``` bash
sudo apt-get update && sudo apt-get install -y python3 curl
# Go: the official tarball (apt ships an older Go)
curl -LO https://go.dev/dl/go1.25.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile && export PATH=$PATH:/usr/local/go/bin
# Node.js 22 LTS via NodeSource
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs
```
macOS (Homebrew):
``` bash
brew install go node python
```
Windows (winget, in PowerShell):
``` powershell
winget install GoLang.Go OpenJS.NodeJS.LTS Python.Python.3.12
```
Then verify:
``` bash
go version          # go version go1.25.x ...
node -v             # v18 or newer
python3 --version   # Python 3.8 or newer
```

Fetch the pinned Go modules and the Playwright browser once, from the
repository root:
``` bash
go mod download
cd benchmark/e2/browser
npm ci
npx playwright install chromium
cd ../../..
```

## 3.3 E1: Local computation overhead
> **Where to run:** host shell, repository root. Containers: **stopped**
> (`docker compose -f docker-compose.yml down`). E1 runs in-process and needs
> no server; a running stack would only compete for CPU, and the unit tests
> start their own IdP on :3000, which fails while the container holds the port.

E1 reproduces the six local-computation rows of Table III. Run the
correctness tests first, then E1:
``` bash
go test ./benchmark/unit/
./benchmark/run-e1.sh          # 100 iterations, quick evaluation
./benchmark/run-e1.sh 1000     # paper setting
```
PowerShell equivalent:
``` powershell
go test ./benchmark/unit/
.\benchmark\run-e1.ps1         # 100 iterations, quick evaluation
.\benchmark\run-e1.ps1 1000    # paper setting
```
The unit tests end with an `ok  secure-sso/benchmark/unit` line. E1 prints
the average of each of the six operations as it goes and finishes with a table
of six rows (Key generation, RP registers to IdP, Pseudonym generation,
AnonyAKE execution, Authorization revoke, Token refresh) and a `Total` line,
to be compared with Table III.
E1 also writes `benchmark/results/e1-wholeflow-<profile>.json`. The complete
Go test log is written to `/tmp/orionlink-e1.log` on Unix or the Windows
temporary directory.

## 3.4 E2: Latency breakdown
> **Where to run:** host shell, repository root. Containers: **running** with
> `ORION_PROFILE=bench`. Playwright and the Go refresh harness run on the host
> and talk to the containers over the published ports.

E2 reproduces Table IV with Playwright against the running containers. Login,
authorization management, and token refresh all use their live protocol paths;
token refresh is measured as an authenticated browser request through
RP → Broker → IdP and back.

Start (or restart) the four containers in benchmark mode. This mode registers
the RP at startup, which the browser experiment requires:
``` bash
ORION_PROFILE=bench docker compose -f docker-compose.yml up -d --wait
```
PowerShell equivalent:
``` powershell
$env:ORION_PROFILE="bench"
docker compose -f docker-compose.yml up -d --wait
```

Run E2 and print the consolidated Table IV:
``` bash
ORION_PROFILE=bench ./benchmark/run-e2.sh        # 10 iterations
ORION_PROFILE=bench ./benchmark/run-e2.sh 100    # paper setting
```
PowerShell equivalent:
``` powershell
$env:ORION_PROFILE="bench"
.\benchmark\run-e2.ps1          # 10 iterations
.\benchmark\run-e2.ps1 100      # paper setting
```
The run prints one `wrote ...` line per harness and `3 passed`, then a
`===== Table 4 =====` section with the SSO Flow rows (Click "Login", Consent
check, Authorization code exchange, Login successful) and the Extension rows
(Authorization management, Token refresh), to be compared with Table IV.
Ten iterations take about a minute. The reports are written to
`benchmark/results/`. To rerender the table without remeasuring, run
`ORION_PROFILE=bench ./benchmark/e2/summarize.py`. To run only the live
token-refresh measurement, use `npm run perf:refresh` from
`benchmark/e2/browser` after setting the same `ORION_*` environment variables.

For the latency experiment at 0/40/100/200 ms container-to-container RTT, apply
the corresponding egress delay described in §3.6 before each E2 run.

**OIDC baseline.** The brokered OIDC baseline that Table IV compares against is a
separate stack with its own image, Compose file and ports (14930-14932); it is
not part of the four containers above and has to be built and started on its
own. Stop the OrionLink stack first, since running both at once causes CPU
contention. See
[benchmark/oidc-baseline/README.md](benchmark/oidc-baseline/README.md) for the
build, the experiment commands and how to copy the results out of the container.

## 3.5 E3: Stress test
> **Where to run:** host shell, repository root. The k6 load generator itself
> runs inside the fifth Compose service `e3`, which these commands start and
> remove. Containers: running, `bench` profile, **no** netem delay.

E3 reproduces the AAKA-interface stress test of Fig. 8: offered load of
100, 500, 1000, 1300 and 1500 requests per second (RPS), 60 s per rate, for
each of the three roles. The submitted image contains the pinned k6 binary and
all E3 scripts, so it does not pull a separate k6 image at review time. By
default the runner starts a lightweight configuration (10 and 200 RPS) that
any machine sustains; the paper's ladder is requested with `--rps`.

Start the four services in benchmark mode with network delay disabled:
``` bash
ORION_PROFILE=bench ORION_NETEM_DELAY="" \
docker compose -f docker-compose.yml up -d --wait
```
PowerShell equivalent:
``` powershell
$env:ORION_PROFILE="bench"
$env:ORION_NETEM_DELAY=""
docker compose -f docker-compose.yml up -d --wait
```

Run the default, lightweight configuration (10 and 200 RPS, 60 s each, about
eight minutes):
``` bash
docker compose -f docker-compose.yml --profile benchmark \
  run --rm --user "$(id -u):$(id -g)" e3
```
PowerShell equivalent:
``` powershell
docker compose -f docker-compose.yml --profile benchmark `
  run --rm e3
```

The run prints one block per role (`idp`, `rp`, `broker`), each a table with
one row per offered load (`target`, `achieved`, `p50`, `p95`, `p99`,
`server p95`, `errors`, `dropped`), and ends with `===== E3 reports =====`
listing the three JSON files it wrote.

On an Apple-silicon Mac, Docker prints a one-line warning that the image's
platform (`linux/amd64`) differs from the host; the run proceeds under
emulation and the warning can be ignored.

`--quick` shortens each stage to 15 s (about two minutes), enough to check that
the path works:
``` bash
docker compose -f docker-compose.yml --profile benchmark \
  run --rm --user "$(id -u):$(id -g)" e3 --quick
```
PowerShell equivalent (the Unix UID/GID option is unnecessary on Windows):
``` powershell
docker compose -f docker-compose.yml --profile benchmark `
  run --rm e3 --quick
```

To reproduce Fig. 8 at the paper's setting, pass the paper's ladder (about 15
minutes; the three roles run one after another, five rates each). The stages
from 500 RPS up need a machine with cores to spare, on a smaller one they
measure the queue and drop requests:
``` bash
docker compose -f docker-compose.yml --profile benchmark \
  run --rm --user "$(id -u):$(id -g)" e3 \
  --rps 100,500,1000,1300,1500
```
PowerShell equivalent:
``` powershell
docker compose -f docker-compose.yml --profile benchmark `
  run --rm e3 --rps "100,500,1000,1300,1500"
```
Arguments after `e3` are passed to `benchmark/run-e3.sh`. For example:
``` bash
# Only measure one role: idp, rp, or broker.
docker compose -f docker-compose.yml --profile benchmark \
  run --rm --user "$(id -u):$(id -g)" e3 --line idp
```

The temporary load-generator container is removed after each run. JSON reports
are written to `benchmark/results/e3-{idp,rp,broker}-bench.json` on the host.
A stage is a valid data point only when `dropped` is `0` and `achieved` matches
`target`; use `p95` as the plotted latency. If the server containers were
started with `ORION_NETEM_DELAY`, their response-side delay will also appear in
E3, so baseline stress tests should leave it empty.

See `benchmark/README.md` for all parameters and troubleshooting.

## 3.6 Setting the container-to-container network delay
> **Where to run:** host shell, repository root. The script applies `tc` inside
> each running container for you; nothing has to be typed inside a container.

We use `tc` to set a delay for all outbound traffic. You can use the following shell for quick setting:
``` bash
./netem-compose.sh set-egress 20ms  # set RTT = 40ms
./netem-compose.sh set-egress 50ms  # set RTT = 100ms
./netem-compose.sh set-egress 100ms # set RTT = 200ms
./netem-compose.sh clear            # clear all delay. set RTT = 0ms
```
PowerShell equivalent:
``` powershell
.\netem-compose.ps1 set-egress 20ms  # set RTT = 40ms
.\netem-compose.ps1 set-egress 50ms  # set RTT = 100ms
.\netem-compose.ps1 set-egress 100ms # set RTT = 200ms
.\netem-compose.ps1 clear            # clear all delay; set RTT = 0ms
```
It will run `tc qdisc add dev "$iface" root netem delay "$delay"` in every container. So the `RTT` is nearly twice the set delay.

Or you can set it when starting containers:
``` bash
ORION_NETEM_DELAY=20ms \
docker compose -f docker-compose.yml up -d --wait
```

# 4. Try it in the browser

An optional functional check of the deployment, and the quickest way to see
what E2 measures. It is **not** a prerequisite for any experiment: E1 needs no
containers, and E2/E3 start the stack in `bench` mode, which registers the RP
by itself. Do it after §2.3 with the default `demo` profile; stop the stack
(`docker compose -f docker-compose.yml down`) before E1 afterwards.

Everything below happens in one browser. Use the demo account **Alice** /
**Alice-pass**. The PIN is any digits you choose at the first consent, but the
same PIN must be entered again later to decrypt or revoke, because the
management key is derived from it.

**Step 0 — Open the app.** Go to **http://localhost:3002/ssso/**. The RP's
start page lists "Four things to try", which are steps 1–4 below, and a
navigation bar with *Home*, *Register RP* and *Sign in*.

**Step 1 — Register the app** (paper Phase 1). Click *Register the app* (or
*Register RP* in the navigation bar). The page has two buttons:
- *Register to IdP* — the RP blinds its identity key and asks the IdP to sign it,
  obtaining the domain credential DC and the secret credential SC. On success
  the "Identity obtained" panel fills in Domain D (`http://localhost:3002/ssso/callback`)
  and truncated DC/SC values, and the second button becomes enabled.
- *Register to Broker* — the RP hands (cid, DC) to the broker, which stores it
  under an internal handle. On success a broker-side identifier is shown.
Registration is one-time; re-running it simply issues a fresh credential.
Follow *Continue to sign in →*. (Under `bench` profile this step has already
happened at startup and both buttons are merely re-registrations.)

**Step 2 — Sign in** (paper Phases 2–4). On the *Sign in* page click **Sign in
with OrionLink**. A popup window opens:
1. It shows the broker's "Connecting securely" relay page for a moment, then
   the IdP's **Sign in** page. Username and password are prefilled with
   `Alice` / `Alice-pass`; click *Continue*.
2. The IdP's **Authorize this application** page appears. The IdP displays
   only the app's one-time pseudonym (`acid`) and the requested scopes
   (`username email sub offline_access`); it cannot name the app. Embedded in
   the page is the TCA frame **Confirm the application**, served from the
   separate origin :3003. It verifies that `acid` really belongs to the RP you
   came from and then shows "You are signing in to
   http://localhost:3002/ssso/callback ✓ verified".
3. Type a PIN into the TCA frame and click **Authorize**. The TCA derives the
   management key from the PIN (PIN-OPRF with the IdP), encrypts the app
   identity D under it, and the IdP issues the authorization code.
4. The popup finishes and the original tab moves to the RP's **home page**,
   headed "Signed in as Alice".

The home page explains what happened: the four protocol phases; the "Who sees
what" panel, where the RP shows name, e-mail and `sub` decrypted under K_S while
the broker's column shows only the per-RP pseudonym `uid_rp` and "AES-GCM
ciphertext"; and the relayed access token with its decoded claims, whose
identity fields are ciphertext to the broker.

**Step 3 — Refresh the token** (extension: forward-secure token refresh). On
the home page click **Refresh access token**. The RP asks the broker to renew
the token through the ratcheted RP↔Broker↔IdP path. Expected result: the status
"✓ Renewed (time)", the counter "Refreshes so far" incremented, and a new
access token printed below the button. Repeat as often as you like.

**Step 4 — Manage or revoke the authorization** (extension: authorization
management and revoke). On the home page click **Manage / revoke at the IdP**.
You are taken to the IdP's account page (`http://localhost:3000/ssso/userinfo`),
"Hello, Alice", which lists the **Authorized clients**: one record per
authorization, each showing the scopes, the session pseudonym `acid` and the
encrypted app identity `D_enc`. The IdP itself cannot tell which app a record
belongs to. Each record has two buttons:
- **Decrypt** — opens the TCA dialog "Which app is this authorization for?".
  Enter the PIN from step 2 and click *Decrypt*. Expected result, inside the
  TCA frame only: "This authorization belongs to
  http://localhost:3002/ssso/callback", the `acid`, a nonce, and "Decryption
  successful." A wrong PIN yields a failed decryption. Close the dialog with ✕.
- **Revoke** — asks "Revoke this authorization?"; confirm. Expected result: the
  record disappears from the list and the status line reads "Authorization
  revoked." The RP's token for that session is no longer honoured.

**Sign out.** *Sign out / new login* in the RP's navigation bar returns to the
*Sign in* page; signing in again creates a fresh `acid` and a new record on the
IdP's account page.

If the TCA frame stays empty or the *Authorize* button never enables, the
browser could not reach `http://localhost:3003`: when working over SSH,
forward all four ports, not only 3002.

# 5. Build the image locally

Only needed if you do not want to pull the published image (§2.2). Both routes
below produce an image equivalent to `walnutd/orionlink-ae:ndss2027-v2`, tagged
`orionlink-ae:ndss2027-v2`, which is also the Compose default, so afterwards
either leave `ORION_IMAGE` unset or set it to that tag and continue with §2.3.

**Online build** (one command, needs internet for the Go toolchain and modules):
``` bash
docker build -t orionlink-ae:ndss2027-v2 .
```
Expected output (last lines): `naming to docker.io/library/orionlink-ae:ndss2027-v2`.

## 5.1 Offline build (no network during the code build)
Four steps. Steps 1–3 produce and load the Linux dependency base image;
step 4 compiles the OrionLink source into the code image on top of it.

**Step 1 — Package the base image.** Needs internet once (it pulls the Go and
k6 toolchains).
``` bash
./docker/package-offline-base.sh
```
PowerShell equivalent:
``` powershell
.\docker\package-offline-base.ps1
```
Expected output (last lines; the `id=` and checksum values differ per build):
```
base image: orionlink-ae-linux-base:go1.25.1-k6-1.8.0
id=sha256:... arch=amd64 size=... bytes
archive: dist/orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar
<sha256>  dist/orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar

Offline machine: docker load -i dist/orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar
```
The `dist/` directory now contains two files:
`orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar` and its `.sha256` checksum.

**Step 2 — Verify the archive.**
``` bash
shasum -a 256 -c dist/orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar.sha256
```
PowerShell equivalent (prints the hash; compare it by eye with the `.sha256` file):
``` powershell
Get-FileHash -Algorithm SHA256 .\dist\orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar
Get-Content .\dist\orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar.sha256
```
Expected output (Bash):
```
dist/orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar: OK
```

**Step 3 — Load the base image.** This is the only step that has to run on the
(possibly offline) build machine if steps 1–2 were done elsewhere.
``` bash
docker load -i dist/orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar
docker image inspect orionlink-ae-linux-base:go1.25.1-k6-1.8.0 --format '{{.Id}}'
```
PowerShell equivalent:
``` powershell
docker load -i .\dist\orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar
docker image inspect orionlink-ae-linux-base:go1.25.1-k6-1.8.0 --format '{{.Id}}'
```
Expected output:
```
Loaded image: orionlink-ae-linux-base:go1.25.1-k6-1.8.0
sha256:...
```

**Step 4 — Compile the source into the code image.** Runs with
`--network=none`; it only needs the base image from step 3.
``` bash
./docker/build-ae-offline.sh
```
PowerShell equivalent:
``` powershell
.\docker\build-ae-offline.ps1
```
Expected output (last lines):
```
offline code image: orionlink-ae:ndss2027-v2
id=sha256:... arch=amd64 size=... bytes
```
If step 3 was skipped, the script stops immediately with
`missing local base image: orionlink-ae-linux-base:go1.25.1-k6-1.8.0` and
tells you to run `docker load` first.

> **Note.** The base image (steps 1–3) only needs rebuilding when
> `go.mod`/`go.sum`, the pinned toolchain versions, or the Linux tool
> dependencies change. After a source-code change, re-run step 4 only.

### Check: the image is present
Whichever route you used, this must list one image with tag `ndss2027-v2`:
``` bash
docker image ls orionlink-ae
```
Expected output:
```
REPOSITORY     TAG           IMAGE ID       CREATED        SIZE
orionlink-ae   ndss2027-v2   ...            ...            ...
```

# 6. Source code introduction
## Directory Tree
```
OrionLink/
├── Broker/                         # Oblivious identity broker service (:3001)
│   ├── broker.go, handler.go       # Server entry point and HTTP route handlers
│   ├── aaka.go                     # Broker-side anonymous authenticated key agreement
│   ├── register.go, token.go       # RP registration and authorization-code/token relay
│   ├── refresh.go                  # Forward-secure token-refresh protocol
│   ├── persist.go, storage.go      # Persistent and in-memory broker state
│   ├── bench_support.go            # Bench-profile fixtures and measurement endpoints
│   ├── config/                     # Broker protocol configuration
│   └── static/                     # Broker authentication and popup pages
├── IdP/                            # Identity provider service (:3000)
│   ├── idp.go, handler.go, ssso.go # Server entry point and SSO routes
│   ├── aake.go                     # IdP-side anonymous authenticated key agreement
│   ├── register.go                 # User and RP credential issuance/registration
│   ├── token.go, refresh.go        # Token issuance and forward-secure refresh
│   ├── revoke.go                   # Authorization-management and revocation flow
│   ├── persist.go, storage.go      # Persistent and in-memory IdP state
│   ├── bench_support.go            # Bench-profile fixtures and measurement endpoints
│   ├── config/                     # IdP configuration, users, and generated key state
│   └── static/                     # Login, consent, revoke, and user-info pages
├── RP/                             # Relying party service (:3002)
│   ├── rp.go, handler.go           # Server entry point and RP HTTP routes
│   ├── aaka.go                     # RP-side proofs and authenticated key agreement
│   ├── register.go                 # Registration with the IdP and broker
│   ├── token.go, refresh.go        # Token redemption, decryption, and refresh
│   ├── persist.go, storage.go      # RP sessions, credentials, and persistent state
│   ├── bench_support.go            # Bench-profile auto-registration support
│   ├── config/                     # RP protocol configuration and generated key state
│   └── static/                     # Registration, login, home, and shared CSS assets
├── benchmark/                      # Paper experiments and correctness harnesses
│   ├── README.md                   # E1–E3 scope, commands, outputs, and troubleshooting
│   ├── e1/                         # Table III in-process local-computation experiment
│   │   ├── wholeflow.go            # Six-stage OrionLink protocol benchmark
│   │   └── *_test.go               # E1 benchmark and go-test entry points
│   ├── e2/                         # Table IV user-visible latency experiment
│   │   ├── browser/                # Playwright login, authorization-management, and live-refresh tests
│   │   │   ├── perf/               # Timed browser-flow specifications
│   │   │   └── lib/                # Shared flow control and JSON report utilities
│   │   ├── tokenrefresh/           # Local refresh microbenchmark (not container-RTT E2)
│   │   └── summarize.py            # Consolidates E2 measurements into the paper table
│   ├── e3/                         # Figure 8 k6 AAKA-interface stress experiment
│   │   ├── idp_token.js            # IdP verification and token-issuance load test
│   │   ├── rp_pok.js               # RP proof-construction load test
│   │   ├── broker_randomize.js      # Broker credential-randomization load test
│   │   └── lib/                    # Shared k6 request generation and result reporting
│   ├── unit/                       # Crypto, wire-format, configuration, and startup tests
│   ├── results/                    # E2/E3 JSON reports and TCA benchmark measurements
│   ├── run-e{1,2}.{sh,ps1}         # Cross-platform E1/E2 host runners
│   └── run-e3.sh                   # Linux/container E3 load-test runner
├── docker/                         # Host/build and container runtime helpers
│   ├── ae-entrypoint.sh            # Dispatches one image to the TCA/IdP/Broker/RP role
│   ├── orion-netem.sh              # Container-side tc/netem egress-delay control
│   ├── package-offline-base.{sh,ps1} # Builds/exports the offline dependency image
│   └── build-ae-offline.{sh,ps1}   # Builds the code image with networking disabled
├── internal/                       # Shared non-exported application modules
│   ├── common/                     # Shared types, serialization, codes, and refresh keys
│   ├── config/                     # Deployment profiles, endpoints, and web configuration
│   └── protocol/                   # RP↔Broker↔IdP wire-message definitions
├── lib/                            # Reusable cryptographic primitives
│   ├── PSSig.go                    # Pointcheval-Sanders signatures
│   ├── anonyCred.go                # Blind issuance and anonymous credentials
│   ├── NIZK.go                     # Non-interactive zero-knowledge proofs
│   ├── oprf/                       # OPRF server-side implementation
│   └── utils.go                    # Shared cryptographic helpers
├── tca/                            # Trusted Client Application served on origin :3003
│   ├── dvf*.js, dvf*.html          # Consent and authorization-management logic/pages
│   ├── cryptolib.js                # Browser-side OrionLink cryptographic operations
│   ├── *.bundle.js                 # Committed browser bundles used by the AE deployment
│   ├── vendor/                     # Offline-pinned third-party browser crypto bundle
│   ├── bench.html                  # Browser/mobile cryptographic microbenchmark
│   ├── nginx.conf                  # Dedicated-origin security headers and static serving
│   ├── orion-config.js.tmpl        # Runtime-generated browser endpoint configuration
│   ├── docker-entrypoint.d/        # TCA configuration renderer for nginx startup
│   └── build-*.sh, update-sri.sh   # Bundle construction and SRI verification scripts
├── dist/                           # Generated offline base-image tarball and checksum
├── .gitattributes                  # Forces LF endings for shell/PowerShell scripts
├── .dockerignore                   # Files excluded from Docker build contexts
├── .env.example                    # Unified image, port, profile, and netem settings template
├── .gitignore                      # Git exclusions for generated state and dependencies
├── CLAUDE.md                       # Repository architecture, invariants, and edit rules
├── Dockerfile                      # Online self-contained four-role AE image
├── Dockerfile.base                 # Linux toolchain/dependency base for offline builds
├── Dockerfile.offline              # Network-disabled build from the offline base image
├── docker-compose.yml              # Canonical four-container AE deployment from one image
├── go.mod                          # Go module declaration and dependency versions
├── go.sum                          # Checksums for the resolved Go dependency graph
├── main.go                         # Binary dispatcher for idp, broker, and rp roles
├── netem-compose.{sh,ps1}          # Cross-platform host netem control
├── run.sh                          # Host launcher for source-built services and TCA nginx
├── tca-paper-edit-map.md           # TCA design-to-paper revision checklist
├── LICENSE                         # Project license
└── README.md                       # Build, deployment, evaluation, and source overview
```

## Dependency
### Server end
1. go: `>= 1.25.0`
2. Cloudflare’s CIRCL library (BLS12-381 pairing):
    - module: `github.com/cloudflare/circl` (used v1.6.1)
    - install: `go get github.com/cloudflare/circl@v1.6.1`
3. Fiber web framework:
    - module: `github.com/gofiber/fiber/v2` (used v2.52.9)
    - install: `go get github.com/gofiber/fiber/v2@v2.52.9`
4. JWT library (for ID token issuance/verification):
    - module: `github.com/golang-jwt/jwt/v4` (used v4.4.3)
    - install: `go get github.com/golang-jwt/jwt/v4@v4.4.3`
5. (indirect) crypto helpers from the Go ecosystem may be pulled in, e.g. `golang.org/x/crypto`.

After editing dependencies, run `go mod tidy` or `go build ./...` to fetch modules.

### Client end
1. BLS12-381 library for JavaScript:
   - module: `https://cdn.jsdelivr.net/npm/@noble/bls12-381`
   - import: `import * as bls from 'https://cdn.jsdelivr.net/npm/@noble/bls12-381';`

### Run from source without Docker (development)

This is the developer path: the three Go roles run directly on the host with
`go run`, reading their pages from the working tree, so an edit is live on the
next request without rebuilding any image. Only the TCA still runs as a
container, because its separate origin (:3003) is part of the design and nginx
serves it. The one-command version of everything below is `./run.sh`
(`./run.sh down` stops, `./run.sh status` reports, `./run.sh reset` wipes
generated keys and registrations).

Each `go run` below is a **blocking, long-running server** — it will not return
to the prompt. Start each one in **its own terminal**, in this order (idp first,
since broker/rp connect to it on startup).

``` bash
go mod tidy
```

```bash
# Terminal 1 — TCA static origin on :3003 (needed for the browser flow)
docker run --rm --name orionlink-tca -p 3003:3003 \
  -v "$PWD/tca:/usr/share/nginx/html:ro" \
  -v "$PWD/tca/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  nginx:alpine

# Terminal 2 — IdP on :3000 (start first)
go run main.go -name=idp

# Terminal 3 — Broker on :3001
go run main.go -name=broker

# Terminal 4 — RP on :3002
go run main.go -name=rp
```

If a server prints `listen on :<port> failed: ... address already in use` and
exits, a previous instance is still holding the port. Find and stop it:

```bash
ss -ltnp | grep -E ':3000|:3001|:3002|:3003'   # identify the pid holding the port
kill <pid>
```

The image contains all four roles; to run a single one from the image instead,
pass the role as the container command, e.g.
`docker run --rm -p 3001:3001 walnutd/orionlink-ae:ndss2027-v2 broker`.

## Status

The `/ssso/*` routes on each server implement the active OrionLink protocol;
`IdP/idp.go`, `Broker/broker.go`, `RP/rp.go` are the entry points. The OIDC
compatibility layer (`/oauth2/*`, `oidc_*.html`, `*/oidc.go`) was removed in
the dev-eval alignment — restore from git history if interop is needed.

## Serialization
### BLS12-381 Structure
#### Scalar
1. Use standard provider (big-endian) to byte array: `scalarBytes = Scalar.MarshalBinary(scalar)`
2. Use base64 encode to string: `scalarString = base64.StdEncoding.EncodeToString(scalarBytes)`
#### G1
1. Use standard compress to byte array: `pointBytes = point.BytesCompressed()`
2. Use base64 encode to string: `pointString = base64.StdEncoding.EncodeToString(pointBytes)`
#### G2
1. Use standard compress to byte array: `pointBytes = point.BytesCompressed()`
2. Use base64 encode to string: `pointString = base64.StdEncoding.EncodeToString(pointBytes)`

# Cite this paper
Y. Fang, B. Li, L, Jin, J. Lin, M. Zhou, Z. Zhang, L. Li, Q. Wu, "OrionLink: Single Sign-On with Oblivious Identity Brokers," in Proceedings of the Network and Distributed System Security Symposium (NDSS), 2027.

# Reference
[1] Pointcheval, D., Sanders, O.: Short randomizable signatures. In: Sako, K. (ed.) Topics in Cryptology - CT-RSA 2016. pp. 111–126. Springer International Publishing (2016)  
[2] Damgård, I.: On Σ-protocols. Lecture Notes, University of Aarhus, Department for Computer Science. pp. 84-105 (2002)  
[3] Fiat, A., Shamir, A.: How To Prove Yourself: Practical Solutions to Identification and Signature Problems. In: Odlyzko, A.M. (ed.) Advances in Cryptology CRYPTO’ 86. pp. 186–194. Lecture Notes in Computer Science, Springer (1987)   
[4] He, J., Lei, L., Wang, Y., Wang, P., Jing, J. (2024). ARPSSO: An OIDC-Compatible Privacy-Preserving SSO Scheme Based on RP Anonymization. In: Garcia-Alfaro, J., Kozik, R., Choraś, M., Katsikas, S. (eds) Computer Security – ESORICS 2024. ESORICS 2024. Lecture Notes in Computer Science, vol 14983. Springer, Cham. https://doi.org/10.1007/978-3-031-70890-9_14
