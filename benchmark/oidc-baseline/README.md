Brokered OIDC Baseline
----------------------

This project provides the brokered OIDC baseline used by the OrionLink
comparison experiments. It runs an identity provider (`idp`), an identity
broker (`broker`), and a relying party (`rp`). The supplied users and client
credentials are experiment fixtures only; do not use them in production.

# 1. Run in containers

## 1.1 Build and package the image

Requirements:

- Docker with the Compose plugin (`docker compose`)
- Host ports `14930`, `14931`, and `14932` must be free
- Node.js 18 or later only when running the Playwright experiment

Build the image from source:

```bash
docker build -t secure-sso-oidc:local .
docker image inspect secure-sso-oidc:local
```

The multi-stage Dockerfile compiles a static Go binary and copies only the
runtime binary, HTML templates, and configuration into the final image. It
does not depend on a locally prepared base image.

To build for a specific Linux architecture, for example AMD64:

```bash
docker buildx build \
  --platform linux/amd64 \
  --load \
  -t secure-sso-oidc:local .
```

To export the image for offline transfer:

```bash
mkdir -p dist
docker save -o dist/secure-sso-oidc-local.tar secure-sso-oidc:local
shasum -a 256 dist/secure-sso-oidc-local.tar > dist/secure-sso-oidc-local.tar.sha256
shasum -a 256 -c dist/secure-sso-oidc-local.tar.sha256
```

On the target machine, load and check the image:

```bash
docker load -i dist/secure-sso-oidc-local.tar
docker image inspect secure-sso-oidc:local
```

## 1.2 Start the containers

This baseline uses `14930`-`14932`, independently of OrionLink's ports. The two
stacks can coexist from a port-allocation perspective. For performance
comparisons, run only the stack being measured to avoid CPU and memory
contention.

Build when necessary and start all three services:

```bash
docker compose up -d --build --wait
docker compose ps
```

If the image was loaded from a tar archive, start it without rebuilding:

```bash
OIDC_IMAGE=secure-sso-oidc:local \
docker compose up -d --no-build --wait
```

The host mappings and the corresponding container-internal listeners use the
same ports:

- IdP: http://localhost:14930
- Broker: http://localhost:14931
- RP: http://localhost:14932/oauth2/

Compose starts the services in `idp` -> `broker` -> `rp` order. Broker and RP
start with `-register`; they reuse the supplied credentials when present and
otherwise register after their dependencies become healthy.

Inspect status and logs:

```bash
docker compose ps
docker compose logs --tail=100 idp broker rp
```

## 1.3 Use the browser flow

Open http://localhost:14932/oauth2/ and click **Login with OIDC**. The browser
is redirected through the broker to the IdP and then back to the RP user page.
For deterministic benchmark execution, the IdP page uses the fixture account
`Alice / Alice-pass` and submits the form automatically.

## 1.4 Run the comparison experiments

Run the server stack before either experiment:

```bash
docker compose up -d --build --wait
mkdir -p results
```

The result files live inside the RP container. Copy them out before running
`docker compose down`, which removes the containers and their unexported data.

### 1.4.1 RP registration latency

Clear prior in-container samples, then run the built-in 10-iteration client:

```bash
docker compose exec -T rp sh -c ': > /app/RP/register_latency_test.txt'
docker compose exec -T rp \
  ./secure-sso-oidc -name=test_register \
  | tee results/oidc-registration-client.log
docker compose cp \
  rp:/app/RP/register_latency_test.txt \
  ./results/oidc-register-latency.txt
```

The terminal log measures each complete HTTP request to the RP registration
endpoint. `oidc-register-latency.txt` separately records the RP server's IdP
registration time and broker-registration time. The client waits 100 ms
between requests; that wait is outside the reported request duration.

### 1.4.2 End-to-end OIDC latency

Install the pinned Playwright dependency and Chromium on the host once:

```bash
cd e2e
npm ci
npx playwright install chromium
cd ..
```

Clear prior samples and run the browser experiment (10 iterations by default):

```bash
docker compose exec -T rp sh -c ': > /app/RP/latency_results.txt'
npm --prefix e2e test
docker compose cp \
  rp:/app/RP/latency_results.txt \
  ./results/oidc-e2e-latency.txt
```

For the paper's 100-iteration setting, run the same experiment with:

```bash
OIDC_E2E_ITERATIONS=100 npm --prefix e2e test
```

Playwright must run on the host because the browser-visible redirects and
callbacks intentionally use `localhost:14930` through `localhost:14932`.

Each recorded sample contains:

- `T1 (Login -> IdP render)`: RP login click to the IdP page's post-render marker
- `T2 (Submit -> UserView)`: IdP form submission to the RP user-view marker
- `T3 (Total)`: RP login click to the RP user-view marker

The IdP form submission is automated, so these values measure the implemented
machine path and exclude human typing or decision time. The one-second wait at
the end of each Playwright iteration only allows the metrics request to finish
and is outside `T1`-`T3`.

For an OrionLink comparison, use the same machine, Chromium version, iteration
count, and network-delay setting, and measure the two stacks separately to
avoid CPU contention. Compare only rows with the same timing boundaries; the
three OIDC markers above are not automatically equivalent to every OrionLink
latency-breakdown row.

### 1.4.3 Apply network delay with tc/netem

The image contains `tc`, and Compose grants each service `NET_ADMIN`. The
following example adds `20ms` egress delay to every service container:

```bash
for service in idp broker rp; do
  docker compose exec -T --user root "$service" \
    tc qdisc replace dev eth0 root netem delay 20ms
done
```

Check the active rule:

```bash
docker compose exec -T --user root idp tc qdisc show dev eth0
docker compose exec -T --user root broker tc qdisc show dev eth0
docker compose exec -T --user root rp tc qdisc show dev eth0
```

Clear all delay rules:

```bash
for service in idp broker rp; do
  docker compose exec -T --user root "$service" \
    sh -c 'tc qdisc del dev eth0 root 2>/dev/null || true'
done
```

This setting delays traffic leaving each selected container. The total added
delay depends on the number of container-egress legs traversed by the measured
flow, so record the exact rule with every result set.

## 1.5 Stop and clean up

```bash
docker compose down
```

To remove the locally built image as well:

```bash
docker image rm secure-sso-oidc:local
```

# 2. Source code introduction

```text
secure-sso-oidc/
├── IdP/                         # OIDC identity provider (:14930)
│   ├── idp.go, oidc.go          # Server entry point and OIDC routes
│   ├── token.go, storage.go     # Token and authorization-code handling
│   ├── persist.go              # User and client configuration persistence
│   ├── config/                 # Demo users and registered clients
│   └── static/                 # Login and user-information pages
├── Broker/                      # OIDC identity broker (:14931)
│   ├── broker.go, oidc.go       # Server entry point and brokered OIDC flow
│   ├── token.go                # Broker token issuance and validation
│   ├── persist.go              # Broker, IdP, and RP credential persistence
│   ├── config/                 # Runtime endpoints and demo credentials
│   └── static/                 # Registration and login pages
├── RP/                          # OIDC relying party (:14932)
│   ├── rp.go, oidc.go           # Server entry point, callbacks, and metrics
│   ├── benchmark_register.go    # Ten-iteration registration client
│   ├── persist.go, storage.go   # RP runtime configuration and state
│   ├── config/                 # Runtime endpoints and client credentials
│   └── static/                 # RP registration, login, and user pages
├── e2e/                         # Playwright end-to-end latency experiment
├── internal/                    # Shared protocol and serialization types
├── lib/                         # Cryptographic helpers
├── .dockerignore               # Docker build-context exclusions
├── Dockerfile                  # Multi-stage server image
├── docker-compose.yml          # Three-service local experiment stack
├── go.mod, go.sum              # Pinned Go dependencies
└── main.go                     # idp/broker/rp/test_register dispatcher
```

# 3. Troubleshooting

| Symptom | Cause and action |
|---|---|
| A container remains unhealthy | Run `docker compose logs <service>`; the health checks probe the OIDC discovery or RP home endpoint. |
| Port `14930`, `14931`, or `14932` is already allocated | Stop or reconfigure the conflicting process. The browser URLs, internal listeners, and registered callbacks require these exact ports. |
| Playwright reports that Chromium is missing | Run `cd e2e && npx playwright install chromium`. |
| The E2E test reaches the registration page | Check broker/RP auto-registration in `docker compose logs broker rp`, then recreate the stack with `docker compose down && docker compose up -d --build --wait`. |
| A result file is missing on the host | Results are written inside the RP container; run the documented `docker compose cp` command before `docker compose down`. |

# 4. Reference

[1] J. He, L. Lei, Y. Wang, P. Wang, and J. Jing, "ARPSSO: An OIDC-Compatible Privacy-Preserving SSO Scheme Based on RP Anonymization," ESORICS 2024, doi:10.1007/978-3-031-70890-9_14.
