ARG BUILDPLATFORM
ARG TARGETARCH
ARG K6_IMAGE=grafana/k6:1.8.0@sha256:b992f241070f3f3a7d78096fa6020db1edcda49297ee8ed9eb0ab847ef3dcb32

FROM --platform=${BUILDPLATFORM} golang:1.25.1-alpine3.21 AS builder
WORKDIR /src
ARG TARGETARCH

COPY go.mod go.sum ./
RUN go env -w GOPROXY=https://proxy.golang.org,direct && go mod download

COPY main.go ./
COPY Broker ./Broker
COPY IdP ./IdP
COPY RP ./RP
COPY internal ./internal
COPY lib ./lib

# One static binary serves all three Go roles. TARGETARCH is supplied by
# BuildKit/buildx, allowing the submitted image to be published for amd64 and
# arm64 from the same Dockerfile.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags='-s -w' -o /out/orionlink ./main.go

FROM ${K6_IMAGE} AS k6

FROM nginx:1.31.3-alpine

# iproute2 supplies tc/netem. Containers still need the narrowly scoped
# NET_ADMIN capability at runtime; docker-compose.yml grants it without
# making the containers privileged. Bash runs the E3 wrapper; the pinned k6
# binary is copied from Grafana's multi-architecture release image below.
RUN apk add --no-cache bash ca-certificates curl iproute2

WORKDIR /app

COPY --from=builder /out/orionlink /app/orionlink
COPY --from=k6 /usr/bin/k6 /usr/local/bin/k6
COPY RP/static /app/RP/static
COPY RP/config /app/RP/config
COPY Broker/static /app/Broker/static
COPY Broker/config /app/Broker/config
COPY IdP/static /app/IdP/static
COPY IdP/config /app/IdP/config

# The same image also contains the complete TCA origin. No source-tree bind
# mount is needed by the canonical compose file.
COPY tca /usr/share/nginx/html
COPY tca/nginx.conf /etc/nginx/conf.d/default.conf
COPY tca/docker-entrypoint.d/40-orion-config.sh /usr/local/bin/orion-render-tca

COPY docker/ae-entrypoint.sh /usr/local/bin/orion-entrypoint
COPY docker/orion-netem.sh /usr/local/bin/orion-netem
COPY benchmark/run-e3.sh /app/benchmark/run-e3.sh
COPY benchmark/e3 /app/benchmark/e3

RUN chmod 0755 \
      /app/orionlink \
      /app/benchmark/run-e3.sh \
      /usr/local/bin/orion-entrypoint \
      /usr/local/bin/orion-netem \
      /usr/local/bin/orion-render-tca \
    && mkdir -p /app/benchmark/results /usr/share/nginx/orion /etc/nginx/orion

ENV ORION_ASSET_DIR=/app

EXPOSE 3000 3001 3002 3003

ENTRYPOINT ["/usr/local/bin/orion-entrypoint"]
CMD ["idp"]
