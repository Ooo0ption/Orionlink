ARG GO_VERSION=1.25.1
ARG ALPINE_VERSION=3.21

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY Broker ./Broker
COPY IdP ./IdP
COPY RP ./RP
COPY internal ./internal
COPY lib ./lib

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/secure-sso-oidc ./main.go

FROM alpine:${ALPINE_VERSION} AS runtime

# iproute2 supplies tc/netem for the network-delay comparison experiment.
RUN apk add --no-cache ca-certificates iproute2 \
    && addgroup -S oidc \
    && adduser -S -G oidc oidc

WORKDIR /app

COPY --from=builder --chown=oidc:oidc /out/secure-sso-oidc ./secure-sso-oidc
COPY --chown=oidc:oidc IdP/static ./IdP/static
COPY --chown=oidc:oidc IdP/config ./IdP/config
COPY --chown=oidc:oidc Broker/static ./Broker/static
COPY --chown=oidc:oidc Broker/config ./Broker/config
COPY --chown=oidc:oidc RP/static ./RP/static
COPY --chown=oidc:oidc RP/config ./RP/config

USER oidc

EXPOSE 14930 14931 14932

ENTRYPOINT ["./secure-sso-oidc"]
CMD ["-name=idp"]
