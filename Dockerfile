# One image with every service binary, the demo included. The logs CLI runs on the host.
FROM golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/ ./cmd/keysvc ./cmd/collector ./cmd/aggregator ./cmd/producer ./cmd/demo

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
# The demo follows pipeline events with kubectl logs, using its ServiceAccount.
ARG TARGETARCH
RUN set -e; case "$TARGETARCH" in \
      amd64) sum=6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f ;; \
      arm64) sum=922df28df248cc00a9e025f947704f1d1482de64ece54cfe57e61f19eaf1eef3 ;; \
      *) echo "unsupported arch $TARGETARCH"; exit 1 ;; esac; \
    curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.37.0/bin/linux/$TARGETARCH/kubectl"; \
    echo "$sum  /usr/local/bin/kubectl" | sha256sum -c -; chmod +x /usr/local/bin/kubectl
COPY --from=build /out/ /usr/local/bin/
USER 65532:65532
