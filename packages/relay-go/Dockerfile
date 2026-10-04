FROM golang:1.22-alpine AS builder

WORKDIR /build

# Cache dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Build static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o relay-go ./cmd/relay

# ── Runtime image ─────────────────────────────────────────────────────────
# Use alpine (not scratch) so we get a shell for the HEALTHCHECK curl
FROM alpine:3.20

RUN apk add --no-cache curl

COPY --from=builder /build/relay-go /relay-go

EXPOSE 8080

# The relay exposes no HTTP health endpoint itself (it's pure WebSocket).
# We probe the TCP port to confirm the process is up.
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD nc -z localhost 8080 || exit 1

ENTRYPOINT ["/relay-go"]
