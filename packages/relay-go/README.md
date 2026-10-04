# CPace-Relay — Go relay server

This directory contains a pure-Go port of `packages/relay` (the TypeScript reference implementation).

## Why Go?

| Concern | TypeScript relay | Go relay |
|---|---|---|
| Concurrency model | Single-threaded event loop | Goroutine-per-connection |
| Memory at idle | ~60 MB (Node runtime) | ~5–8 MB |
| Deployment | Needs Node.js runtime | Single static binary |
| Crypto stdlib | `ws` + `tweetnacl` | `golang.org/x/crypto` (ristretto255, hkdf, nacl/box) |
| Cold start | ~400 ms | <10 ms |

## Structure

```
relay-go/
├── main.go          # entrypoint (PORT env var, SIGINT handler)
├── types.go         # wire message types (mirrors types.ts)
├── store.go         # in-memory session store with TTL enforcement (mirrors store.ts)
├── ratelimit.go     # sliding-window rate limiter (mirrors rateLimit.ts)
├── server.go        # WebSocket handler + all 4 message routes (mirrors server.ts)
├── server_test.go   # integration tests (mirrors wire.test.ts)
├── go.mod
└── Dockerfile
```

## Running

```bash
# Dev
go run .

# With custom port
PORT=9090 go run .

# Build binary
go build -o relay-go .

# Tests
go test ./... -v

# Docker
docker build -t cpace-relay-go .
docker run -p 8080:8080 cpace-relay-go
```

## Protocol compatibility

The Go relay is **wire-compatible** with the TypeScript relay — the existing `packages/test-clients` and `packages/crypto` work against it unchanged. The message schema (`initSession`, `joinSession`, `registerKey`, `relay` and their responses) is identical.

## Security properties preserved

- **Blind broker**: server stores and forwards only ciphertext and base64 nacl blobs. No PIN, no scalars, no derived keys ever touch this process.
- **Application-level TTL**: session expiry is checked on every read, not by a background sweeper. A missed sweep cannot widen the attack window.
- **Rate limiting**: 10 `joinSession` attempts per 5-minute window. The 11th permanently locks the session for its remaining lifetime.
- **PHI guard**: a best-effort regex check rejects any blob field that looks like plaintext medical text, catching accidental developer mistakes before they reach the store.
