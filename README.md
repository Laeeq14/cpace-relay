# CPace-Relay

> **An untrusted-broker PAKE for pairing two devices over an insecure channel using nothing but a short-lived PIN.**
> No server-side trust. No stored verifier. No offline dictionary attack surface.

Originally designed for encrypted patient intake (PassChart); the protocol itself is domain-agnostic — see [Applications](#applications) below.

**Threat model**: [`THREAT_MODEL.md`](./THREAT_MODEL.md)

---

## Status

The core protocol — PAKE handshake, relay, threat model, test suite — is complete and stable. This repo is maintained as a **reference implementation and portfolio project**, not a commercial product.

A hypothetical productization path (patient-facing UI, HIPAA compliance structure, clinical pilot) is sketched in [`/docs/productization-notes.md`](./docs/productization-notes.md) for anyone evaluating this for real-world use — but is not active development.

---

## What This Is

A two-device pairing protocol over a zero-knowledge relay:

1. **Device A** generates a random 6-digit PIN and opens a session on the relay
2. **Device B** enters the PIN and joins
3. Both sides independently derive the same ristretto255 DH generator `G = hash_to_curve(PBKDF2(pin) ‖ sessionId)`
4. Each sends an ephemeral point `Y = r * G` through the relay; the relay forwards it without being able to verify or forge it
5. Both compute the same shared secret `K = r_A * Y_B = r_B * Y_A` — the relay never sees the scalars
6. Both derive a session key via HKDF and prove it with HMAC-based key confirmation before any data is exchanged
7. Subsequent messages are encrypted with `nacl.box` (XSalsa20-Poly1305)

The relay is a **blind broker** throughout. It stores only ciphertext, enforces rate limits and TTL, and has no access to the PIN, the scalars, or the derived keys.

---

## Applications

This is a PIN-authenticated key exchange over a zero-knowledge relay. The pattern generalizes to any two-party pairing problem where a middle server should not be a trust bottleneck:

- **Healthcare intake** — encrypted symptom data from a patient device to a clinician browser, with no PHI in transit (original design target)
- **IoT device pairing** — pairing a smartphone to a new device using a PIN shown on-screen, without trusting the cloud broker
- **Ephemeral secure channels** — legal document exchange, attorney-client communications, scenarios where both parties want end-to-end encryption without pre-shared keys or PKI
- **Wallet recovery / key ceremonies** — any flow where two parties need to establish a shared secret authenticated only by a low-entropy code

**Domains with strict compliance regimes** (finance, broker-dealer under SEC 17a-4, HIPAA-covered entities) need additional review before this pattern applies as-is. The relay as implemented does not provide message persistence, audit logs, or the immutability guarantees those regimes require.

---

## Architecture

```
Device A                        Relay (blind broker)              Device B
      │                               │                                 │
      │── initSession ───────────────>│                                 │
      │   (sessionId assigned)        │                                 │
      │<── sessionInited ─────────────│                                 │
      │                               │<── joinSession ────────────────│
      │                               │                                 │
      │ G = hash_to_curve(            │                G = hash_to_curve(
      │   PBKDF2(PIN) || sessionId)   │                  PBKDF2(PIN) || sessionId)
      │ Ya = a * G  ─────────────────>│─── Ya (point) ─────────────────>│
      │                               │<── Yb (point) ──────────────────│
      │<─────────────── Yb ───────────│    Yb = b * G                   │
      │                               │                                 │
      │ K = a*Yb  [scalar a secret]   │             K = b*Ya  [scalar b secret]
      │ key = HKDF(K || Ya || Yb || sessionId)                          │
      │── HMAC(key,"A-confirm") ─────>│─── confirm ────────────────────>│
      │<── HMAC(key,"B-confirm") ─────│<── confirm ─────────────────────│
      │                               │                                 │
      │ [both verify confirmation]    │                 [both verify]
      │── relay(nacl.box ciphertext)─>│── relayed ─────────────────────>│
      │                               │                  [decrypt & display]
```

---

## Cryptographic Protocol

### Why not plain X25519?

A plain DH exchange over an untrusted relay is MITM-able: the relay can substitute its own public key and terminate both sides independently. Adding a PIN is the standard mitigation — but *how* the PIN is used matters.

### The oracle problem with `secretbox(pubKey, PBKDF2(pin))`

The first implementation wrapped each side's X25519 public key in `nacl.secretbox` keyed with `PBKDF2(pin)`. This prevents the relay from forging keys (it doesn't know the PIN), but creates a **verifiable decryption oracle**:

- An eavesdropper captures the wrapped key from the wire
- For each of the 1,000,000 possible PINs: compute `PBKDF2(guess)`, try `secretbox.open`, check the MAC
- If the MAC validates, the PIN is found — no relay interaction required, rate limits don't apply

PBKDF2 at 600k iterations makes each trial slow (~seconds on commodity hardware), but does not remove the oracle. The attack surface is the captured ciphertext, not the relay.

### CPace: moving the PIN into the exponent

CPace (IETF draft-irtf-cfrg-cpace) eliminates the oracle by mixing the PIN into the DH *generator* via hash-to-curve, not into a symmetric cipher wrapped around the key:

1. **PIN-blinded generator** — Both sides compute `G = hash_to_curve(PBKDF2(pin) ‖ sessionId)` using `ristretto255_hasher` (RFC 9380). The relay never sees or computes G.
2. **Ephemeral DH messages** — Each side generates a random scalar `r` (reduced mod curve order), computes `Y = r * G`, and sends Y to the relay. The scalar is held in memory only, never transmitted.
3. **Shared secret** — `K = r_A * Y_B = r_B * Y_A = r_A * r_B * G` (identical by commutativity of scalar multiplication).
4. **Session key** — `HKDF(K ‖ Y_A ‖ Y_B ‖ sessionId)` → 32-byte key. The sessionId binding prevents cross-session replay.
5. **Key confirmation** — Each side sends `HMAC-SHA256(sessionKey, "<role>-confirm")`, proving they derived the same key without revealing it.
6. **Message encryption** — `nacl.box` (XSalsa20-Poly1305).

**Why this eliminates the oracle**: to verify a guessed PIN, an attacker needs to compute `K = r * Y_peer`. That requires knowing `r` — the ephemeral scalar, which is never transmitted. The wire messages `Y_A` and `Y_B` are group elements on ristretto255; checking a PIN guess against them is computationally equivalent to solving the discrete log problem, not checking a MAC.

---

## Libraries

| Library | Purpose |
|---|---|
| [`tweetnacl`](https://github.com/dchest/tweetnacl-js) | X25519 key exchange, XSalsa20-Poly1305 encryption — audited, no native deps |
| [`tweetnacl-util`](https://github.com/dchest/tweetnacl-util) | Base64 encode/decode for wire format |
| `crypto.subtle` (Web Crypto API) | PBKDF2 key derivation — built-in, no extra dependency |
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | Ristretto255 hash-to-curve (RFC 9380) for CPace PAKE — audited, pure-JS |
| [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) | HKDF, HMAC-SHA256 for session key derivation and key confirmation — audited, pure-JS |
| [`ws`](https://github.com/websockets/ws) | Local WebSocket relay server |

---

## Monorepo Structure

```
cpace-relay/
├── packages/
│   ├── crypto/                  ← Shared encryption logic
│   │   ├── src/
│   │   │   ├── pin.ts           ← 6-digit PIN generation (crypto.getRandomValues, rejection sampling)
│   │   │   ├── pinKdf.ts        ← PBKDF2 key derivation (600k iterations, SHA-256)
│   │   │   ├── keyExchange.ts   ← Legacy X25519 DH + nacl.box (baseline, kept for reference)
│   │   │   ├── cpace.ts         ← CPace PAKE: hash-to-curve, DH, session key, key confirmation
│   │   │   └── index.ts         ← Package barrel export
│   │   └── tests/
│   │       ├── pinKdf.test.ts       ← KDF determinism + distinctness tests
│   │       ├── keyExchange.test.ts  ← Legacy round-trip + wire-level plaintext assertions
│   │       └── cpace.test.ts        ← CPace handshake, offline oracle proof, session isolation
│   │
│   ├── relay/                   ← Local WebSocket relay server
│   │   ├── src/
│   │   │   ├── server.ts        ← ws server with assertNoCleartext() PHI guard
│   │   │   ├── store.ts         ← In-memory sessions with application-level TTL
│   │   │   ├── rateLimit.ts     ← 10 attempts / 5 min → permanent session lock
│   │   │   └── types.ts         ← Wire protocol TypeScript types
│   │   └── tests/integration/
│   │       └── wire.test.ts     ← Integration tests: handshake, plaintext assertion, rate limit, expiry
│   │
│   └── test-clients/            ← CLI demo clients (synthetic data only)
│       └── src/
│           ├── patient.ts       ← Patient-side: generate PIN, encrypt, send
│           └── clinician.ts     ← Clinician-side: enter PIN, decrypt, print
│
├── THREAT_MODEL.md              ← Full adversary model and per-threat analysis
├── package.json                 ← npm workspaces root
└── tsconfig.json                ← Strict TypeScript base config
```

---

## Test Results

```
@passchart/crypto    10/10 ✅ (legacy handshake tests)
  ✓ produces a 32-byte key
  ✓ same PIN produces same key on both sides
  ✓ different PINs produce different keys
  ✓ zero-padded PIN is distinct from unpadded
  ✓ patient and clinician derive the same shared secret
  ✓ encrypts and decrypts a synthetic intake message end-to-end
  ✓ wrong PIN fails unwrapping (server cannot forge public keys)
  ✓ tampered ciphertext fails authentication
  ✓ WrappedKey contains no raw private key bytes
  ✓ EncryptedMessage contains no plaintext intake string

@passchart/crypto    10/10 ✅ (CPace PAKE tests)
  ✓ both sides derive the same session key
  ✓ key confirmation: patient confirms to clinician
  ✓ key confirmation: clinician confirms to patient
  ✓ full bidirectional key confirmation round-trip passes
  ✓ captured wire messages do not yield a verification oracle for PIN guesses
  ✓ wrong PIN → key confirmation fails
  ✓ tampered point from relay is rejected during key derivation
  ✓ same PIN + different sessionId → different session keys
  ✓ confirmation from session A does not verify against session B key
  ✓ each session generates a fresh session key (no determinism across sessions)

@passchart/relay     6/6 ✅
  ✓ device A inits session and receives sessionInited ACK
  ✓ device B joins and receives device A wrapped key
  ✓ relay forwards ciphertext from A to B
  ✓ store contains no forbidden plaintext after a full session
  ✓ 11th joinSession attempt is rate-limited/locked
  ✓ expired session is blocked (application-level TTL check)
```

---

## Security Properties

| Property | Implementation |
|---|---|
| Relay cannot MITM key exchange | PIN baked into DH generator via `hash_to_curve(PBKDF2(pin) ‖ sessionId)` — relay cannot compute valid points without the PIN |
| **Offline brute-force infeasible** | **CPace: ephemeral scalar (never transmitted) required to compute K; wire messages alone provide no verification oracle** |
| Relay stores only ciphertext | `assertNoCleartext()` in every relay handler; wire-level test asserts this |
| Online brute-force resistance | Rate limit: 10 attempts / 5 min per session → permanent session lock |
| Rate-limit reset scope | Counter resets only on full pairing completion, not on join — prevents reset-and-retry loops |
| Cross-session replay blocked | sessionId bound into generator derivation via HKDF |
| Key confirmation | `HMAC-SHA256(session_key, role_label)` — both sides prove they derived the same key before sending data |
| TTL enforcement | Application-level check on every store read — does not rely on DynamoDB TTL background sweeper (AWS docs: up to 48hr lag) |
| Authenticated encryption | `nacl.box` (XSalsa20-Poly1305) — decryption fails if ciphertext is tampered |

---

## Running Locally

### Prerequisites

- Node.js ≥ 18
- npm ≥ 8

### Setup

```bash
git clone https://github.com/Laeeq14/cpace-relay.git
cd cpace-relay
npm install
npm run build --workspace=packages/crypto
```

### Run Tests

```bash
# Crypto unit tests (20 tests)
npm test --workspace=packages/crypto

# Relay integration tests (6 tests)
npm test --workspace=packages/relay -- --forceExit
```

### Manual End-to-End Demo (synthetic data only)

Open three terminals from the project root:

**Terminal 1 — relay server:**
```bash
npm run dev --workspace=packages/relay
```

**Terminal 2 — device A (patient side):**
```bash
npm run patient --workspace=packages/test-clients
# Prints a 6-digit pairing code
```

**Terminal 3 — device B (clinician side):**
```bash
npm run clinician --workspace=packages/test-clients
# Enter the 6-digit code from Terminal 2
# Prints the decrypted synthetic intake data
```

The relay terminal shows only base64-encoded ciphertext — no plaintext transits the server.

---

## Design Decisions

### Why CPace over `secretbox(pubKey, PBKDF2(pin))`?

The original scheme encrypted each party's DH public key with a PIN-derived symmetric key before sending it to the relay. This prevents the relay from forging keys (it doesn't know the PIN), but creates a verifiable decryption oracle: an eavesdropper who captures the wire ciphertext can brute-force all 1,000,000 PINs offline by trying `secretbox.open(captured, PBKDF2(guess))` and checking whether the MAC passes. PBKDF2 at 600k iterations makes each trial slow (~seconds on commodity hardware), but the oracle itself cannot be rate-limited or prevented.

CPace eliminates the oracle by mixing the PIN into the DH *generator* via `hash_to_curve`, not into a symmetric cipher wrapped around the key. The wire messages are ristretto255 points; verifying a PIN guess requires computing `K = scalar * peer_point`, which requires the ephemeral scalar — never transmitted. Without it, a captured transcript reveals nothing checkable.

### Why CPace over SPAKE2 or OPAQUE?

SPAKE2 also eliminates the offline oracle but requires more complex group arithmetic and has more implementation surface area. OPAQUE is designed for client-server authentication where the server stores a verifier — not applicable here (symmetric setup, no server-stored verifier). CPace is purpose-built for the symmetric, peer-to-peer case and is simpler to implement correctly.

### Why `@noble/curves` for hash-to-curve instead of hand-rolling it?

Hash-to-curve (mapping arbitrary bytes to a valid curve point) is the part of PAKE implementations most prone to subtle bugs — off-curve points, cofactor issues, timing leaks in the map function. `@noble/curves` implements RFC 9380 (hash-to-curve) with ristretto255, is audited by multiple security researchers, and has no WASM or native dependencies.

### Why PBKDF2 over HKDF for PIN derivation?

A 6-digit PIN has only 1,000,000 possibilities. PBKDF2 with 600k iterations makes offline trials expensive even before CPace's oracle removal. HKDF is intentionally fast and is **not** appropriate for low-entropy inputs like PINs.

### Why application-level TTL instead of DynamoDB TTL?

AWS [explicitly documents](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html) that DynamoDB TTL is a background sweeper that can take **up to 48 hours** to physically delete an expired item. Relying on it to enforce a 15-minute security window is a false guarantee. Every store read checks `Date.now() > createdAt + TTL_MS` and actively rejects expired sessions regardless of whether the record is still on disk.

### Why reset the rate-limit counter only on `registerKey`, not `joinSession`?

Resetting the counter on every successful `joinSession` would allow an attacker to make 10 attempts, succeed (because the code is valid), reset the counter, and repeat indefinitely. The counter only resets when the **full pairing completes** — both keys exchanged via `registerKey`. Brute-force attempts always accumulate.

---

See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for the full adversary model and per-threat analysis.

---

## Note on Synthetic Data

All test fixtures use the string `[SYNTHETIC TEST DATA — NOT REAL PHI]`. No real patient data has ever been fed into this system. See [`/docs/productization-notes.md`](./docs/productization-notes.md) for what a compliant deployment path would require.
