# cpace-relay

> **Secure, end-to-end encrypted patient intake for independent clinics.**
>
> A patient completes a symptom intake on their phone. The data is encrypted on-device, relayed as ciphertext, and decrypted only inside the clinician's browser — the server never sees plaintext PHI.

---

## Project Status

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | Core encryption & pairing handshake | ✅ Complete |
| Phase 2 | Patient intake UI (React Native / Expo) | 🔲 Planned |
| Phase 3 | Backend (AWS Lambda + DynamoDB) | 🔲 Planned |
| Phase 4 | Clinician portal (Next.js) | 🔲 Planned |
| Phase 5 | Security review & synthetic-data validation | 🔲 Planned |
| Phase 6 | Legal structuring (LLC, BAA, cloud BAAs) | 🔲 Planned |
| Phase 7 | Pilot with real clinics (real PHI, under BAA) | 🔲 Planned |

> **Core rule**: No real patient data touches this system until Phase 6 (BAA + LLC in place). All current development uses synthetic test data only.

---

## Phase 1 — What's Built

### Architecture

```
Patient Device                  Relay (blind broker)              Clinician Portal
      │                               │                                 │
      │── initSession ───────────────>│                                 │
      │   nacl.secretbox(pubKey,      │                                 │
      │   PBKDF2(PIN))                │                                 │
      │<── sessionInited ─────────────│                                 │
      │                               │<── joinSession(PIN) ────────────│
      │                               │─── patientKey ─────────────────>│
      │                               │    (wrapped pubKey, still       │
      │                               │     ciphertext to relay)        │
      │                               │<── registerKey ─────────────────│
      │<── clinicianJoined ───────────│    (wrapped clinicianPubKey)    │
      │                               │                                 │
      │ [derive shared secret]        │                  [derive shared secret]
      │ [encrypt intake data]         │                                 │
      │── relay(ciphertext) ─────────>│── relayed ─────────────────────>│
      │                               │                  [decrypt & display]
```

### Cryptographic Protocol

The relay is an **untrusted broker** — it never sees plaintext keys or PHI. The key exchange is authenticated using the 6-digit pairing PIN, which closes the server-MITM hole that a plain Diffie-Hellman exchange would leave open.

1. **PIN generation** — Patient device generates a cryptographically random 6-digit PIN using `crypto.getRandomValues` with rejection sampling (no modulo bias).
2. **Key derivation** — Both sides independently run `PBKDF2(pin, salt, 600_000 iterations, SHA-256)` → 256-bit symmetric key. Neither side sends the PIN or derived key to the relay.
3. **PIN-authenticated key exchange** — Each side wraps their ephemeral X25519 public key in `nacl.secretbox(pinDerivedKey)` before sending it through the relay. The relay cannot forge or substitute public keys because it does not know the PIN.
4. **Shared secret** — Both sides call `nacl.box.before(theirPublicKey, myPrivateKey)` → identical 32-byte shared secret (X25519 Diffie-Hellman).
5. **Message encryption** — All intake data is encrypted with `nacl.box` (XSalsa20-Poly1305 authenticated encryption) using the shared secret. The relay relays only base64-encoded ciphertext.

### Libraries Used

| Library | Purpose |
|---|---|
| [`tweetnacl`](https://github.com/dchest/tweetnacl-js) | X25519 key exchange, XSalsa20-Poly1305 encryption — audited, no native deps |
| [`tweetnacl-util`](https://github.com/dchest/tweetnacl-util) | Base64 encode/decode for wire format |
| `crypto.subtle` (Web Crypto API) | PBKDF2 key derivation — built-in, no extra dependency |
| [`ws`](https://github.com/websockets/ws) | Local WebSocket relay server (will port to AWS Lambda + API Gateway) |

### Monorepo Structure

```
PassChart/
├── packages/
│   ├── crypto/                  ← Shared encryption logic
│   │   ├── src/
│   │   │   ├── pin.ts           ← 6-digit PIN generation (crypto.getRandomValues)
│   │   │   ├── pinKdf.ts        ← PBKDF2 key derivation (600k iterations)
│   │   │   ├── keyExchange.ts   ← PIN-authenticated X25519 DH + nacl.box encrypt/decrypt
│   │   │   └── index.ts         ← Package barrel export
│   │   └── tests/
│   │       ├── pinKdf.test.ts   ← KDF determinism + distinctness tests
│   │       └── keyExchange.test.ts ← Full round-trip + wire-level plaintext assertions
│   │
│   ├── relay/                   ← Local WebSocket relay server
│   │   ├── src/
│   │   │   ├── server.ts        ← ws server with plaintext PHI guard
│   │   │   ├── store.ts         ← In-memory sessions with application-level TTL
│   │   │   ├── rateLimit.ts     ← 10 attempts / 5 min → session lock
│   │   │   └── types.ts         ← Wire protocol TypeScript types
│   │   └── tests/integration/
│   │       └── wire.test.ts     ← Integration tests: handshake, wire assertion, rate limit, expiry
│   │
│   └── test-clients/            ← CLI demo clients (synthetic data only)
│       └── src/
│           ├── patient.ts       ← Patient-side: generate PIN, encrypt, send
│           └── clinician.ts     ← Clinician-side: enter PIN, decrypt, print
│
├── package.json                 ← npm workspaces root
└── tsconfig.json                ← Strict TypeScript base config
```

### Test Results

```
@passchart/crypto    10/10 ✅
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

@passchart/relay     6/6 ✅
  ✓ patient inits session and receives sessionInited ACK
  ✓ clinician joins and receives patient wrapped key
  ✓ relay forwards ciphertext from patient to clinician
  ✓ store contains no forbidden plaintext after a full session
  ✓ 11th joinSession attempt is rate-limited/locked
  ✓ expired session is blocked (application-level TTL check)
```

### Security Properties

| Property | Implementation |
|---|---|
| Server cannot MITM key exchange | Public keys wrapped in `nacl.secretbox(PBKDF2(pin))` — relay never knows the PIN |
| Relay stores only ciphertext | `assertNoCleartext()` in every relay handler; wire-level test asserts this |
| Weak PIN brute-force resistance | PBKDF2 at 600k iterations (2023 NIST guidance for SHA-256) |
| Online brute-force resistance | Rate limit: 10 attempts / 5 min per session → permanent session lock |
| TTL enforcement | Application-level check on every store read — does not rely on DynamoDB TTL background sweeper (which can lag up to 48hrs per AWS docs) |
| Authenticated encryption | `nacl.box` (XSalsa20-Poly1305) — decryption fails if ciphertext is tampered |

---

## Running Locally

### Prerequisites

- Node.js ≥ 18
- npm ≥ 8

### Setup

```bash
git clone https://github.com/Laeeq14/PassChart.git
cd PassChart
npm install
npm run build --workspace=packages/crypto
```

### Run Tests

```bash
# Crypto unit tests
npm test --workspace=packages/crypto

# Relay integration tests
npm test --workspace=packages/relay -- --forceExit
```

### Manual End-to-End Demo (synthetic data only)

Open three terminals from the project root:

**Terminal 1 — relay server:**
```bash
npm run dev --workspace=packages/relay
```

**Terminal 2 — patient:**
```bash
npm run patient --workspace=packages/test-clients
# Prints a 6-digit pairing code
```

**Terminal 3 — clinician:**
```bash
npm run clinician --workspace=packages/test-clients
# Enter the 6-digit code from Terminal 2
# Prints the decrypted synthetic intake data
```

The relay terminal will show only base64-encoded ciphertext — no plaintext ever transits the server.

---

## Design Decisions

### Why PBKDF2 over HKDF for PIN derivation?

A 6-digit PIN has only 1,000,000 possibilities. PBKDF2 with 600k iterations makes offline brute-force expensive even if an attacker dumps the relay's stored ciphertext. HKDF is intentionally fast and is **not** appropriate for low-entropy inputs like PINs.

### Why not hand-roll SPAKE2/PAKE?

Rolling your own PAKE from curve math is where solo/small teams introduce real vulnerabilities. `tweetnacl` + `crypto.subtle.PBKDF2` achieves the same security goal (PIN-authenticated key exchange) using audited primitives without custom curve arithmetic.

### Why application-level TTL instead of DynamoDB TTL?

AWS [explicitly documents](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html) that DynamoDB TTL is a background sweeper that can take **up to 48 hours** to physically delete an expired item. Relying on it to enforce a 15-minute security window is a false guarantee. Every store read in PassChart checks `Date.now() > createdAt + TTL_MS` and actively rejects expired sessions regardless of whether the record is still on disk.

### Why reset the rate-limit counter only on `registerKey`, not `joinSession`?

Resetting the counter on every successful `joinSession` would allow an attacker to make 10 attempts, succeed (because the code is valid), reset the counter, and repeat indefinitely. The counter only resets when the **full pairing completes** — both keys exchanged via `registerKey`. Brute-force attempts always accumulate.

---

## Roadmap

- **Phase 2**: Patient intake UI (React Native / Expo) — chat flow, persistent 911 banner, screen capture prevention
- **Phase 3**: Backend (AWS Lambda + DynamoDB) — port relay handlers, ciphertext-only storage, TTL auto-expiry
- **Phase 4**: Clinician portal (Next.js) — SOAP note display, raw transcript, clipboard export
- **Phase 5**: Security review — appsec consult, brute-force load test, adversarial UX testing
- **Phase 6**: Legal — Minnesota LLC, BAA, cloud provider BAAs, clinical advisor
- **Phase 7**: Pilot — real PHI under signed BAAs, $79/mo from day one

---

## Important: No Real PHI Until Phase 6

This codebase currently uses **synthetic test data only**. The string `[SYNTHETIC TEST DATA — NOT REAL PHI]` appears in all test fixtures. Do not feed real patient symptom data into this system until:

- [ ] Minnesota LLC formed + EIN obtained
- [ ] BAA drafted and reviewed by a licensed healthcare attorney
- [ ] Cloud provider BAAs (AWS/Azure) executed
- [ ] Clinical advisor named and clinical logic reviewed

Processing real PHI before these items are complete makes you a de facto HIPAA Business Associate with no BAA — the exact liability exposure this architecture is designed to avoid.
