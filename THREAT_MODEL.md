# Threat Model — CPace-Relay / PassChart Phase 1

## Overview

This document covers the security properties and adversary model for the
Phase 1 cryptographic pairing handshake. Scope is limited to the relay and
in-transit data; device-level and application-layer concerns are out of scope
for this phase.

---

## Assets

| Asset | Description | Sensitivity |
|---|---|---|
| Session key | 32-byte key derived by both sides after handshake | Critical — compromise means message decryption |
| PHI in transit | Patient intake data encrypted with session key | Critical — HIPAA regulated |
| Pairing PIN | 6-digit code shared out-of-band (e.g., read aloud) | Medium — low entropy, protected by PAKE |
| Ephemeral scalar | Private DH scalar, held in memory only, never serialized | Critical — leaking it reveals session key |
| Relay session store | In-memory map of sessionId → wrapped messages | Low — relay sees only ciphertext |

---

## Adversary Capabilities

| Capability | Description |
|---|---|
| **Passive eavesdropper** | Captures all WebSocket traffic between clients and relay |
| **Compromised relay** | Relay is fully controlled by attacker (can read/modify relay-stored data, inject messages) |
| **Offline attacker** | Has captured wire transcript; performs offline computation without relay interaction |
| **Online attacker** | Can attempt joinSession with arbitrary PINs via the relay |

---

## Threat Analysis

### T1 — Server MITM (relay substitutes public keys)

**Attack**: Relay intercepts `patientKey` message and replaces the ristretto255 point with its own. Clinician completes DH with the relay, not the patient.

**Mitigation**: CPace mixes the PIN directly into the DH generator `G = hash_to_curve(PBKDF2(pin) || sessionId || role)`. The relay does not know the PIN. It cannot compute a valid `G` and therefore cannot construct a point that will produce a matching session key and pass key confirmation.

**Status**: ✅ Addressed.

---

### T2 — Offline PIN brute-force from captured transcript

**Attack**: Attacker captures the two CPace messages (ristretto255 points `Ya`, `Yb`) from the wire. For each of the 1,000,000 possible PINs, the attacker tries to derive a session key and verify it via key confirmation.

**Previous exposure (legacy scheme)**: The old `secretbox(pubKey, PBKDF2(pin))` approach used the MAC from secretbox as a free verification oracle. An attacker could try `secretbox.open(captured_cipher, PBKDF2(guessed_pin))` and check if decryption succeeded. This is a local operation — PBKDF2 at 600k iterations makes each trial slow but doesn't make the oracle disappear.

**CPace mitigation**: The wire messages (`Ya`, `Yb`) are ristretto255 points. To check a guessed PIN `p'`, an attacker would compute `G' = hash_to_curve(PBKDF2(p') || sessionId)` and then need an ephemeral scalar to compute `K' = scalar * Ya`. The scalar is never transmitted — it exists only in memory on the originating device for the duration of the session. Without it, the attacker cannot compute K and cannot verify whether their PIN guess produced the right generator. There is no MAC to check against.

**Status**: ✅ Addressed (the core improvement over Phase 1).

---

### T3 — Online PIN brute-force

**Attack**: Attacker repeatedly calls `joinSession` with guessed PINs via the relay.

**Mitigation**: Rate limiting at the relay layer — 10 attempts per session within 5 minutes triggers permanent session lock. Rate-limit counter resets only on full pairing completion (`registerKey`), not on `joinSession` success, to prevent an attacker from resetting the counter by guessing correctly and retrying.

**Status**: ✅ Addressed.

---

### T4 — Cross-session replay

**Attack**: Attacker captures a transcript from a valid session (pin=X, sessionId=A) and attempts to replay the messages against a new session (pin=X, sessionId=B).

**Mitigation**: The CPace generator derivation binds to `sessionId` via HKDF. Same PIN + different sessionId → different generator → different K → different session key. The confirmation MAC from session A will not verify against session B's key.

**Status**: ✅ Addressed. Tested in `cpace.test.ts → Session isolation`.

---

### T5 — Session expiry enforcement

**Attack**: Attacker stores a valid session token and attempts to resume it after TTL expiry.

**Mitigation**: Application-level TTL check on every store read (`Date.now() > createdAt + TTL_MS`). Does not rely on DynamoDB's background sweeper, which AWS documents can lag up to 48 hours.

**Status**: ✅ Addressed in relay layer.

---

### T6 — PIN interception during out-of-band exchange

**Attack**: Attacker overhears the patient reading the 6-digit PIN to the clinician (e.g., shoulder-surfing, phone call recording).

**Mitigation**: **Partially mitigated.** CPace with PBKDF2 makes offline brute-force infeasible from the wire alone, but if the PIN itself is compromised out-of-band, all bets are off. The pairing window is time-limited (15-minute TTL) which limits the window for use. Future enhancement: higher-entropy PIN (8 digits) or QR-code pairing for higher-security contexts.

**Status**: ⚠️ Partially mitigated. Acceptable for the current threat model; flagged for future improvement.

---

## Out of Scope

| Threat | Reason |
|---|---|
| Device compromise (malware on patient/clinician device) | Application-layer concern; cryptography cannot protect against an attacker who reads process memory |
| Side-channel attacks on client hardware (timing, power analysis) | Below the threat model for a WebSocket application |
| Denial of service against the relay | Infrastructure concern, not cryptographic |
| Clinician identity authentication | Phase 4 concern (clinician portal with auth) |

---

## Security Properties Summary

| Property | Mechanism | Status |
|---|---|---|
| Relay cannot MITM key exchange | PIN baked into DH generator via hash-to-curve | ✅ |
| Offline brute-force infeasible | CPace: scalar (never sent) required to verify PIN guess | ✅ |
| Online brute-force limited | Rate limit: 10 attempts / 5 min → permanent lock | ✅ |
| Cross-session replay blocked | sessionId bound into generator derivation via HKDF | ✅ |
| Key confirmation | HMAC-SHA256(session_key, role_label) — proves shared key without revealing it | ✅ |
| Relay stores no plaintext | `assertNoCleartext()` guard in every relay handler; wire-level test asserts this | ✅ |
| Session expiry enforced | App-level TTL, not DynamoDB background sweeper | ✅ |
| Authenticated message encryption | `nacl.box` (XSalsa20-Poly1305) | ✅ |
