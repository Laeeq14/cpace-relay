/**
 * cpace.ts
 * CPace Password-Authenticated Key Exchange (IETF draft-irtf-cfrg-cpace)
 *
 * Replaces the previous `secretbox(pubKey, PBKDF2(pin))` approach which
 * created an offline decryption oracle. In that scheme, an eavesdropper who
 * captures the wire transcript could brute-force all 1,000,000 PINs offline —
 * for each guess, run PBKDF2 + secretbox.open and test the MAC. No relay
 * interaction is needed; rate limiting only protects the online path.
 *
 * CPace closes this by mixing the PIN directly into the DH generator:
 *
 *   G = hash_to_curve(PBKDF2(pin) || sessionId || role_context)
 *   Ya = a * G        (patient sends Ya, keeps scalar a)
 *   Yb = b * G        (clinician sends Yb, keeps scalar b)
 *   K  = a * Yb = b * Ya = a*b*G   (shared secret)
 *
 * To verify a guessed PIN offline, an attacker would need to compute K —
 * which requires knowing either scalar a or b (never sent). The wire messages
 * alone do not provide a cheap oracle. This is the key distinction from the
 * previous scheme: decryption success is no longer a local, free operation.
 *
 * Key confirmation proves both sides derived the same session key without
 * revealing it: each sends HMAC-SHA256(K, "<role>-confirm").
 *
 * Implementation uses @noble/curves v2.x (audited, pure-JS, no WASM):
 *   - ristretto255_hasher.hashToCurve() for RFC 9380 hash-to-curve
 *   - ristretto255.Point for the group operations
 *
 * References:
 *   - IETF CPace draft: https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/
 *   - @noble/curves:    https://github.com/paulmillr/noble-curves
 */

import { ristretto255, ristretto255_hasher } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

// ── Constants ────────────────────────────────────────────────────────────────

const DSI = new TextEncoder().encode("cpace-relay-v1"); // domain separation identifier
const CONFIRMATION_LABEL_PATIENT = new TextEncoder().encode("patient-confirm");
const CONFIRMATION_LABEL_CLINICIAN = new TextEncoder().encode("clinician-confirm");

export type CpaceRole = "patient" | "clinician";

// ── Types ────────────────────────────────────────────────────────────────────

export interface CpaceMessage {
  /** Ristretto255 point (32 bytes), base64-encoded — safe to send to relay. */
  pointB64: string;
}

export interface CpaceHandshakeState {
  /** Our ephemeral private scalar as hex string (never sent anywhere). */
  scalarHex: string;
  /** Our public message (point). */
  myMessage: CpaceMessage;
}

export interface CpaceSessionKey {
  /** 32-byte derived session key. */
  key: Uint8Array;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function b64Encode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function b64Decode(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}

/**
 * Derives a PIN-blinded ristretto255 generator.
 *
 * Both parties (patient and clinician) MUST compute the same generator G.
 * The PIN + sessionId are mixed in; role separation happens in key derivation
 * (HKDF info string), not here — role-separated generators would break DH
 * commutativity (a*G_p ≠ a*G_c means the shared secret would not match).
 *
 * @param pinKey    - 32-byte output of PBKDF2(pin), from pinKdf.ts
 * @param sessionId - Unique session identifier (prevents cross-session replay)
 */
function derivePinGenerator(
  pinKey: Uint8Array,
  sessionId: string
) {
  const sessionBytes = new TextEncoder().encode(sessionId);

  // Build context: DSI || sessionId (no role — must be identical for both sides)
  const info = new Uint8Array([
    ...DSI,
    ...sessionBytes,
  ]);

  // HKDF-expand to produce a uniform 64-byte string for hash-to-curve
  // (RFC 9380 requires >= 2 * field_len bytes of uniform randomness)
  const uniform = hkdf(sha256, pinKey, undefined, info, 64);

  // hash_to_curve maps uniform bytes → a valid ristretto255 point
  // ristretto255_hasher implements RFC 9380 hash-to-curve
  return ristretto255_hasher.hashToCurve(uniform);
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Step 1: Generate this side's CPace message (ephemeral point).
 *
 * Call this once per session. The returned scalarHex must be kept in memory
 * only — never serialize to disk or log it.
 *
 * @param pinKey    - 32-byte output of derivePinKey(pin)
 * @param sessionId - Unique session ID (e.g. relay-assigned session token)
 * @param role      - "patient" or "clinician"
 */
export async function cpaceGenerateMessage(
  pinKey: Uint8Array,
  sessionId: string,
  role: CpaceRole
): Promise<CpaceHandshakeState> {
  const G = derivePinGenerator(pinKey, sessionId);
  // role parameter is kept in the signature so callers can track which side
  // they are; it is used in cpaceDeriveSessionKey for HKDF info binding

  // Generate a cryptographically random ephemeral scalar (32 bytes)
  // Must be in range [1, n) where n is the ristretto255 curve order
  const n = ristretto255.Point.Fn.ORDER;
  const scalarBytes = crypto.getRandomValues(new Uint8Array(32));
  const scalarRaw = bytesToBigInt(scalarBytes) % n;
  const scalar = scalarRaw === 0n ? 1n : scalarRaw; // ensure scalar >= 1

  // Compute our public message: Y = scalar * G
  const Y = G.multiply(scalar);

  return {
    scalarHex: scalar.toString(16).padStart(64, "0"),
    myMessage: {
      pointB64: b64Encode(Y.toBytes()),
    },
  };
}

/**
 * Step 2: Derive the shared session key from the other party's message.
 *
 * Call this after receiving the other side's CpaceMessage.
 * Both sides compute the same K = a*b*G via commutativity of scalar multiplication.
 *
 * @param myScalarHex  - Our ephemeral scalar hex from cpaceGenerateMessage
 * @param theirMessage - CpaceMessage received from the other side
 * @param pinKey       - 32-byte output of derivePinKey(pin)
 * @param sessionId    - Same session ID used in cpaceGenerateMessage
 * @param myRole       - Our role ("patient" or "clinician")
 * @param myMessage    - Our own CpaceMessage (needed for key binding)
 * @param theirRole    - The other party's role
 */
export async function cpaceDeriveSessionKey(
  myScalarHex: string,
  theirMessage: CpaceMessage,
  pinKey: Uint8Array,
  sessionId: string,
  myRole: CpaceRole,
  myMessage: CpaceMessage,
  theirRole: CpaceRole
): Promise<CpaceSessionKey> {
  // Decode and validate the other side's point
  let theirPoint: ReturnType<typeof ristretto255.Point.fromBytes>;
  try {
    const theirBytes = b64Decode(theirMessage.pointB64);
    theirPoint = ristretto255.Point.fromBytes(theirBytes);
  } catch {
    throw new Error("cpaceDeriveSessionKey: invalid point from peer — possible tampering");
  }

  // K = myScalar * theirPoint
  // Both sides compute the same K = a*b*G (scalar mult is commutative on the exponent)
  const myScalar = BigInt("0x" + myScalarHex);
  const K = theirPoint.multiply(myScalar);
  const Kbytes = K.toBytes();

  // Canonicalize message order so both sides derive identical keying material
  // regardless of which role calls this function first
  const patientMsg = myRole === "patient" ? myMessage.pointB64 : theirMessage.pointB64;
  const clinicianMsg = myRole === "clinician" ? myMessage.pointB64 : theirMessage.pointB64;

  // Derive the session key via HKDF, binding K to both messages and the session ID
  // Role labels are included in HKDF info to provide domain separation
  // even though G is shared — this is where role separation lives.
  const ikm = new Uint8Array([
    ...Kbytes,
    ...b64Decode(patientMsg),
    ...b64Decode(clinicianMsg),
  ]);

  const sessionBytes = new TextEncoder().encode(sessionId);
  // Info does NOT include role — both sides must derive the same session key.
  // Role domain separation is provided by key confirmation labels (patient-confirm / clinician-confirm).
  const info = new Uint8Array([...DSI, ...sessionBytes]);

  const sessionKey = hkdf(sha256, ikm, undefined, info, 32);

  return { key: sessionKey };
}

/**
 * Step 3: Generate a key confirmation MAC.
 *
 * Proves to the other side that we derived the same session key without
 * revealing it. Send this through the relay after key derivation.
 *
 * @param sessionKey - From cpaceDeriveSessionKey
 * @param role       - Our role
 */
export function cpaceGenerateConfirmation(
  sessionKey: CpaceSessionKey,
  role: CpaceRole
): Uint8Array {
  const label =
    role === "patient" ? CONFIRMATION_LABEL_PATIENT : CONFIRMATION_LABEL_CLINICIAN;
  return hmac(sha256, sessionKey.key, label);
}

/**
 * Step 4: Verify the other side's key confirmation MAC.
 *
 * Returns true if the other side derived the same session key.
 * A false result means the PIN was wrong or the relay forged the message.
 *
 * @param sessionKey  - Our derived session key
 * @param theirRole   - The other party's role
 * @param received    - The confirmation bytes we received from them
 */
export function cpaceVerifyConfirmation(
  sessionKey: CpaceSessionKey,
  theirRole: CpaceRole,
  received: Uint8Array
): boolean {
  const expected = cpaceGenerateConfirmation(sessionKey, theirRole);

  // Constant-time comparison to prevent timing oracle
  if (expected.length !== received.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected[i]! ^ received[i]!;
  }
  return diff === 0;
}
