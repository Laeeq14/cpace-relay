/**
 * keyExchange.ts
 * PIN-authenticated X25519 Diffie-Hellman key exchange using tweetnacl.
 *
 * Protocol:
 *  1. Both sides generate ephemeral keypairs (nacl.box.keyPair).
 *  2. Both sides derive the same 256-bit symmetric key from the shared PIN
 *     (via pinKdf.ts / PBKDF2).
 *  3. Each side wraps their ephemeral PUBLIC key with nacl.secretbox
 *     (authenticated encryption using the PIN-derived key) before sending
 *     it to the relay.
 *  4. Each side unwraps the other party's public key using the same key.
 *  5. Both sides compute the shared secret via nacl.box.before().
 *  6. All subsequent messages use nacl.box (X25519-XSalsa20-Poly1305).
 *
 * Security guarantee: The relay stores only ciphertext — it cannot forge or
 * substitute public keys because it does not know the PIN. Even if an
 * attacker brute-forces the PIN offline and recovers the public keys,
 * they still cannot derive the shared secret (they need the private keys).
 */

import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
const { encodeBase64, decodeBase64 } = naclUtil;

// ── Types ──────────────────────────────────────────────────────────────────

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Wire format: base64-encoded nonce + ciphertext, joined by ".". */
export interface WrappedKey {
  nonce: string;   // base64
  cipher: string;  // base64
}

export interface EncryptedMessage {
  nonce: string;   // base64
  cipher: string;  // base64
}

// ── Key Generation ─────────────────────────────────────────────────────────

/**
 * Generate an ephemeral X25519 keypair.
 * Call once per pairing session — never reuse across sessions.
 */
export function generateKeyPair(): KeyPair {
  return nacl.box.keyPair();
}

// ── PIN-authenticated Public Key Wrapping ──────────────────────────────────

/**
 * Wrap an ephemeral public key with nacl.secretbox using the PIN-derived key.
 * The output is safe to send to the untrusted relay.
 *
 * @param publicKey - The 32-byte X25519 public key to wrap
 * @param pinKey    - 32-byte key from derivePinKey(pin)
 */
export function wrapPublicKey(publicKey: Uint8Array, pinKey: Uint8Array): WrappedKey {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const cipher = nacl.secretbox(publicKey, nonce, pinKey);

  if (cipher === null) {
    throw new Error("wrapPublicKey: nacl.secretbox encryption failed");
  }

  return {
    nonce: encodeBase64(nonce),
    cipher: encodeBase64(cipher),
  };
}

/**
 * Unwrap a public key received from the relay.
 * Throws if the PIN was wrong or the ciphertext was tampered with.
 *
 * @param wrapped - The WrappedKey received from the relay
 * @param pinKey  - 32-byte key from derivePinKey(pin)
 */
export function unwrapPublicKey(wrapped: WrappedKey, pinKey: Uint8Array): Uint8Array {
  const nonce = decodeBase64(wrapped.nonce);
  const cipher = decodeBase64(wrapped.cipher);
  const publicKey = nacl.secretbox.open(cipher, nonce, pinKey);

  if (publicKey === null) {
    throw new Error(
      "unwrapPublicKey: decryption failed — wrong PIN or tampered ciphertext"
    );
  }

  return publicKey;
}

// ── Shared Secret & Message Encryption ────────────────────────────────────

/**
 * Derive the shared secret from the other party's public key and our private key.
 * Both sides compute the same 32-byte shared secret (X25519).
 * Store in memory only — never serialize or log this value.
 *
 * @param theirPublicKey  - Unwrapped public key from the other party
 * @param ourSecretKey    - Our own private key
 */
export function deriveSharedSecret(
  theirPublicKey: Uint8Array,
  ourSecretKey: Uint8Array
): Uint8Array {
  return nacl.box.before(theirPublicKey, ourSecretKey);
}

/**
 * Encrypt a message using the shared secret (nacl.box.after = XSalsa20-Poly1305).
 * Safe to send through the relay — authenticated encryption prevents tampering.
 *
 * @param plaintext    - UTF-8 string (e.g. synthetic intake data)
 * @param sharedSecret - 32-byte value from deriveSharedSecret()
 */
export function encryptMessage(
  plaintext: string,
  sharedSecret: Uint8Array
): EncryptedMessage {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const encoded = new TextEncoder().encode(plaintext);
  const cipher = nacl.box.after(encoded, nonce, sharedSecret);

  if (cipher === null) {
    throw new Error("encryptMessage: nacl.box.after encryption failed");
  }

  return {
    nonce: encodeBase64(nonce),
    cipher: encodeBase64(cipher),
  };
}

/**
 * Decrypt a message using the shared secret.
 * Throws if authentication fails (tampered ciphertext or wrong key).
 *
 * @param msg          - EncryptedMessage received from the relay
 * @param sharedSecret - 32-byte value from deriveSharedSecret()
 */
export function decryptMessage(
  msg: EncryptedMessage,
  sharedSecret: Uint8Array
): string {
  const nonce = decodeBase64(msg.nonce);
  const cipher = decodeBase64(msg.cipher);
  const plaintext = nacl.box.open.after(cipher, nonce, sharedSecret);

  if (plaintext === null) {
    throw new Error(
      "decryptMessage: authentication failed — tampered ciphertext or wrong shared secret"
    );
  }

  return new TextDecoder().decode(plaintext);
}
