/**
 * pinKdf.ts
 * Derives a 256-bit symmetric key from the 6-digit pairing PIN using PBKDF2.
 *
 * Security guarantee: Both the patient device and the clinician portal run
 * this exact function with the same PIN. The resulting key is used ONLY to
 * wrap (encrypt) each party's ephemeral DH public key before sending it to
 * the relay. The relay never sees the PIN or the derived key.
 *
 * Why PBKDF2 here and not a faster KDF (e.g. HKDF)?
 * A 6-digit PIN has only 1,000,000 possibilities. PBKDF2 with a high
 * iteration count makes offline brute-force expensive even if an attacker
 * dumps the relay's stored ciphertext. HKDF is fast — intentionally not
 * used for low-entropy inputs like PINs.
 */

/** Fixed salt — public, domain-separated, not secret. */
const SALT = new TextEncoder().encode("passchart-v1-pin-kdf");

/** PBKDF2 iterations. NIST recommends ≥ 600,000 for SHA-256 (2023). */
const ITERATIONS = 600_000;

/**
 * Derives a 256-bit Uint8Array key from a 6-digit PIN string.
 * Both sides must call this with the same PIN to get the same key.
 *
 * @param pin - The 6-digit pairing code as a string (e.g. "047291")
 * @returns A 32-byte Uint8Array suitable for use with nacl.secretbox
 */
export async function derivePinKey(pin: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(pin),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: SALT,
      iterations: ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}
