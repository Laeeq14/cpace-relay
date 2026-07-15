/**
 * pin.ts
 * Generates a cryptographically random 6-digit pairing PIN.
 * Uses crypto.getRandomValues — never Math.random().
 */

/**
 * Generates a cryptographically random 6-digit pairing code.
 * Returns a zero-padded string (e.g. "047291").
 * Range: 000000–999999 (1,000,000 possibilities).
 */
export function generatePairingCode(): string {
  // Generate random value in range [0, 999999]
  // We use rejection sampling to avoid modulo bias.
  const max = 1_000_000;
  const buf = new Uint32Array(1);

  let value: number;
  do {
    crypto.getRandomValues(buf);
    // buf[0] is in [0, 2^32 - 1]. We reject values that would introduce bias.
    value = buf[0]! % max;
  } while (buf[0]! >= Math.floor(0xffffffff / max) * max);

  return value.toString().padStart(6, "0");
}
