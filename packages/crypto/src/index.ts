/**
 * index.ts
 * Public API of the @passchart/crypto package.
 */

export { generatePairingCode } from "./pin.js";
export { derivePinKey } from "./pinKdf.js";

// ── Legacy key exchange (Phase 1 baseline) ───────────────────────────────────
// Note: wrapPublicKey / unwrapPublicKey are superseded by the CPace module
// below, which eliminates the offline brute-force oracle. Kept for reference.
export {
  generateKeyPair,
  wrapPublicKey,
  unwrapPublicKey,
  deriveSharedSecret,
  encryptMessage,
  decryptMessage,
} from "./keyExchange.js";

export type { KeyPair, WrappedKey, EncryptedMessage } from "./keyExchange.js";

// ── CPace PAKE (hardened key exchange) ───────────────────────────────────────
// Use these instead of wrapPublicKey/unwrapPublicKey for new sessions.
export {
  cpaceGenerateMessage,
  cpaceDeriveSessionKey,
  cpaceGenerateConfirmation,
  cpaceVerifyConfirmation,
} from "./cpace.js";

export type { CpaceRole, CpaceMessage, CpaceHandshakeState, CpaceSessionKey } from "./cpace.js";
