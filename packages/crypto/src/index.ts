/**
 * index.ts
 * Public API of the @passchart/crypto package.
 */

export { generatePairingCode } from "./pin.js";
export { derivePinKey } from "./pinKdf.js";
export {
  generateKeyPair,
  wrapPublicKey,
  unwrapPublicKey,
  deriveSharedSecret,
  encryptMessage,
  decryptMessage,
} from "./keyExchange.js";

export type { KeyPair, WrappedKey, EncryptedMessage } from "./keyExchange.js";
