/**
 * keyExchange.test.ts
 *
 * Tests the full PIN-authenticated DH handshake:
 *  1. Both sides generate keypairs independently
 *  2. Both sides derive a key from the same PIN
 *  3. Each wraps their public key with nacl.secretbox(pinKey)
 *  4. Each unwraps the other's public key
 *  5. Both derive the same shared secret
 *  6. Encrypt on one side, decrypt on the other — round-trip succeeds
 *
 * Wire-level assertion: no raw private key material or plaintext PHI
 * appears in the WrappedKey or EncryptedMessage objects.
 */

import {
  generateKeyPair,
  wrapPublicKey,
  unwrapPublicKey,
  deriveSharedSecret,
  encryptMessage,
  decryptMessage,
} from "../src/keyExchange.js";
import { derivePinKey } from "../src/pinKdf.js";
import naclUtil from "tweetnacl-util";
const { encodeBase64 } = naclUtil;

const SYNTHETIC_INTAKE =
  "Patient reports: right knee pain for 3 days, no swelling, worse when climbing stairs. No trauma. [SYNTHETIC TEST DATA — NOT REAL PHI]";

describe("Full PIN-authenticated handshake round-trip", () => {
  it("patient and clinician derive the same shared secret from the same PIN", async () => {
    const pin = "847201";

    const patientKP = generateKeyPair();
    const clinicianKP = generateKeyPair();
    const pinKey = await derivePinKey(pin);

    // Each side wraps their public key
    const wrappedPatient = wrapPublicKey(patientKP.publicKey, pinKey);
    const wrappedClinician = wrapPublicKey(clinicianKP.publicKey, pinKey);

    // Each side unwraps the other's public key
    const patientPublicKeyReceived = unwrapPublicKey(wrappedPatient, pinKey);
    const clinicianPublicKeyReceived = unwrapPublicKey(wrappedClinician, pinKey);

    // Both sides compute shared secret
    const sharedByPatient = deriveSharedSecret(clinicianPublicKeyReceived, patientKP.secretKey);
    const sharedByClinician = deriveSharedSecret(patientPublicKeyReceived, clinicianKP.secretKey);

    expect(sharedByPatient).toEqual(sharedByClinician);
  });

  it("encrypts and decrypts a synthetic intake message end-to-end", async () => {
    const pin = "319048";

    const patientKP = generateKeyPair();
    const clinicianKP = generateKeyPair();
    const pinKey = await derivePinKey(pin);

    const wrappedPatient = wrapPublicKey(patientKP.publicKey, pinKey);
    const wrappedClinician = wrapPublicKey(clinicianKP.publicKey, pinKey);

    const patientPublicKey = unwrapPublicKey(wrappedPatient, pinKey);
    const clinicianPublicKey = unwrapPublicKey(wrappedClinician, pinKey);

    const sharedByPatient = deriveSharedSecret(clinicianPublicKey, patientKP.secretKey);
    const sharedByClinician = deriveSharedSecret(patientPublicKey, clinicianKP.secretKey);

    // Patient encrypts and sends
    const msg = encryptMessage(SYNTHETIC_INTAKE, sharedByPatient);

    // Clinician decrypts
    const decrypted = decryptMessage(msg, sharedByClinician);

    expect(decrypted).toBe(SYNTHETIC_INTAKE);
  });

  it("wrong PIN fails unwrapping with an error — server cannot forge public keys", async () => {
    const correctPin = "123456";
    const wrongPin = "654321";

    const kp = generateKeyPair();
    const correctKey = await derivePinKey(correctPin);
    const wrongKey = await derivePinKey(wrongPin);

    const wrapped = wrapPublicKey(kp.publicKey, correctKey);

    expect(() => unwrapPublicKey(wrapped, wrongKey)).toThrow(
      "decryption failed — wrong PIN or tampered ciphertext"
    );
  });

  it("tampered ciphertext fails authentication", async () => {
    const pin = "555555";
    const pinKey = await derivePinKey(pin);
    const kp = generateKeyPair();
    const wrapped = wrapPublicKey(kp.publicKey, pinKey);

    // Simulate relay tampering: flip a byte in the cipher
    const cipherBytes = Buffer.from(wrapped.cipher, "base64");
    cipherBytes[0] = cipherBytes[0]! ^ 0xff;
    const tampered = { ...wrapped, cipher: cipherBytes.toString("base64") };

    expect(() => unwrapPublicKey(tampered, pinKey)).toThrow(
      "decryption failed — wrong PIN or tampered ciphertext"
    );
  });
});

// ── Wire-level assertions ───────────────────────────────────────────────────
describe("Wire-level: no plaintext PHI or raw private key material on the wire", () => {
  it("WrappedKey contains no raw private key bytes", async () => {
    const pin = "000001";
    const kp = generateKeyPair();
    const pinKey = await derivePinKey(pin);
    const wrapped = wrapPublicKey(kp.publicKey, pinKey);

    const privateKeyB64 = encodeBase64(kp.secretKey);
    const wirePayload = JSON.stringify(wrapped);

    expect(wirePayload).not.toContain(privateKeyB64);
  });

  it("EncryptedMessage contains no plaintext intake string", async () => {
    const pin = "000002";

    const patientKP = generateKeyPair();
    const clinicianKP = generateKeyPair();
    const pinKey = await derivePinKey(pin);

    const wrappedClinician = wrapPublicKey(clinicianKP.publicKey, pinKey);
    const clinicianPublicKey = unwrapPublicKey(wrappedClinician, pinKey);
    const shared = deriveSharedSecret(clinicianPublicKey, patientKP.secretKey);

    const msg = encryptMessage(SYNTHETIC_INTAKE, shared);
    const wirePayload = JSON.stringify(msg);

    // The plaintext must not appear anywhere in the wire payload
    expect(wirePayload).not.toContain("right knee pain");
    expect(wirePayload).not.toContain("Patient reports");
    expect(wirePayload).not.toContain("SYNTHETIC TEST DATA");
  });
});
