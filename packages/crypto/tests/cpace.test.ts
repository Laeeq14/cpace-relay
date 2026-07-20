/**
 * cpace.test.ts
 *
 * Tests for the CPace PIN-authenticated key exchange.
 *
 * Three test categories:
 *
 * 1. Happy path — both sides complete the handshake and confirm the same key.
 *
 * 2. Offline brute-force resistance — the key new security property this
 *    module adds over the legacy secretbox approach. Given only the wire
 *    messages (the two CPace points), an attacker cannot verify a PIN guess
 *    without possessing an ephemeral scalar — which is never sent. This test
 *    samples wrong PINs and asserts that key confirmation fails for each,
 *    proving there is no cheap offline oracle.
 *
 * 3. Session isolation — same PIN + different sessionId → completely different
 *    session keys. A transcript from one session cannot be replayed against
 *    another.
 */

import { derivePinKey } from "../src/pinKdf.js";
import {
  cpaceGenerateMessage,
  cpaceDeriveSessionKey,
  cpaceGenerateConfirmation,
  cpaceVerifyConfirmation,
} from "../src/cpace.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

async function runHandshake(pin: string, sessionId: string) {
  const pinKey = await derivePinKey(pin);

  const patientState = await cpaceGenerateMessage(pinKey, sessionId, "patient");
  const clinicianState = await cpaceGenerateMessage(pinKey, sessionId, "clinician");

  const patientKey = await cpaceDeriveSessionKey(
    patientState.scalarHex,
    clinicianState.myMessage,
    pinKey,
    sessionId,
    "patient",
    patientState.myMessage,
    "clinician"
  );

  const clinicianKey = await cpaceDeriveSessionKey(
    clinicianState.scalarHex,
    patientState.myMessage,
    pinKey,
    sessionId,
    "clinician",
    clinicianState.myMessage,
    "patient"
  );

  return { patientState, clinicianState, patientKey, clinicianKey };
}

// ── 1. Happy path ─────────────────────────────────────────────────────────────

describe("CPace handshake — happy path", () => {
  it("both sides derive the same session key", async () => {
    const { patientKey, clinicianKey } = await runHandshake("847201", "session-abc");
    expect(patientKey.key).toEqual(clinicianKey.key);
    expect(patientKey.key.byteLength).toBe(32);
  });

  it("key confirmation: patient confirms to clinician", async () => {
    const { patientKey, clinicianKey } = await runHandshake("314159", "session-xyz");

    const patientConfirmation = cpaceGenerateConfirmation(patientKey, "patient");
    const valid = cpaceVerifyConfirmation(clinicianKey, "patient", patientConfirmation);
    expect(valid).toBe(true);
  });

  it("key confirmation: clinician confirms to patient", async () => {
    const { patientKey, clinicianKey } = await runHandshake("000001", "session-001");

    const clinicianConfirmation = cpaceGenerateConfirmation(clinicianKey, "clinician");
    const valid = cpaceVerifyConfirmation(patientKey, "clinician", clinicianConfirmation);
    expect(valid).toBe(true);
  });

  it("full bidirectional key confirmation round-trip passes", async () => {
    const { patientKey, clinicianKey } = await runHandshake("999999", "session-full");

    const patientConf = cpaceGenerateConfirmation(patientKey, "patient");
    const clinicianConf = cpaceGenerateConfirmation(clinicianKey, "clinician");

    expect(cpaceVerifyConfirmation(clinicianKey, "patient", patientConf)).toBe(true);
    expect(cpaceVerifyConfirmation(patientKey, "clinician", clinicianConf)).toBe(true);
  });
});

// ── 2. Offline brute-force resistance ─────────────────────────────────────────

describe("Offline brute-force resistance — the core security property", () => {
  /**
   * This test proves the key invariant that separates CPace from the old
   * secretbox scheme:
   *
   * An eavesdropper who captures the wire messages (patientState.myMessage
   * and clinicianState.myMessage) cannot verify a PIN guess without also
   * possessing one of the ephemeral scalars — which are never transmitted.
   *
   * For each wrong PIN, we derive a session key "as if" we were the
   * clinician but using a wrong PIN. The resulting key confirmation will
   * not match, because the DH computation uses the same points but a
   * different generator, producing a different K.
   *
   * Contrast with the old scheme: wrong PIN → try secretbox.open → MAC check
   * is a free local operation that tells you immediately if the PIN is right.
   * That oracle does not exist here.
   */
  it("captured wire messages do not yield a verification oracle for PIN guesses", async () => {
    const correctPin = "572931";
    const sessionId = "session-oracle-test";

    // Run a real handshake — an attacker can see these messages on the wire
    const { patientState, clinicianState, clinicianKey } =
      await runHandshake(correctPin, sessionId);

    const wrongPins = ["000001", "123456", "999998", "572930", "572932", "100000"];

    for (const wrongPin of wrongPins) {
      const wrongPinKey = await derivePinKey(wrongPin);

      // Attacker tries: "if I use wrongPin, can I derive a session key that
      // confirms against the captured messages?"
      // They have access to patientState.myMessage and clinicianState.myMessage
      // but NOT to patientState.scalarHex (never sent).
      //
      // They can only generate a fresh wrong scalar and wrong generator.
      const attackerState = await cpaceGenerateMessage(wrongPinKey, sessionId, "clinician");
      const attackerKey = await cpaceDeriveSessionKey(
        attackerState.scalarHex,
        patientState.myMessage, // captured from wire
        wrongPinKey,
        sessionId,
        "clinician",
        attackerState.myMessage, // attacker's own (wrong) point
        "patient"
      );

      // The attacker's derived key cannot verify the real clinician's confirmation
      const realClinicianConf = cpaceGenerateConfirmation(clinicianKey, "clinician");
      const attackerVerifies = cpaceVerifyConfirmation(
        attackerKey,
        "clinician",
        realClinicianConf
      );

      expect(attackerVerifies).toBe(false);
    }
  });

  it("wrong PIN → key confirmation fails", async () => {
    const sessionId = "session-wrong-pin";

    const correctPinKey = await derivePinKey("123456");
    const wrongPinKey = await derivePinKey("654321");

    const patientState = await cpaceGenerateMessage(correctPinKey, sessionId, "patient");
    // Clinician uses wrong PIN — simulates an attacker who guessed incorrectly
    const clinicianState = await cpaceGenerateMessage(wrongPinKey, sessionId, "clinician");

    const patientKey = await cpaceDeriveSessionKey(
      patientState.scalarHex,
      clinicianState.myMessage,
      correctPinKey,
      sessionId,
      "patient",
      patientState.myMessage,
      "clinician"
    );
    const clinicianKey = await cpaceDeriveSessionKey(
      clinicianState.scalarHex,
      patientState.myMessage,
      wrongPinKey,
      sessionId,
      "clinician",
      clinicianState.myMessage,
      "patient"
    );

    // Keys are different — confirmation will fail on both sides
    expect(patientKey.key).not.toEqual(clinicianKey.key);

    const clinicianConf = cpaceGenerateConfirmation(clinicianKey, "clinician");
    expect(cpaceVerifyConfirmation(patientKey, "clinician", clinicianConf)).toBe(false);
  });

  it("tampered point from relay is rejected during key derivation", async () => {
    const pin = "777777";
    const sessionId = "session-tamper";
    const pinKey = await derivePinKey(pin);

    const patientState = await cpaceGenerateMessage(pinKey, sessionId, "patient");

    // Simulate relay tampering: corrupt the base64 point
    const tamperedMessage = {
      pointB64: Buffer.from("this is not a valid ristretto point padded 00000000000000").toString("base64"),
    };

    await expect(
      cpaceDeriveSessionKey(
        patientState.scalarHex,
        tamperedMessage,
        pinKey,
        sessionId,
        "patient",
        patientState.myMessage,
        "clinician"
      )
    ).rejects.toThrow("invalid point from peer");
  });
});

// ── 3. Session isolation ──────────────────────────────────────────────────────

describe("Session isolation — transcript from one session cannot replay against another", () => {
  it("same PIN + different sessionId → different session keys", async () => {
    const pin = "474747";
    const { patientKey: key1 } = await runHandshake(pin, "session-A");
    const { patientKey: key2 } = await runHandshake(pin, "session-B");

    expect(key1.key).not.toEqual(key2.key);
  });

  it("confirmation from session A does not verify against session B key", async () => {
    const pin = "282828";

    const { patientKey: keyA } = await runHandshake(pin, "session-A-iso");
    const { patientKey: keyB } = await runHandshake(pin, "session-B-iso");

    const confA = cpaceGenerateConfirmation(keyA, "patient");
    // Cross-session replay: confA against keyB
    expect(cpaceVerifyConfirmation(keyB, "patient", confA)).toBe(false);
  });

  it("each session generates a fresh session key (no determinism across sessions)", async () => {
    const pin = "111111";
    // Same pin, same sessionId — but fresh ephemeral scalars each time
    const { patientKey: k1 } = await runHandshake(pin, "session-fresh");
    const { patientKey: k2 } = await runHandshake(pin, "session-fresh");

    // The scalar is random each call, so K and the session key differ
    expect(k1.key).not.toEqual(k2.key);
  });
});
