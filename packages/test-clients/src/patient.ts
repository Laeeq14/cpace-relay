/**
 * patient.ts
 * Simulates a patient device during Phase 1 testing.
 *
 * Flow:
 *  1. Generate ephemeral X25519 keypair
 *  2. Generate 6-digit pairing code
 *  3. Derive PIN key from pairing code (PBKDF2)
 *  4. Wrap public key with PIN key
 *  5. Send initSession to relay with wrapped public key
 *  6. Wait for clinician to join (clinicianJoined message)
 *  7. Unwrap clinician's public key
 *  8. Derive shared secret
 *  9. Encrypt synthetic intake data
 * 10. Send encrypted payload to relay
 * 11. Print confirmation and exit
 *
 * Run: npm run patient --workspace=packages/test-clients
 * Requires: relay server running on ws://localhost:8080
 */

import { WebSocket } from "ws";
import {
  generatePairingCode,
  derivePinKey,
  generateKeyPair,
  wrapPublicKey,
  unwrapPublicKey,
  deriveSharedSecret,
  encryptMessage,
} from "@passchart/crypto";

// ── Synthetic intake data — NOT real PHI ──────────────────────────────────
const SYNTHETIC_INTAKE = `
SYNTHETIC TEST DATA — NOT REAL PHI
Chief Complaint: Right knee pain for 3 days
HPI: Patient is a 35-year-old synthetic test subject reporting gradual onset
     right knee pain, rated 5/10. No swelling, no trauma. Worse with stairs.
     No prior injury to this joint.
Medications: None (synthetic)
Allergies: NKDA (synthetic)
`.trim();

const RELAY_URL = "ws://localhost:8080";

async function runPatientClient(): Promise<void> {
  console.log("\n[PatientClient] Starting PassChart patient simulation...");
  console.log("[PatientClient] Generating keypair and pairing code...");

  const keyPair = generateKeyPair();
  const pin = generatePairingCode();

  console.log(`\n╔════════════════════════════════╗`);
  console.log(`║  PAIRING CODE: ${pin}        ║`);
  console.log(`║  (Give this code to the        ║`);
  console.log(`║   clinician terminal)          ║`);
  console.log(`╚════════════════════════════════╝\n`);

  console.log("[PatientClient] Deriving PIN key (PBKDF2, 600k iterations)...");
  const pinKey = await derivePinKey(pin);

  const wrappedKey = wrapPublicKey(keyPair.publicKey, pinKey);
  console.log("[PatientClient] Public key wrapped with PIN key ✓");

  const ws = new WebSocket(RELAY_URL);

  await new Promise<void>((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });

  console.log("[PatientClient] Connected to relay ✓");

  // Init session
  ws.send(JSON.stringify({
    type: "initSession",
    sessionId: pin,
    wrappedPatientKey: wrappedKey,
  }));

  // Wait for session ACK
  const ack = await waitForMessage(ws);
  if (ack.type !== "sessionInited") {
    throw new Error(`Unexpected response: ${JSON.stringify(ack)}`);
  }
  console.log("[PatientClient] Session initialised on relay ✓");
  console.log("[PatientClient] Waiting for clinician to join...\n");

  // Wait for clinician to join and send their wrapped key
  const clinicianMsg = await waitForMessage(ws);
  if (clinicianMsg.type !== "clinicianJoined") {
    throw new Error(`Expected clinicianJoined, got: ${JSON.stringify(clinicianMsg)}`);
  }
  console.log("[PatientClient] Clinician joined ✓");

  // Unwrap clinician's public key using PIN key
  const clinicianPublicKey = unwrapPublicKey(clinicianMsg.wrappedClinicianKey, pinKey);
  console.log("[PatientClient] Clinician public key unwrapped and authenticated ✓");

  // Derive shared secret
  const sharedSecret = deriveSharedSecret(clinicianPublicKey, keyPair.secretKey);
  console.log("[PatientClient] Shared secret derived ✓");

  // Encrypt synthetic intake
  const encrypted = encryptMessage(SYNTHETIC_INTAKE, sharedSecret);
  console.log("[PatientClient] Intake data encrypted ✓");

  // Send via relay
  ws.send(JSON.stringify({
    type: "relay",
    sessionId: pin,
    payload: encrypted,
  }));

  console.log("[PatientClient] Encrypted payload sent to relay ✓");
  console.log("[PatientClient] The relay only saw ciphertext — no plaintext PHI transmitted ✓");
  console.log("\n[PatientClient] Done. Closing connection.");
  ws.close();
}

function waitForMessage(ws: WebSocket): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    ws.once("message", (data) => {
      try {
        resolve(JSON.parse(data.toString()) as Record<string, unknown>);
      } catch (e) {
        reject(e);
      }
    });
    ws.once("error", reject);
    ws.once("close", () => reject(new Error("Connection closed before message received")));
  });
}

runPatientClient().catch((err) => {
  console.error("[PatientClient] Fatal error:", err);
  process.exit(1);
});
