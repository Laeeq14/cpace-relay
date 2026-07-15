/**
 * clinician.ts
 * Simulates a clinician portal during Phase 1 testing.
 *
 * Flow:
 *  1. Prompt for 6-digit pairing code (typed by clinician)
 *  2. Generate ephemeral X25519 keypair
 *  3. Derive PIN key from pairing code (PBKDF2)
 *  4. Send joinSession to relay
 *  5. Receive patient's wrapped public key from relay
 *  6. Unwrap patient's public key using PIN key
 *  7. Wrap own public key with PIN key
 *  8. Send registerKey to relay
 *  9. Derive shared secret
 * 10. Wait for relayed encrypted intake payload
 * 11. Decrypt and print intake data
 *
 * Run: npm run clinician --workspace=packages/test-clients
 * Requires: relay server running on ws://localhost:8080
 * and a patient session already initialised.
 */

import { WebSocket } from "ws";
import * as readline from "readline";
import {
  derivePinKey,
  generateKeyPair,
  wrapPublicKey,
  unwrapPublicKey,
  deriveSharedSecret,
  decryptMessage,
} from "@passchart/crypto";
import type { EncryptedMessage } from "@passchart/crypto";

const RELAY_URL = "ws://localhost:8080";

async function promptPin(): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question("Enter the 6-digit pairing code from the patient device: ", (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function runClinicianClient(): Promise<void> {
  console.log("\n[ClinicianPortal] Starting PassChart clinician simulation...");

  const pin = await promptPin();

  if (!/^\d{6}$/.test(pin)) {
    console.error("[ClinicianPortal] Invalid PIN — must be exactly 6 digits.");
    process.exit(1);
  }

  console.log("[ClinicianPortal] Generating keypair...");
  const keyPair = generateKeyPair();

  console.log("[ClinicianPortal] Deriving PIN key (PBKDF2, 600k iterations)...");
  const pinKey = await derivePinKey(pin);

  const ws = new WebSocket(RELAY_URL);

  await new Promise<void>((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });

  console.log("[ClinicianPortal] Connected to relay ✓");

  // Join session
  ws.send(JSON.stringify({ type: "joinSession", sessionId: pin }));

  // Receive patient's wrapped public key
  const patientKeyMsg = await waitForMessage(ws);
  if (patientKeyMsg.type !== "patientKey") {
    if (patientKeyMsg.type === "error") {
      const code = (patientKeyMsg as Record<string, string>)["code"];
      const msg = (patientKeyMsg as Record<string, string>)["message"];
      console.error(`[ClinicianPortal] Error joining session: [${code}] ${msg}`);
    } else {
      console.error(`[ClinicianPortal] Unexpected response: ${JSON.stringify(patientKeyMsg)}`);
    }
    process.exit(1);
  }

  console.log("[ClinicianPortal] Received patient wrapped public key from relay ✓");

  // Unwrap patient's public key using PIN key
  // TypeScript: narrowed after type check above
  const wrappedPatientKey = (patientKeyMsg as Record<string, unknown>)["wrappedPatientKey"] as { nonce: string; cipher: string };
  const patientPublicKey = unwrapPublicKey(wrappedPatientKey, pinKey);
  console.log("[ClinicianPortal] Patient public key unwrapped and authenticated ✓");

  // Wrap our own public key and send to relay
  const wrappedClinicianKey = wrapPublicKey(keyPair.publicKey, pinKey);
  ws.send(JSON.stringify({
    type: "registerKey",
    sessionId: pin,
    wrappedClinicianKey,
  }));
  console.log("[ClinicianPortal] Clinician wrapped public key sent to relay ✓");

  // Derive shared secret
  const sharedSecret = deriveSharedSecret(patientPublicKey, keyPair.secretKey);
  console.log("[ClinicianPortal] Shared secret derived ✓");
  console.log("[ClinicianPortal] Waiting for encrypted intake data from patient...\n");

  // Wait for relayed encrypted payload
  const relayedMsg = await waitForMessage(ws);
  if (relayedMsg.type !== "relayed") {
    console.error(`[ClinicianPortal] Unexpected message: ${JSON.stringify(relayedMsg)}`);
    process.exit(1);
  }

  const payload = (relayedMsg as Record<string, unknown>)["payload"] as EncryptedMessage;

  // Decrypt
  const decrypted = decryptMessage(payload, sharedSecret);

  console.log("═══════════════════════════════════════════════════════");
  console.log("  DECRYPTED INTAKE DATA (authenticated, tamper-proof)");
  console.log("═══════════════════════════════════════════════════════");
  console.log(decrypted);
  console.log("═══════════════════════════════════════════════════════");
  console.log("\n[ClinicianPortal] Decryption successful ✓");
  console.log("[ClinicianPortal] This data never touched the relay in plaintext ✓");

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

runClinicianClient().catch((err) => {
  console.error("[ClinicianPortal] Fatal error:", err);
  process.exit(1);
});
