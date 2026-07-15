/**
 * server.ts
 * Local WebSocket relay server using the 'ws' library.
 * Mirrors the handler logic that will be ported to AWS Lambda + API Gateway.
 *
 * Routes:
 *  initSession   — Patient registers session + wrapped public key
 *  joinSession   — Clinician joins (rate-limited), relay patient key back
 *  registerKey   — Clinician uploads their wrapped public key → relay to patient
 *  relay         — Forward ciphertext blob to the other party
 *
 * Security properties maintained:
 *  - Server sees only ciphertext and base64-encoded nacl.secretbox blobs
 *  - Application-level session TTL enforced on every read (not TTL sweeper)
 *  - Rate limiting on joinSession (10 attempts / 5 min → lock)
 */

import { WebSocketServer, WebSocket } from "ws";
import { v4 as uuidv4 } from "uuid";
import {
  createSession,
  getSession,
  updateSession,
  deleteSession,
  registerConnection,
  unregisterConnection,
  getConnection,
} from "./store.js";
import { recordAttempt, resetAttempts } from "./rateLimit.js";
import type {
  ClientMessage,
  ServerMessage,
  ErrorMsg,
} from "./types.js";

export const DEFAULT_PORT = 8080;

// ── Helper ────────────────────────────────────────────────────────────────

function send(ws: WebSocket, msg: ServerMessage): void {
  ws.send(JSON.stringify(msg));
}

function sendError(ws: WebSocket, code: ErrorMsg["code"], message: string): void {
  send(ws, { type: "error", code, message });
}

// ── Connection registry (socketId → WebSocket) ────────────────────────────

const sockets = new Map<string, WebSocket>();

// ── Server Factory ────────────────────────────────────────────────────────

/**
 * Creates and starts the WebSocket relay server.
 * Returns the server instance so tests can close it after each suite.
 */
export function createRelayServer(port = DEFAULT_PORT): WebSocketServer {
  const wss = new WebSocketServer({ port });

  wss.on("connection", (ws: WebSocket) => {
    const socketId = uuidv4();
    sockets.set(socketId, ws);

    ws.on("message", (raw: Buffer) => {
      let msg: ClientMessage;
      try {
        msg = JSON.parse(raw.toString()) as ClientMessage;
      } catch {
        sendError(ws, "INVALID_MESSAGE", "Malformed JSON");
        return;
      }

      try {
        handleMessage(ws, socketId, msg);
      } catch (err) {
        const message = err instanceof Error ? err.message : "Unknown error";
        if (message.includes("expired")) {
          sendError(ws, "SESSION_EXPIRED", message);
        } else if (message.includes("locked")) {
          sendError(ws, "SESSION_LOCKED", message);
        } else if (message.includes("not found")) {
          sendError(ws, "SESSION_NOT_FOUND", message);
        } else {
          sendError(ws, "INVALID_MESSAGE", message);
        }
      }
    });

    ws.on("close", () => {
      sockets.delete(socketId);
      unregisterConnection(socketId);
    });
  });

  return wss;
}

// ── Message Dispatcher ────────────────────────────────────────────────────

function handleMessage(ws: WebSocket, socketId: string, msg: ClientMessage): void {
  switch (msg.type) {
    case "initSession":
      handleInitSession(ws, socketId, msg.sessionId, msg.wrappedPatientKey);
      break;
    case "joinSession":
      handleJoinSession(ws, socketId, msg.sessionId);
      break;
    case "registerKey":
      handleRegisterKey(ws, socketId, msg.sessionId, msg.wrappedClinicianKey);
      break;
    case "relay":
      handleRelay(ws, socketId, msg.sessionId, msg.payload);
      break;
    default:
      sendError(ws, "INVALID_MESSAGE", "Unknown message type");
  }
}

// ── Handlers ──────────────────────────────────────────────────────────────

function handleInitSession(
  ws: WebSocket,
  socketId: string,
  sessionId: string,
  wrappedPatientKey: { nonce: string; cipher: string }
): void {
  // Validate: only base64 chars in key material — plaintext check
  assertNoCleartext(wrappedPatientKey.cipher, "wrappedPatientKey.cipher");

  createSession(sessionId);
  updateSession(sessionId, {
    patientSocketId: socketId,
    patientWrappedKey: wrappedPatientKey,
  });
  registerConnection(socketId, sessionId, "patient");

  send(ws, { type: "sessionInited", sessionId });
}

function handleJoinSession(ws: WebSocket, socketId: string, sessionId: string): void {
  // Rate limit check before touching session store
  const allowed = recordAttempt(sessionId);
  if (!allowed) {
    // Lock the session in store too
    try {
      updateSession(sessionId, { locked: true });
    } catch {
      // Session may already be gone — still reject
    }
    sendError(ws, "RATE_LIMITED", "Too many pairing attempts — session locked");
    return;
  }

  // getSession enforces application-level TTL
  const session = getSession(sessionId);

  if (session.patientWrappedKey === null) {
    sendError(ws, "SESSION_NOT_FOUND", "Patient has not initialised this session yet");
    return;
  }

  registerConnection(socketId, sessionId, "clinician");
  updateSession(sessionId, { clinicianSocketId: socketId });
  // Do NOT reset attempt counter here — only reset when full pairing completes (registerKey)

  // Relay patient's wrapped public key to clinician
  send(ws, {
    type: "patientKey",
    wrappedPatientKey: session.patientWrappedKey,
  });
}

function handleRegisterKey(
  ws: WebSocket,
  socketId: string,
  sessionId: string,
  wrappedClinicianKey: { nonce: string; cipher: string }
): void {
  assertNoCleartext(wrappedClinicianKey.cipher, "wrappedClinicianKey.cipher");

  const session = getSession(sessionId); // TTL enforced
  updateSession(sessionId, { clinicianWrappedKey: wrappedClinicianKey });
  resetAttempts(sessionId); // Full pairing complete — reset brute-force counter

  // Forward clinician's wrapped public key to patient
  if (session.patientSocketId !== null) {
    const patientSocket = sockets.get(session.patientSocketId);
    if (patientSocket !== undefined && patientSocket.readyState === WebSocket.OPEN) {
      send(patientSocket, { type: "clinicianJoined", wrappedClinicianKey });
    }
  }
  // No ACK sent back to clinician — clinician waits for the relayed payload from patient.
  // Sending sessionInited here would arrive before the relayed message and corrupt the protocol.
}

function handleRelay(
  ws: WebSocket,
  socketId: string,
  sessionId: string,
  payload: { nonce: string; cipher: string }
): void {
  // Application-level TTL enforced
  const session = getSession(sessionId);
  assertNoCleartext(payload.cipher, "relay.payload.cipher");

  const conn = getConnection(socketId);
  if (conn === undefined) {
    sendError(ws, "INVALID_MESSAGE", "Not registered to a session");
    return;
  }

  // Route to the other party
  const targetSocketId =
    conn.role === "patient" ? session.clinicianSocketId : session.patientSocketId;

  if (targetSocketId === null) {
    sendError(ws, "SESSION_NOT_FOUND", "Other party not connected");
    return;
  }

  const targetSocket = sockets.get(targetSocketId);
  if (targetSocket === undefined || targetSocket.readyState !== WebSocket.OPEN) {
    sendError(ws, "SESSION_NOT_FOUND", "Other party disconnected");
    return;
  }

  send(targetSocket, { type: "relayed", payload });
}

// ── Plaintext guard ────────────────────────────────────────────────────────

/**
 * Asserts that a value going into the relay store looks like base64,
 * not a plaintext string. This is a best-effort sanity check to catch
 * accidental developer mistakes — not a cryptographic guarantee.
 */
function assertNoCleartext(value: string, field: string): void {
  // Plaintext medical terms that must never appear in relay payloads
  const forbiddenPatterns = [
    /patient reports/i,
    /chief complaint/i,
    /symptom/i,
    /diagnosis/i,
    /medication/i,
    /prescription/i,
  ];
  for (const pattern of forbiddenPatterns) {
    if (pattern.test(value)) {
      throw new Error(
        `SECURITY: Plaintext PHI detected in relay field "${field}". ` +
        "All PHI must be encrypted before sending to the relay."
      );
    }
  }
}

// ── Entrypoint ────────────────────────────────────────────────────────────

// Only start server when run directly, not when imported by tests
const isMain = process.argv[1]?.endsWith("server.ts") ||
               process.argv[1]?.endsWith("server.js");

if (isMain) {
  const server = createRelayServer(DEFAULT_PORT);
  console.log(`[PassChart Relay] Listening on ws://localhost:${DEFAULT_PORT}`);
  console.log("[PassChart Relay] This is the local dev relay — not for production use with real PHI.");

  process.on("SIGINT", () => {
    server.close(() => {
      console.log("[PassChart Relay] Shut down cleanly.");
      process.exit(0);
    });
  });
}
