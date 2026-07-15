/**
 * store.ts
 * In-memory session store for the local relay.
 * Mirrors the schema planned for DynamoDB, including application-level
 * expiry checks on every read (does not rely on TTL background sweepers).
 *
 * Sessions: 15-minute TTL
 * Message queues: 10-minute TTL per message
 */

import type { WebSocket } from "ws";

// ── Constants ─────────────────────────────────────────────────────────────

export const SESSION_TTL_MS = 15 * 60 * 1000;   // 15 minutes
export const MESSAGE_TTL_MS = 10 * 60 * 1000;   // 10 minutes

// ── Types ─────────────────────────────────────────────────────────────────

export type SessionRole = "patient" | "clinician";

export interface WrappedKeyPayload {
  nonce: string;   // base64
  cipher: string;  // base64
}

export interface QueuedMessage {
  id: string;
  cipher: string;   // base64 — full nacl.box ciphertext
  nonce: string;    // base64
  createdAt: number; // epoch ms
}

export interface Session {
  id: string;                             // 6-digit pairing code (hashed in prod; plaintext OK locally)
  patientSocketId: string | null;
  clinicianSocketId: string | null;
  patientWrappedKey: WrappedKeyPayload | null;   // Encrypted with PIN-derived key — relay never decrypts
  clinicianWrappedKey: WrappedKeyPayload | null;
  messageQueue: QueuedMessage[];
  createdAt: number;  // epoch ms
  locked: boolean;    // rate-limit lock
}

// ── Store ─────────────────────────────────────────────────────────────────

/** Map from session ID → Session */
const sessions = new Map<string, Session>();

/** Map from WebSocket connection ID → session ID + role */
const connections = new Map<string, { sessionId: string; role: SessionRole }>();

// ── Application-level expiry helper ──────────────────────────────────────

/**
 * CRITICAL: Do not rely on TTL background sweepers (DynamoDB TTL, cron, etc.)
 * to enforce the security window. Every read goes through this check.
 */
function isSessionExpired(session: Session): boolean {
  return Date.now() > session.createdAt + SESSION_TTL_MS;
}

function isMessageExpired(msg: QueuedMessage): boolean {
  return Date.now() > msg.createdAt + MESSAGE_TTL_MS;
}

// ── Session Operations ────────────────────────────────────────────────────

export function createSession(sessionId: string): Session {
  const session: Session = {
    id: sessionId,
    patientSocketId: null,
    clinicianSocketId: null,
    patientWrappedKey: null,
    clinicianWrappedKey: null,
    messageQueue: [],
    createdAt: Date.now(),
    locked: false,
  };
  sessions.set(sessionId, session);
  return session;
}

/**
 * Get a session by ID with mandatory application-level expiry check.
 * Throws if session is missing, expired, or locked.
 */
export function getSession(sessionId: string): Session {
  const session = sessions.get(sessionId);
  if (session === undefined) {
    throw new Error(`Session not found: ${sessionId}`);
  }
  // Application-level TTL enforcement — never skip this
  if (isSessionExpired(session)) {
    sessions.delete(sessionId);
    throw new Error("Session expired");
  }
  if (session.locked) {
    throw new Error("Session locked — too many pairing attempts");
  }
  return session;
}

export function updateSession(sessionId: string, patch: Partial<Session>): void {
  const session = getSession(sessionId); // enforces expiry on write too
  Object.assign(session, patch);
}

export function deleteSession(sessionId: string): void {
  sessions.delete(sessionId);
}

// ── Message Queue ─────────────────────────────────────────────────────────

export function enqueueMessage(sessionId: string, msg: Omit<QueuedMessage, "createdAt">): void {
  const session = getSession(sessionId);
  session.messageQueue.push({ ...msg, createdAt: Date.now() });
}

/**
 * Drain unexpired messages from the queue.
 * Expired messages are silently discarded — application-level TTL enforcement.
 */
export function drainMessages(sessionId: string): QueuedMessage[] {
  const session = getSession(sessionId);
  const live = session.messageQueue.filter((m) => !isMessageExpired(m));
  session.messageQueue = [];
  return live;
}

// ── Connection Registry ────────────────────────────────────────────────────

export function registerConnection(
  socketId: string,
  sessionId: string,
  role: SessionRole
): void {
  connections.set(socketId, { sessionId, role });
}

export function unregisterConnection(socketId: string): { sessionId: string; role: SessionRole } | undefined {
  const conn = connections.get(socketId);
  connections.delete(socketId);
  return conn;
}

export function getConnection(socketId: string): { sessionId: string; role: SessionRole } | undefined {
  return connections.get(socketId);
}

// ── Diagnostic (test use only) ────────────────────────────────────────────

/** Returns a snapshot of all sessions. Used in integration tests to assert
 *  that the store never contains plaintext PHI or raw private keys. */
export function __getAllSessionsSnapshot(): unknown[] {
  return [...sessions.values()].map((s) => ({ ...s }));
}

export function __clearAll(): void {
  sessions.clear();
  connections.clear();
}
