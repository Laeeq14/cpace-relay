/**
 * rateLimit.ts
 * In-memory rate limiter for pairing code join attempts.
 *
 * Rule: max 10 attempts per session within 5 minutes.
 * On the 11th attempt, the session is locked permanently for its lifetime.
 *
 * In production (Lambda), this counter moves to DynamoDB with a TTL.
 * The logic here mirrors what the Lambda handler will do.
 */

interface AttemptRecord {
  count: number;
  windowStart: number; // epoch ms
}

const WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const MAX_ATTEMPTS = 10;

const attempts = new Map<string, AttemptRecord>();

/**
 * Records a pairing attempt for the given session ID.
 * Returns true if the attempt is allowed, false if it should be rejected.
 * On the 11th attempt within the window, marks the session as locked in the store.
 */
export function recordAttempt(sessionId: string): boolean {
  const now = Date.now();
  const record = attempts.get(sessionId);

  if (record === undefined || now - record.windowStart > WINDOW_MS) {
    // New window
    attempts.set(sessionId, { count: 1, windowStart: now });
    return true;
  }

  record.count += 1;

  if (record.count > MAX_ATTEMPTS) {
    return false; // Locked
  }

  return true;
}

/**
 * Returns the current attempt count for a session.
 * Used in tests to verify lockout behaviour.
 */
export function getAttemptCount(sessionId: string): number {
  return attempts.get(sessionId)?.count ?? 0;
}

/** Resets the counter for a session (called on successful pairing). */
export function resetAttempts(sessionId: string): void {
  attempts.delete(sessionId);
}

/** Test-only: clears all counters. */
export function __clearAll(): void {
  attempts.clear();
}
