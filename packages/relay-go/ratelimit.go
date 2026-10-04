// ratelimit.go
// In-memory rate limiter for pairing-code join attempts.
//
// Rule: max 10 attempts per session within a 5-minute sliding window.
// On the 11th attempt the session is permanently locked for its lifetime.
//
// In production (Lambda / DynamoDB) this counter moves to an atomic
// DynamoDB item with a TTL attribute. The logic here mirrors that exactly.
package relay

import (
	"sync"
	"time"
)

const (
	rateLimitWindow   = 5 * time.Minute
	rateLimitMaxTries = 10
)

type attemptRecord struct {
	count       int
	windowStart time.Time
}

// RateLimiter tracks per-session join attempts.
// All methods are safe for concurrent use.
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*attemptRecord
}

// NewRateLimiter returns an initialised RateLimiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{attempts: make(map[string]*attemptRecord)}
}

// RecordAttempt records a joinSession attempt.
// Returns true if the attempt is allowed, false if it must be rejected and
// the session locked.
func (rl *RateLimiter) RecordAttempt(sessionID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rec, ok := rl.attempts[sessionID]

	if !ok || now.Sub(rec.windowStart) > rateLimitWindow {
		// Fresh window
		rl.attempts[sessionID] = &attemptRecord{count: 1, windowStart: now}
		return true
	}

	rec.count++
	return rec.count <= rateLimitMaxTries
}

// GetAttemptCount returns the current attempt count. Primarily for tests.
func (rl *RateLimiter) GetAttemptCount(sessionID string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rec, ok := rl.attempts[sessionID]; ok {
		return rec.count
	}
	return 0
}

// ResetAttempts clears the counter on successful pairing (registerKey).
func (rl *RateLimiter) ResetAttempts(sessionID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, sessionID)
}

// Clear wipes all counters. Test use only.
func (rl *RateLimiter) Clear() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.attempts = make(map[string]*attemptRecord)
}
