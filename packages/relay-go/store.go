// store.go
// In-memory session store with application-level TTL enforcement.
//
// Security invariant: every read goes through an explicit expiry check.
// We deliberately do NOT rely on background sweepers — a missed sweep would
// widen the security window for brute-force attacks on the 6-digit PIN.
//
// Sessions:  15-minute TTL
// Messages:  10-minute TTL per queued message
package relay

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ── Constants ──────────────────────────────────────────────────────────────

const (
	SessionTTL = 15 * time.Minute
	MessageTTL = 10 * time.Minute
)

// ── Types ──────────────────────────────────────────────────────────────────

// SessionRole identifies which side of a pairing a connection holds.
type SessionRole string

const (
	RolePatient   SessionRole = "patient"
	RoleClinician SessionRole = "clinician"
)

// QueuedMessage is a ciphertext blob with a creation timestamp for TTL checks.
type QueuedMessage struct {
	ID        string
	Cipher    string // base64 nacl.box ciphertext
	Nonce     string // base64
	CreatedAt time.Time
}

// Session is the in-memory state for one pairing session.
type Session struct {
	ID                   string
	PatientSocketID      string // empty = not connected
	ClinicianSocketID    string
	PatientWrappedKey    *WrappedKeyPayload
	ClinicianWrappedKey  *WrappedKeyPayload
	MessageQueue         []QueuedMessage
	CreatedAt            time.Time
	Locked               bool
}

// ConnInfo binds a socket ID to its session and role.
type ConnInfo struct {
	SessionID string
	Role      SessionRole
}

// ── Store ──────────────────────────────────────────────────────────────────

// Store holds all in-memory state for the relay.
// All exported methods are safe for concurrent use.
type Store struct {
	mu          sync.RWMutex
	sessions    map[string]*Session
	connections map[string]*ConnInfo // socketID → ConnInfo
}

// NewStore allocates and returns an empty Store.
func NewStore() *Store {
	return &Store{
		sessions:    make(map[string]*Session),
		connections: make(map[string]*ConnInfo),
	}
}

// ── Application-level expiry helpers ──────────────────────────────────────

func sessionExpired(s *Session) bool {
	return time.Now().After(s.CreatedAt.Add(SessionTTL))
}

func messageExpired(m QueuedMessage) bool {
	return time.Now().After(m.CreatedAt.Add(MessageTTL))
}

// ── Session operations ─────────────────────────────────────────────────────

// CreateSession adds a new session to the store.
func (st *Store) CreateSession(sessionID string) *Session {
	st.mu.Lock()
	defer st.mu.Unlock()

	s := &Session{
		ID:        sessionID,
		CreatedAt: time.Now(),
	}
	st.sessions[sessionID] = s
	return s
}

// GetSession returns the session, enforcing TTL and lock status.
// Callers MUST use this for every read — never access the map directly.
func (st *Store) GetSession(sessionID string) (*Session, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	s, ok := st.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	// Application-level TTL — never skip
	if sessionExpired(s) {
		delete(st.sessions, sessionID)
		return nil, fmt.Errorf("session expired")
	}
	if s.Locked {
		return nil, fmt.Errorf("session locked — too many pairing attempts")
	}
	return s, nil
}

// UpdateSession applies a mutator function inside the store lock.
// The mutator receives the session pointer directly; the TTL check fires first.
func (st *Store) UpdateSession(sessionID string, fn func(*Session)) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	s, ok := st.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	if sessionExpired(s) {
		delete(st.sessions, sessionID)
		return fmt.Errorf("session expired")
	}
	fn(s)
	return nil
}

// LockSession sets locked=true even if the session is expired or already absent.
// Used on rate-limit breach — we want best-effort lock even under degraded state.
func (st *Store) LockSession(sessionID string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.sessions[sessionID]; ok {
		s.Locked = true
	}
}

// DeleteSession removes a session from the store.
func (st *Store) DeleteSession(sessionID string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.sessions, sessionID)
}

// ── Message queue ──────────────────────────────────────────────────────────

// EnqueueMessage appends a ciphertext blob to a session's queue.
func (st *Store) EnqueueMessage(sessionID string, cipher, nonce string) error {
	return st.UpdateSession(sessionID, func(s *Session) {
		s.MessageQueue = append(s.MessageQueue, QueuedMessage{
			ID:        uuid.NewString(),
			Cipher:    cipher,
			Nonce:     nonce,
			CreatedAt: time.Now(),
		})
	})
}

// DrainMessages returns and removes all unexpired queued messages.
// Expired messages are silently discarded per the application-level TTL rule.
func (st *Store) DrainMessages(sessionID string) ([]QueuedMessage, error) {
	var live []QueuedMessage
	err := st.UpdateSession(sessionID, func(s *Session) {
		for _, m := range s.MessageQueue {
			if !messageExpired(m) {
				live = append(live, m)
			}
		}
		s.MessageQueue = nil
	})
	return live, err
}

// ── Connection registry ────────────────────────────────────────────────────

// RegisterConn binds a socket ID to a session and role.
func (st *Store) RegisterConn(socketID, sessionID string, role SessionRole) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.connections[socketID] = &ConnInfo{SessionID: sessionID, Role: role}
}

// UnregisterConn removes a socket from the registry and returns its last ConnInfo.
func (st *Store) UnregisterConn(socketID string) *ConnInfo {
	st.mu.Lock()
	defer st.mu.Unlock()
	info := st.connections[socketID]
	delete(st.connections, socketID)
	return info
}

// GetConn returns the ConnInfo for a socket, or nil if not registered.
func (st *Store) GetConn(socketID string) *ConnInfo {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.connections[socketID]
}

// ── Test helpers ───────────────────────────────────────────────────────────

// Snapshot returns a copy of all sessions for test assertions.
// Never call this in production paths.
func (st *Store) Snapshot() []*Session {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]*Session, 0, len(st.sessions))
	for _, s := range st.sessions {
		cp := *s
		out = append(out, &cp)
	}
	return out
}

// Clear wipes all state. Test use only.
func (st *Store) Clear() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sessions = make(map[string]*Session)
	st.connections = make(map[string]*ConnInfo)
}
