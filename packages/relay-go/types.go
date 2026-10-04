// types.go
// Wire message types for the CPace-Relay protocol.
// The relay only ever routes these — it never decrypts them.
package relay

// ── Wrapped key payload ────────────────────────────────────────────────────

// WrappedKeyPayload is a nacl.secretbox-encrypted key blob.
// The relay stores and forwards this opaquely; it never has the PIN to open it.
type WrappedKeyPayload struct {
	Nonce  string `json:"nonce"`  // base64 nacl nonce
	Cipher string `json:"cipher"` // base64 nacl ciphertext
}

// ── Client → Server ────────────────────────────────────────────────────────

type baseMsg struct {
	Type string `json:"type"`
}

// InitSessionMsg — patient registers a session and uploads their wrapped public key.
type InitSessionMsg struct {
	Type              string            `json:"type"`
	SessionID         string            `json:"sessionId"`
	WrappedPatientKey WrappedKeyPayload `json:"wrappedPatientKey"`
}

// JoinSessionMsg — clinician joins using the 6-digit PIN.
type JoinSessionMsg struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
}

// RelayMsg — either party forwards an encrypted payload to the other.
type RelayMsg struct {
	Type      string            `json:"type"`
	SessionID string            `json:"sessionId"`
	Payload   WrappedKeyPayload `json:"payload"`
}

// RegisterKeyMsg — clinician uploads their wrapped public key after joining.
type RegisterKeyMsg struct {
	Type                string            `json:"type"`
	SessionID           string            `json:"sessionId"`
	WrappedClinicianKey WrappedKeyPayload `json:"wrappedClinicianKey"`
}

// ── Server → Client ────────────────────────────────────────────────────────

// SessionInitedMsg — ACK sent to patient after initSession.
type SessionInitedMsg struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
}

// ClinicianJoinedMsg — sent to patient when clinician registers their key.
type ClinicianJoinedMsg struct {
	Type                string            `json:"type"`
	WrappedClinicianKey WrappedKeyPayload `json:"wrappedClinicianKey"`
}

// PatientKeyMsg — sent to clinician after joinSession, carrying patient's wrapped key.
type PatientKeyMsg struct {
	Type              string            `json:"type"`
	WrappedPatientKey WrappedKeyPayload `json:"wrappedPatientKey"`
}

// RelayedMsg — ciphertext forwarded from one party to the other.
type RelayedMsg struct {
	Type    string            `json:"type"`
	Payload WrappedKeyPayload `json:"payload"`
}

// ErrorCode is a typed error code sent to clients.
type ErrorCode string

const (
	ErrSessionNotFound ErrorCode = "SESSION_NOT_FOUND"
	ErrSessionExpired  ErrorCode = "SESSION_EXPIRED"
	ErrSessionLocked   ErrorCode = "SESSION_LOCKED"
	ErrRateLimited     ErrorCode = "RATE_LIMITED"
	ErrInvalidMessage  ErrorCode = "INVALID_MESSAGE"
)

// ErrorMsg — sent to the client on any failure path.
type ErrorMsg struct {
	Type    string    `json:"type"`
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}
