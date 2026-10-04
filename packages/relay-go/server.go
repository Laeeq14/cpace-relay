// server.go
// WebSocket relay server — the Go port of packages/relay/src/server.ts.
//
// Routes:
//   initSession   — Patient registers session + wrapped public key
//   joinSession   — Clinician joins (rate-limited), relay patient key back
//   registerKey   — Clinician uploads wrapped key → relay to patient
//   relay         — Forward ciphertext blob to the other party
//
// Security properties maintained:
//   - Server sees only ciphertext and base64-encoded nacl blobs
//   - Application-level session TTL enforced on every read (never TTL sweeper)
//   - Rate limiting on joinSession: 10 attempts / 5 min → permanent lock
//   - PHI plaintext guard on every blob field written to the store
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// DefaultPort is the WebSocket port the relay listens on.
const DefaultPort = 8080

// ── Plaintext guard ────────────────────────────────────────────────────────

var forbiddenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)patient reports`),
	regexp.MustCompile(`(?i)chief complaint`),
	regexp.MustCompile(`(?i)symptom`),
	regexp.MustCompile(`(?i)diagnosis`),
	regexp.MustCompile(`(?i)medication`),
	regexp.MustCompile(`(?i)prescription`),
}

// assertNoCleartext is a best-effort developer sanity check.
// It catches accidental plaintext PHI before it reaches the store.
func assertNoCleartext(value, field string) error {
	for _, pat := range forbiddenPatterns {
		if pat.MatchString(value) {
			return fmt.Errorf(
				"SECURITY: plaintext PHI detected in relay field %q — all PHI must be encrypted before sending",
				field,
			)
		}
	}
	return nil
}

// ── Per-connection state ───────────────────────────────────────────────────

type conn struct {
	id   string
	ws   *websocket.Conn
	ctx  context.Context
}

// ── Server ─────────────────────────────────────────────────────────────────

// Server is the WebSocket relay server.
type Server struct {
	store   *Store
	limiter *RateLimiter
	logger  *slog.Logger

	mu      sync.RWMutex
	sockets map[string]*conn // socketID → conn
}

// NewServer creates a Server with the given store and rate limiter.
func NewServer(store *Store, limiter *RateLimiter, logger *slog.Logger) *Server {
	return &Server{
		store:   store,
		limiter: limiter,
		logger:  logger,
		sockets: make(map[string]*conn),
	}
}

// ServeHTTP makes Server an http.Handler — mount it directly on a ServeMux.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Allow any origin for local/dev; tighten in production.
		InsecureSkipVerify: true,
	})
	if err != nil {
		s.logger.Error("websocket accept failed", "err", err)
		return
	}

	socketID := uuid.NewString()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	c := &conn{id: socketID, ws: ws, ctx: ctx}

	s.mu.Lock()
	s.sockets[socketID] = c
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sockets, socketID)
		s.mu.Unlock()
		s.store.UnregisterConn(socketID)
		ws.Close(websocket.StatusNormalClosure, "bye")
	}()

	s.logger.Info("client connected", "socketID", socketID)
	s.readLoop(c)
	s.logger.Info("client disconnected", "socketID", socketID)
}

// readLoop reads messages from a single client connection until it closes.
func (s *Server) readLoop(c *conn) {
	for {
		var raw json.RawMessage
		if err := wsjson.Read(c.ctx, c.ws, &raw); err != nil {
			if !errors.Is(err, context.Canceled) &&
				websocket.CloseStatus(err) == -1 {
				s.logger.Warn("read error", "socketID", c.id, "err", err)
			}
			return
		}

		if err := s.dispatch(c, raw); err != nil {
			s.logger.Warn("dispatch error", "socketID", c.id, "err", err)
		}
	}
}

// dispatch routes a raw JSON message to the correct handler.
func (s *Server) dispatch(c *conn, raw json.RawMessage) error {
	var base baseMsg
	if err := json.Unmarshal(raw, &base); err != nil {
		return s.sendError(c, ErrInvalidMessage, "malformed JSON")
	}

	var err error
	switch base.Type {
	case "initSession":
		var m InitSessionMsg
		if jsonErr := json.Unmarshal(raw, &m); jsonErr != nil {
			return s.sendError(c, ErrInvalidMessage, "malformed initSession")
		}
		err = s.handleInitSession(c, m)

	case "joinSession":
		var m JoinSessionMsg
		if jsonErr := json.Unmarshal(raw, &m); jsonErr != nil {
			return s.sendError(c, ErrInvalidMessage, "malformed joinSession")
		}
		err = s.handleJoinSession(c, m)

	case "registerKey":
		var m RegisterKeyMsg
		if jsonErr := json.Unmarshal(raw, &m); jsonErr != nil {
			return s.sendError(c, ErrInvalidMessage, "malformed registerKey")
		}
		err = s.handleRegisterKey(c, m)

	case "relay":
		var m RelayMsg
		if jsonErr := json.Unmarshal(raw, &m); jsonErr != nil {
			return s.sendError(c, ErrInvalidMessage, "malformed relay")
		}
		err = s.handleRelay(c, m)

	default:
		return s.sendError(c, ErrInvalidMessage, "unknown message type: "+base.Type)
	}

	return s.mapHandlerError(c, err)
}

// mapHandlerError converts handler errors to typed wire error messages.
func (s *Server) mapHandlerError(c *conn, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case contains(msg, "expired"):
		return s.sendError(c, ErrSessionExpired, msg)
	case contains(msg, "locked"):
		return s.sendError(c, ErrSessionLocked, msg)
	case contains(msg, "not found"):
		return s.sendError(c, ErrSessionNotFound, msg)
	default:
		return s.sendError(c, ErrInvalidMessage, msg)
	}
}

// ── Handlers ───────────────────────────────────────────────────────────────

func (s *Server) handleInitSession(c *conn, m InitSessionMsg) error {
	if err := assertNoCleartext(m.WrappedPatientKey.Cipher, "wrappedPatientKey.cipher"); err != nil {
		return err
	}

	s.store.CreateSession(m.SessionID)
	if err := s.store.UpdateSession(m.SessionID, func(sess *Session) {
		sess.PatientSocketID = c.id
		sess.PatientWrappedKey = &WrappedKeyPayload{
			Nonce:  m.WrappedPatientKey.Nonce,
			Cipher: m.WrappedPatientKey.Cipher,
		}
	}); err != nil {
		return err
	}
	s.store.RegisterConn(c.id, m.SessionID, RolePatient)

	return s.send(c, SessionInitedMsg{Type: "sessionInited", SessionID: m.SessionID})
}

func (s *Server) handleJoinSession(c *conn, m JoinSessionMsg) error {
	// Rate-limit check before touching the session store
	if !s.limiter.RecordAttempt(m.SessionID) {
		s.store.LockSession(m.SessionID)
		return s.sendError(c, ErrRateLimited, "too many pairing attempts — session locked")
	}

	sess, err := s.store.GetSession(m.SessionID)
	if err != nil {
		return err
	}

	if sess.PatientWrappedKey == nil {
		return s.sendError(c, ErrSessionNotFound, "patient has not initialised this session yet")
	}

	s.store.RegisterConn(c.id, m.SessionID, RoleClinician)
	if err := s.store.UpdateSession(m.SessionID, func(sess *Session) {
		sess.ClinicianSocketID = c.id
	}); err != nil {
		return err
	}

	// Relay patient's wrapped public key to clinician
	return s.send(c, PatientKeyMsg{
		Type:              "patientKey",
		WrappedPatientKey: *sess.PatientWrappedKey,
	})
}

func (s *Server) handleRegisterKey(c *conn, m RegisterKeyMsg) error {
	if err := assertNoCleartext(m.WrappedClinicianKey.Cipher, "wrappedClinicianKey.cipher"); err != nil {
		return err
	}

	sess, err := s.store.GetSession(m.SessionID)
	if err != nil {
		return err
	}

	if err := s.store.UpdateSession(m.SessionID, func(sess *Session) {
		sess.ClinicianWrappedKey = &WrappedKeyPayload{
			Nonce:  m.WrappedClinicianKey.Nonce,
			Cipher: m.WrappedClinicianKey.Cipher,
		}
	}); err != nil {
		return err
	}

	// Full pairing complete — reset brute-force counter
	s.limiter.ResetAttempts(m.SessionID)

	// Forward clinician's wrapped key to patient
	if sess.PatientSocketID != "" {
		patientConn := s.getConn(sess.PatientSocketID)
		if patientConn != nil {
			_ = s.send(patientConn, ClinicianJoinedMsg{
				Type:                "clinicianJoined",
				WrappedClinicianKey: m.WrappedClinicianKey,
			})
		}
	}
	// No ACK sent back to clinician — clinician waits for relayed payload from patient.
	return nil
}

func (s *Server) handleRelay(c *conn, m RelayMsg) error {
	sess, err := s.store.GetSession(m.SessionID)
	if err != nil {
		return err
	}

	if err := assertNoCleartext(m.Payload.Cipher, "relay.payload.cipher"); err != nil {
		return err
	}

	info := s.store.GetConn(c.id)
	if info == nil {
		return s.sendError(c, ErrInvalidMessage, "not registered to a session")
	}

	// Route to the other party
	var targetSocketID string
	if info.Role == RolePatient {
		targetSocketID = sess.ClinicianSocketID
	} else {
		targetSocketID = sess.PatientSocketID
	}

	if targetSocketID == "" {
		return s.sendError(c, ErrSessionNotFound, "other party not connected")
	}

	target := s.getConn(targetSocketID)
	if target == nil {
		return s.sendError(c, ErrSessionNotFound, "other party disconnected")
	}

	return s.send(target, RelayedMsg{Type: "relayed", Payload: m.Payload})
}

// ── Wire helpers ───────────────────────────────────────────────────────────

func (s *Server) send(c *conn, v any) error {
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	return wsjson.Write(ctx, c.ws, v)
}

func (s *Server) sendError(c *conn, code ErrorCode, message string) error {
	_ = s.send(c, ErrorMsg{Type: "error", Code: code, Message: message})
	return fmt.Errorf("%s: %s", code, message) // also return as Go error for logging
}

func (s *Server) getConn(socketID string) *conn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sockets[socketID]
}

// ── Utility ────────────────────────────────────────────────────────────────

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// ── Listener helper (for tests) ────────────────────────────────────────────

// RelayServer wraps an http.Server and exposes the underlying listener address.
type RelayServer struct {
	httpServer *http.Server
	listener   net.Listener
	Handler    *Server
}

// Addr returns the network address the relay is listening on.
func (rs *RelayServer) Addr() string {
	return rs.listener.Addr().String()
}

// Close shuts down the relay server.
func (rs *RelayServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return rs.httpServer.Shutdown(ctx)
}

// StartRelay starts a relay on the given address (e.g. ":8080") and returns
// a RelayServer. Pass ":0" to get a random port (useful in tests).
func StartRelay(addr string, logger *slog.Logger) (*RelayServer, error) {
	store := NewStore()
	limiter := NewRateLimiter()
	handler := NewServer(store, limiter, logger)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	hs := &http.Server{Handler: mux}
	go func() { _ = hs.Serve(ln) }()

	return &RelayServer{httpServer: hs, listener: ln, Handler: handler}, nil
}
