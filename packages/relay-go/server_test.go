// server_test.go
// Integration tests for the Go relay server.
// Mirrors the behaviour of packages/relay/tests/integration/wire.test.ts.
//
// Test groups:
//   1. Full handshake (initSession → joinSession → registerKey → relay)
//   2. Wire-level assertion: store never contains plaintext PHI
//   3. Rate limiting: 11th joinSession attempt → RATE_LIMITED / SESSION_LOCKED
//   4. Application-level expiry: SESSION_NOT_FOUND for unknown session
package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// ── Test helpers ───────────────────────────────────────────────────────────

func newTestServer(t *testing.T) (string, *RelayServer) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	rs, err := StartRelay(":0", logger)
	if err != nil {
		t.Fatalf("StartRelay: %v", err)
	}
	t.Cleanup(func() { _ = rs.Close() })
	return "ws://" + rs.Addr(), rs
}

func dial(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	t.Cleanup(func() { ws.Close(websocket.StatusNormalClosure, "") })
	return ws
}

func sendJSON(t *testing.T, ws *websocket.Conn, v any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := wsjson.Write(ctx, ws, v); err != nil {
		t.Fatalf("sendJSON: %v", err)
	}
}

func recvMsg(t *testing.T, ws *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var raw map[string]any
	if err := wsjson.Read(ctx, ws, &raw); err != nil {
		t.Fatalf("recvMsg: %v", err)
	}
	return raw
}

func assertField(t *testing.T, msg map[string]any, key, want string) {
	t.Helper()
	got, ok := msg[key]
	if !ok {
		t.Fatalf("field %q missing from message %v", key, msg)
	}
	if fmt.Sprintf("%v", got) != want {
		t.Fatalf("field %q: got %q, want %q", key, got, want)
	}
}

// ── Test group 1: Full handshake ───────────────────────────────────────────

func TestInitSession_ACK(t *testing.T) {
	url, _ := newTestServer(t)
	patient := dial(t, url)

	sendJSON(t, patient, map[string]any{
		"type":      "initSession",
		"sessionId": "123456",
		"wrappedPatientKey": map[string]string{
			"nonce":  "dGVzdG5vbmNl",
			"cipher": "dGVzdGNpcGhlcg==",
		},
	})

	resp := recvMsg(t, patient)
	assertField(t, resp, "type", "sessionInited")
	assertField(t, resp, "sessionId", "123456")
}

func TestJoinSession_ReceivesPatientKey(t *testing.T) {
	url, _ := newTestServer(t)
	patient := dial(t, url)
	clinician := dial(t, url)

	// Patient inits
	sendJSON(t, patient, map[string]any{
		"type":      "initSession",
		"sessionId": "234567",
		"wrappedPatientKey": map[string]string{
			"nonce":  "bm9uY2U=",
			"cipher": "Y2lwaGVy",
		},
	})
	recvMsg(t, patient) // consume sessionInited

	// Clinician joins
	sendJSON(t, clinician, map[string]any{
		"type":      "joinSession",
		"sessionId": "234567",
	})

	resp := recvMsg(t, clinician)
	assertField(t, resp, "type", "patientKey")

	wk, ok := resp["wrappedPatientKey"].(map[string]any)
	if !ok {
		t.Fatal("wrappedPatientKey missing or wrong type")
	}
	if wk["cipher"] != "Y2lwaGVy" {
		t.Fatalf("cipher mismatch: got %v", wk["cipher"])
	}
}

func TestFullHandshake_RelayForwardsPayload(t *testing.T) {
	url, _ := newTestServer(t)
	patient := dial(t, url)
	clinician := dial(t, url)

	// Init
	sendJSON(t, patient, map[string]any{
		"type":      "initSession",
		"sessionId": "345678",
		"wrappedPatientKey": map[string]string{
			"nonce": "bm9uY2U=", "cipher": "Y2lwaGVy",
		},
	})
	recvMsg(t, patient)

	// Join
	sendJSON(t, clinician, map[string]any{
		"type":      "joinSession",
		"sessionId": "345678",
	})
	recvMsg(t, clinician)

	// Clinician registers key — patient gets clinicianJoined
	sendJSON(t, clinician, map[string]any{
		"type":      "registerKey",
		"sessionId": "345678",
		"wrappedClinicianKey": map[string]string{
			"nonce": "Y2xpbm9uY2U=", "cipher": "Y2xpbmNpcGhlcg==",
		},
	})

	notify := recvMsg(t, patient)
	assertField(t, notify, "type", "clinicianJoined")

	// Patient relays ciphertext — clinician receives it
	relayDone := make(chan map[string]any, 1)
	go func() { relayDone <- recvMsg(t, clinician) }()

	sendJSON(t, patient, map[string]any{
		"type":      "relay",
		"sessionId": "345678",
		"payload": map[string]string{
			"nonce": "cmVsYXlub25jZQ==", "cipher": "cmVsYXljaXBoZXI=",
		},
	})

	relayed := <-relayDone
	assertField(t, relayed, "type", "relayed")

	pl, ok := relayed["payload"].(map[string]any)
	if !ok {
		t.Fatal("payload missing")
	}
	if pl["cipher"] != "cmVsYXljaXBoZXI=" {
		t.Fatalf("relayed cipher mismatch: got %v", pl["cipher"])
	}
}

// ── Test group 2: Wire-level assertion ────────────────────────────────────

func TestStore_NoCleartextPHI(t *testing.T) {
	url, rs := newTestServer(t)
	patient := dial(t, url)

	sendJSON(t, patient, map[string]any{
		"type":      "initSession",
		"sessionId": "456789",
		"wrappedPatientKey": map[string]string{
			"nonce": "bm9uY2U=", "cipher": "Y2lwaGVy",
		},
	})
	recvMsg(t, patient)

	// Inspect the in-memory store
	snapshot := rs.Handler.store.Snapshot()
	data, _ := json.Marshal(snapshot)
	raw := strings.ToLower(string(data))

	forbidden := []string{
		"patient reports",
		"chief complaint",
		"symptom",
		"right knee",
	}
	for _, term := range forbidden {
		if strings.Contains(raw, term) {
			t.Errorf("store contains forbidden plaintext term %q", term)
		}
	}
}

// ── Test group 3: Rate limiting ────────────────────────────────────────────

func TestRateLimit_11thAttemptBlocked(t *testing.T) {
	url, _ := newTestServer(t)
	sessionID := "567890"

	// Patient inits the session
	patient := dial(t, url)
	sendJSON(t, patient, map[string]any{
		"type":      "initSession",
		"sessionId": sessionID,
		"wrappedPatientKey": map[string]string{
			"nonce": "bm9uY2U=", "cipher": "Y2lwaGVy",
		},
	})
	recvMsg(t, patient)

	// One persistent clinician sends 11 joinSession messages
	clinician := dial(t, url)
	results := make([]map[string]any, 11)
	for i := 0; i < 11; i++ {
		sendJSON(t, clinician, map[string]any{
			"type":      "joinSession",
			"sessionId": sessionID,
		})
		results[i] = recvMsg(t, clinician)
	}

	// First 10 must not be errors
	for i, r := range results[:10] {
		if r["type"] == "error" {
			t.Errorf("attempt %d was unexpectedly rejected: %v", i+1, r)
		}
	}

	// 11th must be RATE_LIMITED or SESSION_LOCKED
	last := results[10]
	if last["type"] != "error" {
		t.Fatalf("11th attempt was not rejected: %v", last)
	}
	code, _ := last["code"].(string)
	if code != string(ErrRateLimited) && code != string(ErrSessionLocked) {
		t.Fatalf("unexpected error code on 11th attempt: %q", code)
	}
}

// ── Test group 4: Expiry / not-found ──────────────────────────────────────

func TestJoinSession_NonExistentSession_NotFound(t *testing.T) {
	url, _ := newTestServer(t)
	clinician := dial(t, url)

	sendJSON(t, clinician, map[string]any{
		"type":      "joinSession",
		"sessionId": "999999",
	})

	resp := recvMsg(t, clinician)
	assertField(t, resp, "type", "error")
	assertField(t, resp, "code", string(ErrSessionNotFound))
}

func TestJoinSession_ExpiredSession_ReturnsExpired(t *testing.T) {
	url, rs := newTestServer(t)
	sessionID := "expired1"

	// Create session then back-date it past TTL
	rs.Handler.store.CreateSession(sessionID)
	_ = rs.Handler.store.UpdateSession(sessionID, func(s *Session) {
		s.CreatedAt = time.Now().Add(-(SessionTTL + time.Second))
	})

	clinician := dial(t, url)
	sendJSON(t, clinician, map[string]any{
		"type":      "joinSession",
		"sessionId": sessionID,
	})

	resp := recvMsg(t, clinician)
	assertField(t, resp, "type", "error")
	code, _ := resp["code"].(string)
	if code != string(ErrSessionExpired) && code != string(ErrSessionNotFound) {
		t.Fatalf("expected SESSION_EXPIRED or SESSION_NOT_FOUND, got %q", code)
	}
}

// ── PHI guard: plaintext in cipher field is rejected ──────────────────────

func TestInitSession_PlaintextPHIRejected(t *testing.T) {
	url, _ := newTestServer(t)
	patient := dial(t, url)

	sendJSON(t, patient, map[string]any{
		"type":      "initSession",
		"sessionId": "phi001",
		"wrappedPatientKey": map[string]string{
			"nonce":  "dGVzdG5vbmNl",
			"cipher": "patient reports right knee pain",
		},
	})

	resp := recvMsg(t, patient)
	assertField(t, resp, "type", "error")
}
