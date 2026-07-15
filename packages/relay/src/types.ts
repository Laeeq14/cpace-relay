/**
 * types.ts
 * Shared wire message types for the PassChart relay protocol.
 * The relay only ever routes these — it never decrypts them.
 */

// ── Client → Server messages ───────────────────────────────────────────────

export interface InitSessionMsg {
  type: "initSession";
  sessionId: string;                    // 6-digit pairing code
  wrappedPatientKey: {
    nonce: string;                      // base64 nacl.secretbox nonce
    cipher: string;                     // base64 nacl.secretbox ciphertext of patient public key
  };
}

export interface JoinSessionMsg {
  type: "joinSession";
  sessionId: string;                    // The 6-digit code the clinician typed
}

export interface RelayMsg {
  type: "relay";
  sessionId: string;
  payload: {
    nonce: string;                      // base64 nacl.box nonce
    cipher: string;                     // base64 nacl.box ciphertext
  };
}

export interface RegisterKeyMsg {
  type: "registerKey";
  sessionId: string;
  wrappedClinicianKey: {
    nonce: string;
    cipher: string;
  };
}

export type ClientMessage =
  | InitSessionMsg
  | JoinSessionMsg
  | RelayMsg
  | RegisterKeyMsg;

// ── Server → Client messages ───────────────────────────────────────────────

export interface SessionInitedMsg {
  type: "sessionInited";
  sessionId: string;
}

export interface ClinicianJoinedMsg {
  type: "clinicianJoined";
  wrappedClinicianKey: {
    nonce: string;
    cipher: string;
  };
}

export interface PatientKeyMsg {
  type: "patientKey";
  wrappedPatientKey: {
    nonce: string;
    cipher: string;
  };
}

export interface RelayedMsg {
  type: "relayed";
  payload: {
    nonce: string;
    cipher: string;
  };
}

export interface ErrorMsg {
  type: "error";
  code: "SESSION_NOT_FOUND" | "SESSION_EXPIRED" | "SESSION_LOCKED" | "RATE_LIMITED" | "INVALID_MESSAGE";
  message: string;
}

export type ServerMessage =
  | SessionInitedMsg
  | ClinicianJoinedMsg
  | PatientKeyMsg
  | RelayedMsg
  | ErrorMsg;
