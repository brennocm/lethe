// Package ipc is the daemon's local control channel (spec §17): JSON-RPC 2.0 over a Unix
// socket, one message per line, peers authenticated by SO_PEERCRED, sensitive methods proven
// with an HMAC of a single-use nonce under a key derived from the baseline passphrase.
package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
)

// MaxMessage is the largest accepted line, newline included; a longer one closes the connection.
const MaxMessage = 64 << 10

// Class of a method (spec §17.2).
type Class int

const (
	ClassRead Class = iota + 1
	ClassSafe
	ClassSensitive
	ClassAgent // only the session agent spawned by the daemon
)

// Methods is the closed method table. alert.ack is SAFE for WARNING/INFO and SENSITIVE for
// CRITICAL; the handler enforces that with RequireAuth.
var Methods = map[string]Class{
	"auth.challenge":             ClassRead,
	"status.get":                 ClassRead,
	"events.subscribe":           ClassRead,
	"events.query":               ClassRead,
	"discovery.get":              ClassRead,
	"heartbeat":                  ClassRead,
	"panic.engage":               ClassSafe,
	"selftest.run":               ClassSafe,
	"alert.ack":                  ClassSafe,
	"agent.report":               ClassAgent,
	"session.arm":                ClassSensitive,
	"session.disarm":             ClassSensitive,
	"panic.release":              ClassSensitive,
	"discovery.confirm_endpoint": ClassSensitive,
}

// Auth proves knowledge of the passphrase for one call.
type Auth struct {
	Nonce []byte `json:"nonce"`
	MAC   []byte `json:"mac"`
}

// Request is one call. Auth is an extension member, outside params, so the MAC covers params.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Auth    *Auth           `json:"auth,omitempty"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("ipc error %d: %s", e.Code, e.Message) }

// Error codes: JSON-RPC standard ones plus the lethe range (-32000…-32099).
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
	CodeDenied         = -32001 // peer or role not allowed
	CodeAuth           = -32002 // missing or wrong proof for a sensitive method
	CodeState          = -32003 // invalid session transition / precondition
)

// Response is a reply to a request (exactly one of Result, Error).
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *uint64         `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Notification is a server push (events.subscribe).
type Notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

// ErrTooLarge is returned for a message over MaxMessage.
var ErrTooLarge = errors.New("ipc: message exceeds 64 KiB")

// DecodeRequest parses and validates one request line (strict: unknown members are errors).
func DecodeRequest(line []byte) (Request, *Error) {
	var r Request
	if len(line) > MaxMessage {
		return r, &Error{Code: CodeInvalidRequest, Message: ErrTooLarge.Error()}
	}
	if err := strictUnmarshal(line, &r); err != nil {
		return r, &Error{Code: CodeParse, Message: "parse error"}
	}
	if r.JSONRPC != "2.0" || r.Method == "" {
		return r, &Error{Code: CodeInvalidRequest, Message: "invalid request"}
	}
	if _, ok := Methods[r.Method]; !ok {
		return r, &Error{Code: CodeMethodNotFound, Message: "method not found"}
	}
	if len(r.Params) > 0 && r.Params[0] != '{' {
		return r, &Error{Code: CodeInvalidParams, Message: "params must be an object"}
	}
	if r.Auth != nil && (len(r.Auth.Nonce) != NonceSize || len(r.Auth.MAC) != 32) {
		return r, &Error{Code: CodeInvalidRequest, Message: "malformed auth"}
	}
	return r, nil
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
