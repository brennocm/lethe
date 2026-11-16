package ipc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/gowebpki/jcs"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/sys/unix"
)

// NonceSize, nonce lifetime and the failure budget (spec §17.3).
const (
	NonceSize  = 32
	nonceTTL   = 30 * time.Second
	failLimit  = 5
	failWindow = 5 * time.Minute
	maxNonces  = 64
	scryptN    = 1 << 15
	scryptR    = 8
	scryptP    = 1
	SaltSize   = 16
	keySize    = 32
)

// Errors of the proof check.
var (
	ErrNoProof      = errors.New("this method requires a passphrase proof")
	ErrBadProof     = errors.New("passphrase proof rejected")
	ErrUnknownNonce = errors.New("unknown, used or expired nonce")
	ErrLocked       = errors.New("sensitive actions are locked for 5 minutes after 5 wrong passphrase proofs (SELF-006); wait and try again")
)

// FailLimit and FailWindow are the failure budget of spec §17.3 (SELF-006).
const (
	FailLimit  = failLimit
	FailWindow = failWindow
)

// DeriveKey is K = scrypt(passphrase, session salt). The caller wipes passphrase.
func DeriveKey(passphrase, salt []byte) ([]byte, error) {
	return scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, keySize)
}

// MAC is HMAC-SHA256(K, nonce ‖ method ‖ JCS(params)).
func MAC(key, nonce []byte, method string, params json.RawMessage) ([]byte, error) {
	canon := []byte("{}")
	if len(bytes.TrimSpace(params)) > 0 {
		c, err := jcs.Transform(params)
		if err != nil {
			return nil, err
		}
		canon = c
	}
	m := hmac.New(sha256.New, key)
	m.Write(nonce)
	m.Write([]byte(method))
	m.Write(canon)
	return m.Sum(nil), nil
}

// Authenticator issues nonces and checks proofs. The key lives in locked memory.
type Authenticator struct {
	mu      sync.Mutex
	key     []byte
	now     func() time.Time
	nonces  map[string]time.Time
	fails   []time.Time
	onLimit func()
	locked  time.Time // sensitive methods refused until then (SELF-006 under guard off)
}

// LockFor refuses every proof for d, without counting the refusals as new failures.
func (a *Authenticator) LockFor(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.locked = a.now().Add(d)
}

// LockedUntil is the end of the current lock (zero when not locked).
func (a *Authenticator) LockedUntil() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.now().Before(a.locked) {
		return a.locked
	}
	return time.Time{}
}

// NewAuthenticator takes ownership of key (mlocked here, wiped by Close). onLimit runs once
// each time the failure budget is exhausted (the daemon engages panic).
func NewAuthenticator(key []byte, now func() time.Time, onLimit func()) *Authenticator {
	_ = unix.Mlock(key) // best effort; CAP_IPC_LOCK raises the limit (§19.3)
	return &Authenticator{key: key, now: now, nonces: map[string]time.Time{}, onLimit: onLimit}
}

// Challenge returns a fresh single-use nonce.
func (a *Authenticator) Challenge() ([]byte, error) {
	n := make([]byte, NonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, t := range a.nonces {
		if now.Sub(t) > nonceTTL {
			delete(a.nonces, k)
		}
	}
	if len(a.nonces) >= maxNonces {
		return nil, errors.New("too many outstanding challenges")
	}
	a.nonces[string(n)] = now
	return n, nil
}

// Verify consumes the nonce and checks the MAC. Every failure counts towards the budget.
func (a *Authenticator) Verify(method string, params json.RawMessage, p *Auth) error {
	if !a.LockedUntil().IsZero() {
		return ErrLocked
	}
	if p == nil {
		a.fail()
		return ErrNoProof
	}
	a.mu.Lock()
	issued, ok := a.nonces[string(p.Nonce)]
	delete(a.nonces, string(p.Nonce))
	now := a.now()
	if !ok || now.Sub(issued) > nonceTTL || a.key == nil {
		a.mu.Unlock()
		a.fail()
		return ErrUnknownNonce
	}
	// Under the lock: Close wipes the key in place.
	want, err := MAC(a.key, p.Nonce, method, params)
	a.mu.Unlock()
	if err != nil || !hmac.Equal(want, p.MAC) {
		a.fail()
		return ErrBadProof
	}
	return nil
}

func (a *Authenticator) fail() {
	a.mu.Lock()
	now := a.now()
	kept := a.fails[:0]
	for _, t := range a.fails {
		if now.Sub(t) < failWindow {
			kept = append(kept, t)
		}
	}
	a.fails = append(kept, now)
	trip := len(a.fails) >= failLimit
	if trip {
		a.fails = nil
	}
	a.mu.Unlock()
	if trip && a.onLimit != nil {
		a.onLimit()
	}
}

// Close wipes the key.
func (a *Authenticator) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.key {
		a.key[i] = 0
	}
	_ = unix.Munlock(a.key)
	a.key = nil
}
