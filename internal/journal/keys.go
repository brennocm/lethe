package journal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
)

const keySize = chacha20poly1305.KeySize

func newKey() ([]byte, error) {
	k := make([]byte, keySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return k, nil
}

// wipe zeroes a secret buffer.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func wrapKey(key []byte, recipients []age.Recipient) (string, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return "", fmt.Errorf("wrap key: %w", err)
	}
	if _, err := w.Write(key); err != nil {
		return "", fmt.Errorf("wrap key: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("wrap key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func unwrapKey(wrapped string, identities []age.Identity) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped key: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(raw), identities...)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}
	k, err := io.ReadAll(io.LimitReader(r, keySize+1))
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}
	if len(k) != keySize {
		return nil, errors.New("unwrap key: wrong key size")
	}
	return k, nil
}

// Fingerprint is the operator-facing anchor of a session public key: the first 128 bits of
// SHA-256(pubkey) as 8 groups of 4 hex digits (spec §14.2).
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	h := hex.EncodeToString(sum[:16])
	groups := make([]string, 0, 8)
	for i := 0; i < len(h); i += 4 {
		groups = append(groups, h[i:i+4])
	}
	return strings.Join(groups, "-")
}

// NormalizeFingerprint makes user input comparable (case, separators).
func NormalizeFingerprint(s string) string {
	s = strings.ToLower(s)
	return strings.NewReplacer("-", "", ":", "", " ", "").Replace(s)
}

// checkpointMessage is what a checkpoint or session.end signs.
func checkpointMessage(session string, uptoSeq uint64, uptoHash string) []byte {
	return []byte("lethe-checkpoint-v1\x00" + session + "\x00" + strconv.FormatUint(uptoSeq, 10) + "\x00" + uptoHash)
}

// sealField encrypts a sensitive field value with the sensitive key (spec §14.3).
func sealField(key []byte, session string, plaintext []byte) (map[string]any, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, []byte("lethe-field-v1\x00"+session))
	return map[string]any{
		"enc": "s1",
		"n":   base64.StdEncoding.EncodeToString(nonce),
		"ct":  base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// ErrNotSealed is returned by OpenField for values that are not sealed fields.
var ErrNotSealed = errors.New("value is not a sealed field")

func openField(key []byte, session string, v any) ([]byte, error) {
	m, ok := v.(map[string]any)
	if !ok || m["enc"] != "s1" {
		return nil, ErrNotSealed
	}
	ns, _ := m["n"].(string)
	cs, _ := m["ct"].(string)
	nonce, err1 := base64.StdEncoding.DecodeString(ns)
	ct, err2 := base64.StdEncoding.DecodeString(cs)
	if err := errors.Join(err1, err2); err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("malformed sealed field: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, []byte("lethe-field-v1\x00"+session))
	if err != nil {
		return nil, fmt.Errorf("open sealed field: %w", err)
	}
	return pt, nil
}
