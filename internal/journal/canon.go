// Package journal writes and verifies the encrypted, hash-chained, signed session log (spec §14).
//
// Layout of a session directory:
//
//	segment-000001.lseg   header line (JSON) + sealed records + trailer (when closed)
//	segment-000002.lseg   ...
//
// Each record is u32be(len) || nonce(24) || XChaCha20-Poly1305(JCS(event)), with associated data
// SHA-256(header line) || u64be(record index). A closed segment ends with a trailer
// "LETHEEND" || u64be(count) || nonce(24) || tag(16) that authenticates the record count, so a
// cleanly closed segment can never be passed off as a crash-truncated one.
package journal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"

	"lethe/internal/contracts"
)

// ZeroHash is the "prev" of the first event of a session.
const ZeroHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Canonical returns the RFC 8785 (JCS) form of ev.
//
// Numbers go through IEEE-754 doubles in JCS, so integers above 2^53 (mono_ns after ~104 days of
// uptime) lose precision. That is deterministic on both write and verify, and ordering is proven by
// seq and the chain, never by mono_ns.
func Canonical(ev contracts.Event) ([]byte, error) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("marshal event: %w", err)
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize event: %w", err)
	}
	return out, nil
}

// ChainHash computes hash = SHA-256(prev || JCS(event without "hash")) (spec §14.2).
func ChainHash(ev contracts.Event) (string, error) {
	ev.Hash = ""
	c, err := Canonical(ev)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(ev.Prev))
	h.Write(c)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
