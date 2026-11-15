package journal

import (
	"crypto/ed25519"
	"encoding/base64"

	"lethe/internal/contracts"
)

// Result summarizes a verified session.
type Result struct {
	Session        string `json:"session"`
	Events         int    `json:"events"`
	Segments       int    `json:"segments"`
	LastSeq        uint64 `json:"last_seq"`
	SignedUpTo     int64  `json:"signed_up_to"` // -1 when no checkpoint was written
	UnsignedTail   int    `json:"unsigned_tail"`
	Checkpoints    int    `json:"checkpoints"`
	Ended          bool   `json:"ended"`
	TruncatedTail  bool   `json:"truncated_tail"`
	MissingTrailer bool   `json:"missing_trailer"`
	Fingerprint    string `json:"fingerprint"`
	Anchored       bool   `json:"anchored"` // matched --expect-fingerprint
	FinalHash      string `json:"final_hash"`
}

// Warnings lists non-fatal conditions an operator must know about.
func (r Result) Warnings() []string {
	var w []string
	if r.TruncatedTail {
		w = append(w, "truncated_tail: the last record was partially written (crash)")
	}
	if !r.Ended {
		w = append(w, "session did not end cleanly (no session.end)")
	}
	if r.MissingTrailer {
		w = append(w, "missing_trailer: crash while closing the last segment")
	}
	if r.UnsignedTail > 0 {
		w = append(w, "events after the last signature are chained but not signed")
	}
	if !r.Anchored {
		w = append(w, "fingerprint not checked against an external anchor (--expect-fingerprint)")
	}
	return w
}

// Verify checks seq continuity, the hash chain, the session key and every signature.
func Verify(s *Session, expectFingerprint string) (Result, error) {
	r := Result{Session: s.ID, Segments: s.Segments, SignedUpTo: -1, TruncatedTail: s.TruncatedTail, MissingTrailer: s.MissingTrailer}
	if len(s.Events) == 0 {
		return r, integrity(0, -1, "session has no events")
	}
	first := s.Events[0]
	if first.Type != contracts.EvSessionStart || first.Prev != ZeroHash {
		return r, integrity(1, 0, "first event must be session.start with the zero prev hash")
	}
	pubB64 := first.Str("pubkey")
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return r, integrity(1, 0, "invalid session public key")
	}
	r.Fingerprint = Fingerprint(pub)
	if first.Str("fingerprint") != r.Fingerprint {
		return r, integrity(1, 0, "recorded fingerprint does not match the public key")
	}
	if expectFingerprint != "" {
		if NormalizeFingerprint(expectFingerprint) != NormalizeFingerprint(r.Fingerprint) {
			return r, integrity(0, -1, "fingerprint %s does not match the external anchor", r.Fingerprint)
		}
		r.Anchored = true
	}
	prev := ZeroHash
	for i, ev := range s.Events {
		seq := int64(i)
		if ev.Seq != uint64(i) {
			return r, integrity(0, seq, "seq gap: found %d", ev.Seq)
		}
		if ev.Session != s.ID {
			return r, integrity(0, seq, "event belongs to another session")
		}
		if ev.Prev != prev {
			return r, integrity(0, seq, "broken chain: prev does not match the previous hash")
		}
		h, err := ChainHash(ev)
		if err != nil || h != ev.Hash {
			return r, integrity(0, seq, "hash mismatch")
		}
		if ev.Type == contracts.EvSessionStart && i != 0 {
			return r, integrity(0, seq, "second session.start")
		}
		if ev.Type == contracts.EvSessionCheckpoint || ev.Type == contracts.EvSessionEnd {
			if err := checkSignature(pub, s.ID, ev); err != nil {
				return r, err
			}
			r.Checkpoints++
			r.SignedUpTo = seq - 1
		}
		if ev.Type == contracts.EvSessionEnd && i != len(s.Events)-1 {
			return r, integrity(0, seq, "events after session.end")
		}
		prev = ev.Hash
	}
	last := s.Events[len(s.Events)-1]
	r.Events, r.LastSeq, r.FinalHash = len(s.Events), last.Seq, last.Hash
	r.Ended = last.Type == contracts.EvSessionEnd
	r.UnsignedTail = int(int64(last.Seq) - r.SignedUpTo)
	if last.Type == contracts.EvSessionEnd || last.Type == contracts.EvSessionCheckpoint {
		r.UnsignedTail = 0 // the signature event itself carries no content to protect
	}
	return r, nil
}

func checkSignature(pub ed25519.PublicKey, session string, ev contracts.Event) error {
	seq := int64(ev.Seq)
	upto, ok := ev.Data["upto_seq"].(float64)
	if !ok || int64(upto) != seq-1 || ev.Str("upto_hash") != ev.Prev {
		return integrity(0, seq, "%s does not cover the preceding event", ev.Type)
	}
	sig, err := base64.StdEncoding.DecodeString(ev.Str("sig"))
	if err != nil || !ed25519.Verify(pub, checkpointMessage(session, uint64(upto), ev.Prev), sig) {
		return integrity(0, seq, "invalid signature on %s", ev.Type)
	}
	return nil
}
