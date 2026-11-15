package journal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"filippo.io/age"

	"lethe/internal/contracts"
)

const maxHeaderSize = 64 << 10

// IntegrityError reports tampering or corruption. The CLI maps it to exit code 4.
type IntegrityError struct {
	Segment int    // 1-based segment number (0 = session level)
	Seq     int64  // event seq, -1 when unknown
	Reason  string // human-readable cause
}

func (e *IntegrityError) Error() string {
	switch {
	case e.Segment > 0 && e.Seq >= 0:
		return fmt.Sprintf("integrity: segment %d, seq %d: %s", e.Segment, e.Seq, e.Reason)
	case e.Segment > 0:
		return fmt.Sprintf("integrity: segment %d: %s", e.Segment, e.Reason)
	default:
		return "integrity: " + e.Reason
	}
}

func integrity(seg int, seq int64, format string, a ...any) error {
	return &IntegrityError{Segment: seg, Seq: seq, Reason: fmt.Sprintf(format, a...)}
}

// IsIntegrity reports whether err is an integrity failure.
func IsIntegrity(err error) bool {
	var ie *IntegrityError
	return errors.As(err, &ie)
}

// Session is a decrypted session journal.
type Session struct {
	ID             string
	Dir            string
	Events         []contracts.Event
	Segments       int
	TruncatedTail  bool // the last segment ends in a partially written record (crash)
	MissingTrailer bool // the session ended but the last trailer is absent (crash while closing)
	sensWrap       string
	sensKey        []byte
}

// Read decrypts every segment of the session in dir with the log identities.
func Read(dir string, identities []age.Identity) (*Session, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "segment-*.lseg"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, integrity(0, -1, "no segments in %s", dir)
	}
	sort.Strings(paths)
	s := &Session{Dir: dir, Segments: len(paths)}
	var dataKey []byte
	defer func() { wipe(dataKey) }()
	ended := false
	for i, p := range paths {
		segNo := i + 1
		if filepath.Base(p) != segmentName(segNo) {
			return nil, integrity(segNo, -1, "missing or misnamed segment (found %s)", filepath.Base(p))
		}
		if ended {
			return nil, integrity(segNo, -1, "segment after session.end")
		}
		raw, err := os.ReadFile(p) // #nosec G304 -- operator-chosen session directory
		if err != nil {
			return nil, err
		}
		hdr, hdrLine, body, err := splitHeader(raw, segNo)
		if err != nil {
			return nil, err
		}
		if s.ID == "" {
			s.ID, s.sensWrap = hdr.Session, hdr.SensitiveKeyWrap
			if dataKey, err = unwrapKey(hdr.KeyWrap, identities); err != nil {
				return nil, integrity(segNo, -1, "cannot open the session key (wrong identity or tampered header): %v", err)
			}
		} else if hdr.Session != s.ID || hdr.SensitiveKeyWrap != s.sensWrap {
			return nil, integrity(segNo, -1, "header does not belong to session %s", s.ID)
		}
		k, err := unwrapKey(hdr.KeyWrap, identities)
		if err != nil || !bytes.Equal(k, dataKey) {
			wipe(k)
			return nil, integrity(segNo, -1, "segment key differs from the session key")
		}
		wipe(k)
		last := i == len(paths)-1
		evs, segEnded, err := s.readRecords(dataKey, headerHash(hdrLine), body, segNo, last)
		if err != nil {
			return nil, err
		}
		s.Events = append(s.Events, evs...)
		ended = segEnded
	}
	return s, nil
}

func splitHeader(raw []byte, segNo int) (Header, []byte, []byte, error) {
	limit := min(len(raw), maxHeaderSize)
	nl := bytes.IndexByte(raw[:limit], '\n')
	if nl < 0 {
		return Header{}, nil, nil, integrity(segNo, -1, "header line missing or too long")
	}
	line := raw[:nl]
	var hdr Header
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&hdr); err != nil || dec.InputOffset() != int64(len(line)) {
		return Header{}, nil, nil, integrity(segNo, -1, "malformed header")
	}
	if hdr.Format != formatName || hdr.V != formatVersion || hdr.Segment != segNo {
		return Header{}, nil, nil, integrity(segNo, -1, "unexpected header (format %q v%d segment %d)", hdr.Format, hdr.V, hdr.Segment)
	}
	return hdr, line, raw[nl+1:], nil
}

func (s *Session) readRecords(key []byte, hh [32]byte, body []byte, segNo int, last bool) ([]contracts.Event, bool, error) {
	recs, closed := body, false
	var wantCount uint64
	if len(body) >= trailerSize {
		if n, ok := parseTrailer(key, hh, body[len(body)-trailerSize:]); ok {
			recs, closed, wantCount = body[:len(body)-trailerSize], true, n
		}
	}
	if !closed && !last {
		return nil, false, integrity(segNo, -1, "segment is not closed but is not the last one")
	}
	var out []contracts.Event
	ended := false
	var idx uint64
	for off := 0; off < len(recs); {
		if ended {
			return nil, false, integrity(segNo, -1, "data after session.end")
		}
		rest := recs[off:]
		if len(rest) < 4 {
			if closed {
				return nil, false, integrity(segNo, -1, "stray bytes before trailer")
			}
			s.TruncatedTail = true
			break
		}
		n := int(binary.BigEndian.Uint32(rest))
		if n > len(rest)-4 {
			if closed {
				return nil, false, integrity(segNo, -1, "record %d length exceeds segment", idx)
			}
			s.TruncatedTail = true
			break
		}
		pt, err := openRecord(key, hh, idx, rest[4:4+n])
		if err != nil {
			return nil, false, integrity(segNo, -1, "%v", err)
		}
		var ev contracts.Event
		if err := json.Unmarshal(pt, &ev); err != nil {
			return nil, false, integrity(segNo, -1, "record %d is not a valid event: %v", idx, err)
		}
		out = append(out, ev)
		ended = ev.Type == contracts.EvSessionEnd
		off += 4 + n
		idx++
	}
	if closed && idx != wantCount {
		return nil, false, integrity(segNo, -1, "trailer says %d records, found %d", wantCount, idx)
	}
	if ended && !closed {
		s.MissingTrailer = true
	}
	return out, ended, nil
}

// UnlockSensitive unwraps the sensitive-field key with the sensitive identities.
func (s *Session) UnlockSensitive(identities []age.Identity) error {
	k, err := unwrapKey(s.sensWrap, identities)
	if err != nil {
		return fmt.Errorf("sensitive fields: %w", err)
	}
	s.sensKey = k
	return nil
}

// Field decrypts a sealed field value (after UnlockSensitive).
func (s *Session) Field(v any) (string, error) {
	if s.sensKey == nil {
		return "", errors.New("sensitive fields are locked")
	}
	pt, err := openField(s.sensKey, s.ID, v)
	return string(pt), err
}

// Wipe zeroes the unlocked sensitive key.
func (s *Session) Wipe() { wipe(s.sensKey); s.sensKey = nil }
