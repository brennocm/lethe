package journal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	"lethe/internal/contracts"
)

// Config configures a session writer.
type Config struct {
	Dir                 string // session directory; created 0700, must not exist or be empty
	Session             string // UUID
	Recipients          []age.Recipient
	SensitiveRecipients []age.Recipient // nil = Recipients
	Now                 func() time.Time
	Mono                func() int64
	RotateEvery         time.Duration // default 5m
	RotateEvents        int           // default 10000
	CheckpointEvery     time.Duration // default 60s
	SyncEvery           time.Duration // default 1s
	StartData           map[string]any
	// ReaderGID, when >= 0, lets that group read the session: the directory becomes
	// root:gid 02750 (setgid, so segments inherit the group) and segments 0640. The daemon
	// keeps no CAP_DAC_OVERRIDE/CAP_CHOWN after start-up, so this is how the operator reads.
	ReaderGID int
}

// Writer appends events to a session. It is safe for concurrent use.
type Writer struct {
	mu        sync.Mutex
	cfg       Config
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	dataKey   []byte
	sensKey   []byte
	keyWrap   string
	sensWrap  string
	seq       uint64 // next seq to assign
	prevHash  string
	segment   int
	file      *os.File
	hdrHash   [32]byte
	segCount  uint64
	segStart  time.Time
	lastCkpt  time.Time
	lastSync  time.Time
	dirty     bool
	sinceCkpt int
	closed    bool
}

// ErrClosed is returned when appending to a closed writer.
var ErrClosed = errors.New("journal closed")

// Open creates the session directory, generates the session keys and writes session.start.
func Open(cfg Config) (*Writer, error) {
	if len(cfg.Recipients) == 0 {
		return nil, errors.New("journal: at least one recipient is required")
	}
	if cfg.SensitiveRecipients == nil {
		cfg.SensitiveRecipients = cfg.Recipients
	}
	if cfg.Now == nil || cfg.Mono == nil {
		return nil, errors.New("journal: Now and Mono clocks are required")
	}
	if cfg.RotateEvery == 0 {
		cfg.RotateEvery = 5 * time.Minute
	}
	if cfg.RotateEvents == 0 {
		cfg.RotateEvents = 10000
	}
	if cfg.CheckpointEvery == 0 {
		cfg.CheckpointEvery = time.Minute
	}
	if cfg.SyncEvery == 0 {
		cfg.SyncEvery = time.Second
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("journal: create %s: %w", cfg.Dir, err)
	}
	if cfg.ReaderGID > 0 {
		if err := os.Chown(cfg.Dir, -1, cfg.ReaderGID); err != nil {
			return nil, fmt.Errorf("journal: group of %s: %w", cfg.Dir, err)
		}
		if err := os.Chmod(cfg.Dir, 0o750|os.ModeSetgid); err != nil { // #nosec G302 -- group read is the point
			return nil, fmt.Errorf("journal: mode of %s: %w", cfg.Dir, err)
		}
	}
	if entries, err := os.ReadDir(cfg.Dir); err != nil || len(entries) > 0 {
		return nil, fmt.Errorf("journal: session directory %s must be empty", cfg.Dir)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("journal: session key: %w", err)
	}
	w := &Writer{cfg: cfg, priv: priv, pub: pub, prevHash: ZeroHash}
	if w.dataKey, err = newKey(); err != nil {
		return nil, err
	}
	if w.sensKey, err = newKey(); err != nil {
		return nil, err
	}
	if w.keyWrap, err = wrapKey(w.dataKey, cfg.Recipients); err != nil {
		return nil, err
	}
	if w.sensWrap, err = wrapKey(w.sensKey, cfg.SensitiveRecipients); err != nil {
		return nil, err
	}
	now := cfg.Now()
	w.lastCkpt, w.lastSync = now, now
	if err := w.openSegment(now); err != nil {
		return nil, err
	}
	data := map[string]any{}
	for k, v := range cfg.StartData {
		data[k] = v
	}
	data["pubkey"] = base64.StdEncoding.EncodeToString(pub)
	data["fingerprint"] = Fingerprint(pub)
	if _, err := w.appendLocked(contracts.Event{Type: contracts.EvSessionStart, Source: contracts.SourceDaemon, Data: data}); err != nil {
		return nil, err
	}
	return w, nil
}

// PublicKey returns the session signing key.
func (w *Writer) PublicKey() ed25519.PublicKey { return w.pub }

// Fingerprint returns the anchor the operator must record outside the machine.
func (w *Writer) Fingerprint() string { return Fingerprint(w.pub) }

// Seal encrypts a sensitive value for the sensitive recipients; put the result in Event.Data.
func (w *Writer) Seal(plaintext string) (map[string]any, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrClosed
	}
	return sealField(w.sensKey, w.cfg.Session, []byte(plaintext))
}

// Append fills v, seq, ts, mono_ns, session, prev and hash, then persists the event.
func (w *Writer) Append(ev contracts.Event) (contracts.Event, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ev, ErrClosed
	}
	if ev.Type == contracts.EvSessionStart || ev.Type == contracts.EvSessionEnd || ev.Type == contracts.EvSessionCheckpoint {
		return ev, fmt.Errorf("journal: %s is written by the journal itself", ev.Type)
	}
	out, err := w.appendLocked(ev)
	if err != nil {
		return out, err
	}
	return out, w.maintainLocked()
}

// Tick performs time-based work: periodic checkpoint, fsync and rotation. Call it every second.
func (w *Writer) Tick() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	return w.maintainLocked()
}

// Close writes a final signed session.end, the segment trailer, and wipes the keys.
func (w *Writer) Close(endData map[string]any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	data := map[string]any{}
	for k, v := range endData {
		data[k] = v
	}
	w.signInto(data)
	_, err := w.appendLocked(contracts.Event{Type: contracts.EvSessionEnd, Source: contracts.SourceDaemon, Data: data})
	err = errors.Join(err, w.closeSegment())
	w.closed = true
	wipe(w.dataKey)
	wipe(w.sensKey)
	wipe(w.priv)
	return err
}

func (w *Writer) signInto(data map[string]any) {
	upto := w.seq - 1
	sig := ed25519.Sign(w.priv, checkpointMessage(w.cfg.Session, upto, w.prevHash))
	data["upto_seq"] = upto
	data["upto_hash"] = w.prevHash
	data["sig"] = base64.StdEncoding.EncodeToString(sig)
}

func (w *Writer) maintainLocked() error {
	now := w.cfg.Now()
	if w.sinceCkpt > 0 && now.Sub(w.lastCkpt) >= w.cfg.CheckpointEvery {
		if err := w.checkpointLocked(now); err != nil {
			return err
		}
	}
	if w.segCount >= uint64(w.cfg.RotateEvents) || (w.segCount > 1 && now.Sub(w.segStart) >= w.cfg.RotateEvery) {
		if err := w.rotateLocked(now); err != nil {
			return err
		}
	}
	if w.dirty && now.Sub(w.lastSync) >= w.cfg.SyncEvery {
		return w.syncLocked(now)
	}
	return nil
}

func (w *Writer) checkpointLocked(now time.Time) error {
	data := map[string]any{}
	w.signInto(data)
	if _, err := w.appendLocked(contracts.Event{Type: contracts.EvSessionCheckpoint, Source: contracts.SourceDaemon, Data: data}); err != nil {
		return err
	}
	w.lastCkpt, w.sinceCkpt = now, 0
	return w.syncLocked(now)
}

func (w *Writer) rotateLocked(now time.Time) error {
	if w.sinceCkpt > 0 {
		if err := w.checkpointLocked(now); err != nil {
			return err
		}
	}
	if err := w.closeSegment(); err != nil {
		return err
	}
	return w.openSegment(now)
}

// mustSync lists event types that are fsynced immediately (spec §14.3).
func mustSync(ev contracts.Event) bool {
	return ev.Severity == contracts.SeverityCritical || ev.Type == contracts.EvAlertAck ||
		ev.Type == contracts.EvResponseExecuted || strings.HasPrefix(string(ev.Type), "session.")
}

func (w *Writer) appendLocked(ev contracts.Event) (contracts.Event, error) {
	now := w.cfg.Now()
	ev.V = 1
	ev.Seq = w.seq
	ev.TS = now.UTC().Truncate(time.Microsecond)
	ev.MonoNS = w.cfg.Mono()
	ev.Session = w.cfg.Session
	ev.Prev = w.prevHash
	if ev.Source == "" {
		ev.Source = contracts.SourceDaemon
	}
	h, err := ChainHash(ev)
	if err != nil {
		return ev, err
	}
	ev.Hash = h
	canon, err := Canonical(ev)
	if err != nil {
		return ev, err
	}
	if len(canon) > maxRecordSize {
		return ev, fmt.Errorf("journal: event of %d bytes exceeds limit", len(canon))
	}
	rec, err := sealRecord(w.dataKey, w.hdrHash, w.segCount, canon)
	if err != nil {
		return ev, err
	}
	if _, err := w.file.Write(rec); err != nil {
		return ev, fmt.Errorf("journal: write: %w", err)
	}
	w.seq++
	w.segCount++
	w.sinceCkpt++
	w.prevHash = h
	w.dirty = true
	if mustSync(ev) {
		if err := w.syncLocked(now); err != nil {
			return ev, err
		}
	}
	return ev, nil
}

func (w *Writer) syncLocked(now time.Time) error {
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("journal: fsync: %w", err)
	}
	w.lastSync, w.dirty = now, false
	return nil
}

func (w *Writer) openSegment(now time.Time) error {
	w.segment++
	hdr := Header{Format: formatName, V: formatVersion, Session: w.cfg.Session, Segment: w.segment, KeyWrap: w.keyWrap, SensitiveKeyWrap: w.sensWrap}
	line, err := json.Marshal(hdr)
	if err != nil {
		return err
	}
	path := filepath.Join(w.cfg.Dir, segmentName(w.segment))
	mode := os.FileMode(0o600)
	if w.cfg.ReaderGID > 0 {
		mode = 0o640
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, mode) // #nosec G304 G302 -- our own session dir
	if err != nil {
		return fmt.Errorf("journal: create segment: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("journal: write header: %w", err)
	}
	w.file, w.hdrHash, w.segCount, w.segStart = f, headerHash(line), 0, now
	return nil
}

func (w *Writer) closeSegment() error {
	tr, err := sealTrailer(w.dataKey, w.hdrHash, w.segCount)
	if err != nil {
		return err
	}
	_, werr := w.file.Write(tr)
	serr := w.file.Sync()
	cerr := w.file.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return fmt.Errorf("journal: close segment: %w", err)
	}
	return nil
}
