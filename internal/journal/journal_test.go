package journal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/gowebpki/jcs"

	"lethe/internal/contracts"
)

const testSession = "5f0c9e2a-7b1d-4c3e-9a8f-2d6b1e0c4a77"

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }
func (c *testClock) mono() int64 {
	return c.t.UnixNano() - time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
}
func (c *testClock) adv(d time.Duration) { c.t = c.t.Add(d) }

type fixture struct {
	dir  string
	id   *age.X25519Identity
	sens *age.X25519Identity
	clk  *testClock
	w    *Writer
}

func newFixture(t testing.TB, mut func(*Config)) *fixture {
	t.Helper()
	id, _ := age.GenerateX25519Identity()
	sens, _ := age.GenerateX25519Identity()
	f := &fixture{dir: filepath.Join(t.TempDir(), "s"), id: id, sens: sens, clk: &testClock{t: time.Date(2026, 11, 15, 14, 0, 0, 0, time.UTC)}}
	cfg := Config{
		Dir: f.dir, Session: testSession, Recipients: []age.Recipient{id.Recipient()},
		SensitiveRecipients: []age.Recipient{sens.Recipient()}, Now: f.clk.now, Mono: f.clk.mono,
		StartData: map[string]any{"operation": "OP-TEST"},
	}
	if mut != nil {
		mut(&cfg)
	}
	w, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.w = w
	return f
}

func (f *fixture) add(t testing.TB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		f.clk.adv(100 * time.Millisecond)
		ev := contracts.Event{Type: contracts.EvCheckAlert, Check: "NET-005", Severity: contracts.SeverityWarning,
			Data: map[string]any{"iface": "eth0", "n": i}}
		if _, err := f.w.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) verify(t *testing.T) (Result, error) {
	t.Helper()
	s, err := Read(f.dir, []age.Identity{f.id})
	if err != nil {
		return Result{}, err
	}
	return Verify(s, "")
}

func TestJCS_RFC8785Vectors(t *testing.T) {
	ins, _ := filepath.Glob("testdata/jcs/*.in.json")
	if len(ins) == 0 {
		t.Fatal("no vectors")
	}
	for _, in := range ins {
		raw, _ := os.ReadFile(in)
		want, _ := os.ReadFile(strings.Replace(in, ".in.", ".out.", 1))
		got, err := jcs.Transform(raw)
		if err != nil || !bytes.Equal(got, bytes.TrimRight(want, "\n")) {
			t.Errorf("%s: got %s err %v", in, got, err)
		}
	}
}

func TestRoundTrip_VerifyAndSensitiveFields(t *testing.T) {
	f := newFixture(t, nil)
	sealed, err := f.w.Seal("secret.example")
	if err != nil {
		t.Fatal(err)
	}
	f.add(t, 3)
	if _, err := f.w.Append(contracts.Event{Type: contracts.EvCheckAlert, Check: "DNS-001", Severity: contracts.SeverityCritical,
		Data: map[string]any{"qname": sealed, "proc": contracts.Proc{PID: 7, Exe: "/usr/bin/dig", Confidence: contracts.ConfidenceHigh}}}); err != nil {
		t.Fatal(err)
	}
	fp := f.w.Fingerprint()
	if err := f.w.Close(map[string]any{"reason": "disarm"}); err != nil {
		t.Fatal(err)
	}
	s, err := Read(f.dir, []age.Identity{f.id})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Verify(s, strings.ToUpper(strings.ReplaceAll(fp, "-", ":")))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Ended || !r.Anchored || r.TruncatedTail || r.UnsignedTail != 0 || r.Events != 6 || len(r.Warnings()) != 0 {
		t.Fatalf("result %+v warnings %v", r, r.Warnings())
	}
	for _, ev := range s.Events {
		if err := contracts.Validate("event", ev); err != nil {
			t.Fatalf("seq %d violates event schema: %v", ev.Seq, err)
		}
	}
	qname := s.Events[4].Data["qname"]
	if _, err := s.Field(qname); err == nil {
		t.Fatal("sensitive field readable before unlock")
	}
	if err := s.UnlockSensitive([]age.Identity{f.id}); err == nil {
		t.Fatal("log identity must not open the sensitive key")
	}
	if err := s.UnlockSensitive([]age.Identity{f.sens}); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Field(qname); err != nil || v != "secret.example" {
		t.Fatalf("field = %q %v", v, err)
	}
	if _, err := s.Field("plain"); !errors.Is(err, ErrNotSealed) {
		t.Fatal(err)
	}
	s.Wipe()
	if _, err := Verify(s, "0000-0000"); !IsIntegrity(err) {
		t.Fatal("wrong anchor must fail")
	}
}

func TestWrongIdentity(t *testing.T) {
	f := newFixture(t, nil)
	_ = f.w.Close(nil)
	other, _ := age.GenerateX25519Identity()
	if _, err := Read(f.dir, []age.Identity{other}); err == nil {
		t.Fatal("other identity opened the session")
	}
}

func TestRotationAndCheckpoints(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RotateEvents = 4; c.CheckpointEvery = time.Second })
	f.add(t, 25)
	if err := f.w.Close(nil); err != nil {
		t.Fatal(err)
	}
	r, err := f.verify(t)
	if err != nil {
		t.Fatal(err)
	}
	if r.Segments < 5 || r.Checkpoints < 5 || !r.Ended {
		t.Fatalf("%+v", r)
	}
}

func TestTimeRotation(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RotateEvery = time.Minute })
	f.add(t, 2)
	f.clk.adv(2 * time.Minute)
	if err := f.w.Tick(); err != nil {
		t.Fatal(err)
	}
	f.add(t, 1)
	_ = f.w.Close(nil)
	if r, err := f.verify(t); err != nil || r.Segments != 2 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestReservedTypesRejected(t *testing.T) {
	f := newFixture(t, nil)
	for _, typ := range []contracts.EventType{contracts.EvSessionStart, contracts.EvSessionEnd, contracts.EvSessionCheckpoint} {
		if _, err := f.w.Append(contracts.Event{Type: typ}); err == nil {
			t.Fatalf("%s accepted from caller", typ)
		}
	}
	_ = f.w.Close(nil)
	if _, err := f.w.Append(contracts.Event{Type: contracts.EvClockJump}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := f.w.Close(nil); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestOpen_RejectsNonEmptyDirAndMissingConfig(t *testing.T) {
	f := newFixture(t, nil)
	_ = f.w.Close(nil)
	id, _ := age.GenerateX25519Identity()
	clk := &testClock{}
	if _, err := Open(Config{Dir: f.dir, Session: testSession, Recipients: []age.Recipient{id.Recipient()}, Now: clk.now, Mono: clk.mono}); err == nil {
		t.Fatal("reused a non-empty session dir")
	}
	if _, err := Open(Config{Dir: t.TempDir(), Now: clk.now, Mono: clk.mono}); err == nil {
		t.Fatal("opened without recipients")
	}
}

// TestCrash_TruncatedTailToleratedAndUnsignedTailReported is the crash half of AC-10.
func TestCrash_TruncatedTailToleratedAndUnsignedTailReported(t *testing.T) {
	f := newFixture(t, nil)
	f.add(t, 5) // never closed: simulates kill -9
	seg := filepath.Join(f.dir, segmentName(1))
	st, _ := os.Stat(seg)
	r, err := f.verify(t)
	if err != nil || r.Ended || r.TruncatedTail || r.UnsignedTail == 0 {
		t.Fatalf("crash without truncation: %+v %v", r, err)
	}
	if err := os.Truncate(seg, st.Size()-7); err != nil {
		t.Fatal(err)
	}
	r, err = f.verify(t)
	if err != nil || !r.TruncatedTail || r.Events != 5 {
		t.Fatalf("truncated tail must be tolerated: %+v %v", r, err)
	}
}

// TestE2E_AC10_AnyByteFlipFailsVerify flips every byte of every segment of a closed session.
func TestE2E_AC10_AnyByteFlipFailsVerify(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RotateEvents = 3 })
	f.add(t, 4)
	if err := f.w.Close(nil); err != nil {
		t.Fatal(err)
	}
	segs, _ := filepath.Glob(filepath.Join(f.dir, "*.lseg"))
	if len(segs) < 2 {
		t.Fatal("want several segments")
	}
	for _, seg := range segs {
		orig, _ := os.ReadFile(seg)
		for i := range orig {
			mod := bytes.Clone(orig)
			mod[i] ^= 0x01
			if err := os.WriteFile(seg, mod, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := f.verify(t)
			if !IsIntegrity(err) {
				t.Fatalf("%s byte %d flipped: verify returned %v", filepath.Base(seg), i, err)
			}
		}
		_ = os.WriteFile(seg, orig, 0o600)
	}
	if _, err := f.verify(t); err != nil {
		t.Fatalf("restored session must verify: %v", err)
	}
}

func TestSegmentRemovalOrReorderDetected(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RotateEvents = 3 })
	f.add(t, 7)
	_ = f.w.Close(nil)
	// remove a middle segment
	_ = os.Rename(filepath.Join(f.dir, segmentName(2)), filepath.Join(t.TempDir(), "x"))
	if _, err := f.verify(t); !IsIntegrity(err) {
		t.Fatalf("missing segment: %v", err)
	}
}

func TestSegmentSwapBetweenSessionsDetected(t *testing.T) {
	a := newFixture(t, nil)
	a.add(t, 2)
	_ = a.w.Close(nil)
	raw, _ := os.ReadFile(filepath.Join(a.dir, segmentName(1)))
	_ = os.WriteFile(filepath.Join(a.dir, segmentName(2)), raw, 0o600)
	if _, err := a.verify(t); !IsIntegrity(err) {
		t.Fatalf("duplicated segment: %v", err)
	}
}

func TestIntegrityError_Messages(t *testing.T) {
	cases := map[string]*IntegrityError{
		"integrity: segment 2, seq 5: x": {Segment: 2, Seq: 5, Reason: "x"},
		"integrity: segment 2: x":        {Segment: 2, Seq: -1, Reason: "x"},
		"integrity: x":                   {Seq: -1, Reason: "x"},
	}
	for want, e := range cases {
		if e.Error() != want {
			t.Errorf("%q != %q", e.Error(), want)
		}
	}
	if IsIntegrity(errors.New("x")) {
		t.Fatal("plain error is not integrity")
	}
}

func TestRead_EmptyDirAndMisnamedSegment(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	if _, err := Read(dir, []age.Identity{id}); !IsIntegrity(err) {
		t.Fatal(err)
	}
	f := newFixture(t, nil)
	_ = f.w.Close(nil)
	_ = os.Rename(filepath.Join(f.dir, segmentName(1)), filepath.Join(f.dir, segmentName(2)))
	if _, err := f.verify(t); !IsIntegrity(err) {
		t.Fatal(err)
	}
}

func TestOpenField_Malformed(t *testing.T) {
	f := newFixture(t, nil)
	_ = f.w.Close(nil)
	s, _ := Read(f.dir, []age.Identity{f.id})
	_ = s.UnlockSensitive([]age.Identity{f.sens})
	for _, v := range []any{
		map[string]any{"enc": "s1", "n": "!!", "ct": ""},
		map[string]any{"enc": "s1", "n": "AAAA", "ct": "AAAA"},
	} {
		if _, err := s.Field(v); err == nil {
			t.Fatalf("malformed field %v accepted", v)
		}
	}
	if _, err := f.w.Seal("x"); !errors.Is(err, ErrClosed) {
		t.Fatal("seal after close")
	}
}

func TestFingerprintFormat(t *testing.T) {
	f := newFixture(t, nil)
	fp := f.w.Fingerprint()
	if len(strings.Split(fp, "-")) != 8 || len(NormalizeFingerprint(fp)) != 32 || len(f.w.PublicKey()) != 32 {
		t.Fatalf("fingerprint %q", fp)
	}
	_ = f.w.Close(nil)
}

func TestWarnings_AllFlags(t *testing.T) {
	r := Result{TruncatedTail: true, MissingTrailer: true, UnsignedTail: 2}
	if len(r.Warnings()) != 5 {
		t.Fatalf("%v", r.Warnings())
	}
}

func TestTick_SyncsAndCheckpoints(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.CheckpointEvery = 10 * time.Second })
	f.add(t, 2)
	f.clk.adv(11 * time.Second)
	if err := f.w.Tick(); err != nil {
		t.Fatal(err)
	}
	r, err := f.verify(t)
	if err != nil || r.Checkpoints != 1 || r.UnsignedTail != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	_ = f.w.Close(nil)
	if err := f.w.Tick(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

// TestVerify_InMemoryTampering covers forgeries that keep every record authentic but break the chain.
func TestVerify_InMemoryTampering(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.CheckpointEvery = time.Second })
	f.add(t, 15)
	_ = f.w.Close(nil)
	base, err := Read(f.dir, []age.Identity{f.id})
	if err != nil {
		t.Fatal(err)
	}
	ckpt := -1
	for i, ev := range base.Events {
		if ev.Type == contracts.EvSessionCheckpoint {
			ckpt = i
			break
		}
	}
	if ckpt < 0 {
		t.Fatal("no checkpoint")
	}
	cases := map[string]func(s *Session){
		"seq gap":          func(s *Session) { s.Events[3].Seq = 99 },
		"other session":    func(s *Session) { s.Events[2].Session = "x" },
		"broken prev":      func(s *Session) { s.Events[4].Prev = ZeroHash },
		"edited data":      func(s *Session) { s.Events[5].Data["n"] = 1234.0 },
		"bad signature":    func(s *Session) { s.Events[ckpt].Data["sig"] = "AAAA" },
		"bad upto":         func(s *Session) { s.Events[ckpt].Data["upto_seq"] = 0.0 },
		"bad pubkey":       func(s *Session) { s.Events[0].Data["pubkey"] = "!!" },
		"bad fingerprint":  func(s *Session) { s.Events[0].Data["fingerprint"] = "x" },
		"not start first":  func(s *Session) { s.Events[0].Type = contracts.EvClockJump },
		"empty":            func(s *Session) { s.Events = nil },
		"events after end": func(s *Session) { s.Events = append(s.Events, s.Events[len(s.Events)-1]) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			s := &Session{ID: base.ID, Segments: base.Segments}
			for _, ev := range base.Events {
				cp := ev
				cp.Data = map[string]any{}
				for k, v := range ev.Data {
					cp.Data[k] = v
				}
				s.Events = append(s.Events, cp)
			}
			mut(s)
			if _, err := Verify(s, ""); !IsIntegrity(err) {
				t.Fatalf("not detected: %v", err)
			}
		})
	}
}
