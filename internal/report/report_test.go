package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"lethe/internal/contracts"
	"lethe/internal/journal"
)

var update = flag.Bool("update", false, "rewrite golden files")

const sid = "5f0c9e2a-7b1d-4c3e-9a8f-2d6b1e0c4a77"

// syntheticSession writes a representative session: arm, a DNS leak with panic, ack, resolution.
func syntheticSession(t *testing.T) (*journal.Session, journal.Result, *age.X25519Identity) {
	t.Helper()
	id, _ := age.GenerateX25519Identity()
	sens, _ := age.GenerateX25519Identity()
	now := time.Date(2026, 11, 15, 14, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	dir := filepath.Join(t.TempDir(), "s")
	w, err := journal.Open(journal.Config{
		Dir: dir, Session: sid, Recipients: []age.Recipient{id.Recipient()}, SensitiveRecipients: []age.Recipient{sens.Recipient()},
		Now: clk, Mono: func() int64 { return now.UnixNano() },
		StartData: map[string]any{"operation": "OP-2026-117", "persona": "falcao", "operator": "agente-07", "guard_mode": "strict",
			"profile_sha256": strings.Repeat("a", 64), "baseline_sha256": strings.Repeat("b", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	add := func(d time.Duration, ev contracts.Event) {
		now = now.Add(d)
		if _, err := w.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	qname, _ := w.Seal("painel.alvo.example")
	add(0, contracts.Event{Type: contracts.EvPreflightResult, Data: map[string]any{"result": "PASS"}})
	add(0, contracts.Event{Type: contracts.EvPreflightManualItem, Data: map[string]any{"item": "no_personal_accounts", "answer": "confirmado"}})
	add(time.Second, contracts.Event{Type: contracts.EvStateChanged, Data: map[string]any{"color": "GREEN"}})
	leak := contracts.Event{Type: contracts.EvCheckAlert, Check: "DNS-001", Severity: contracts.SeverityCritical, AlertID: "A-0001",
		Data:    map[string]any{"iface": "eth0", "dst": "192.0.2.53", "dport": 53, "qname": qname, "proc": contracts.Proc{PID: 9, Exe: "/usr/bin/dig", Confidence: contracts.ConfidenceHigh}},
		Actions: []string{"block_all"}}
	add(10*time.Minute, leak)
	add(0, contracts.Event{Type: contracts.EvStateChanged, Data: map[string]any{"color": "RED"}})
	add(0, contracts.Event{Type: contracts.EvResponseExecuted, AlertID: "A-0001", Data: map[string]any{"action": "block_all", "ok": true, "latency_ms": 42}})
	add(2*time.Second, leak)
	add(time.Minute, contracts.Event{Type: contracts.EvAlertAck, AlertID: "A-0001", Source: contracts.SourceOperator, Data: map[string]any{"reason": "dig manual de teste"}})
	add(0, contracts.Event{Type: contracts.EvCheckResolved, Check: "DNS-001", Severity: contracts.SeverityCritical, AlertID: "A-0001"})
	add(0, contracts.Event{Type: contracts.EvCheckAlert, Check: "NET-006", Severity: contracts.SeverityWarning, AlertID: "A-0002", Data: map[string]any{"iface": "usb0"}})
	add(0, contracts.Event{Type: contracts.EvStateChanged, Data: map[string]any{"color": "YELLOW"}})
	add(3*time.Minute, contracts.Event{Type: contracts.EvStateChanged, Data: map[string]any{"color": "GREEN"}})
	now = now.Add(5 * time.Minute)
	if err := w.Close(nil); err != nil {
		t.Fatal(err)
	}
	s, err := journal.Read(dir, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	res, err := journal.Verify(s, w.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UnlockSensitive([]age.Identity{sens}); err != nil {
		t.Fatal(err)
	}
	return s, res, id
}

func normalize(out string, s *journal.Session, r Report) string {
	return strings.NewReplacer(r.PublicKey, "<PUBKEY>", r.Integrity.Fingerprint, "<FINGERPRINT>", r.Integrity.FinalHash, "<FINAL_HASH>").Replace(out)
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if got != string(want) {
		t.Fatalf("%s differs from golden (run go test -update):\n%s", name, got)
	}
}

func TestReport_MarkdownGolden_Redacted(t *testing.T) {
	s, res, _ := syntheticSession(t)
	r, err := Build(s, res, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WriteMarkdown(&b, r); err != nil {
		t.Fatal(err)
	}
	out := normalize(b.String(), s, r)
	if strings.Contains(out, "painel.alvo.example") {
		t.Fatal("sensitive field leaked without --include-sensitive")
	}
	golden(t, "report.md.golden", out)
}

func TestReport_JSON_Facts(t *testing.T) {
	s, res, _ := syntheticSession(t)
	r, err := Build(s, res, Options{IncludeSensitive: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Alerts) != 2 || r.Alerts[0].Count != 2 || !r.Alerts[0].Acknowledged || !r.Alerts[0].Resolved || r.Alerts[0].Detail["qname"] != "painel.alvo.example" {
		t.Fatalf("alerts: %+v", r.Alerts)
	}
	if r.Alerts[0].Detail["proc"] != "/usr/bin/dig" || len(r.Responses) != 1 || r.Responses[0].LatencyMS != 42 {
		t.Fatalf("detail/responses: %+v %+v", r.Alerts[0].Detail, r.Responses)
	}
	// GREEN: 10m + 5m ; RED 1m2s ; YELLOW 3m  → 15m / 19m2s
	if r.GreenPercent < 78.8 || r.GreenPercent > 78.9 {
		t.Fatalf("green %% = %f", r.GreenPercent)
	}
	var b bytes.Buffer
	if err := WriteJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	if err := contracts.ValidateJSON("report", b.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func TestReport_UnackedCriticalWarned(t *testing.T) {
	s, res, _ := syntheticSession(t)
	var kept []contracts.Event
	for _, ev := range s.Events {
		if ev.Type != contracts.EvAlertAck {
			kept = append(kept, ev)
		}
	}
	s.Events = kept
	r, _ := Build(s, res, Options{})
	found := false
	for _, w := range r.Warnings {
		found = found || strings.Contains(w, "never acknowledged")
	}
	if !found {
		t.Fatalf("warnings %v", r.Warnings)
	}
}

func TestBuild_Empty(t *testing.T) {
	if _, err := Build(&journal.Session{}, journal.Result{}, Options{}); err == nil {
		t.Fatal("empty session accepted")
	}
}

// Untrusted text (process names, QNAMEs, reasons) must not become an image, link or HTML in
// report.md: a viewer fetching it would leak the reader's address.
func TestReport_MarkdownInert(t *testing.T) {
	for _, in := range []string{
		"![x](http://198.51.100.1/p.png)", "<img src=http://198.51.100.1/>", "[a](http://x)", "a|b\n# heading", "x `code`",
	} {
		out := md(in)
		for _, bad := range []string{"![", "](", "<", "\n", " `"} {
			if strings.Contains(out, bad) {
				t.Errorf("md(%q) = %q contains %q", in, out, bad)
			}
		}
		if strings.Count(out, "|") != strings.Count(out, "\\|") {
			t.Errorf("md(%q) = %q splits a table cell", in, out)
		}
	}
	if got := md("&lt;"); got != "&amp;lt;" {
		t.Errorf("entities must not pass through: %q", got)
	}
}
