package contracts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleEvent() Event {
	return Event{
		V: 1, Seq: 7, TS: time.Date(2026, 11, 15, 14, 3, 22, 418213000, time.UTC), MonoNS: 81234567890123,
		Session: "5f0c9e2a-7b1d-4c3e-9a8f-2d6b1e0c4a77", Type: EvCheckAlert, Check: "DNS-001",
		Severity: SeverityCritical, Source: SourceDaemon,
		Data:    map[string]any{"iface": "eth0", "dport": 53, "proc": Proc{PID: 1, Exe: "/usr/bin/dig", UID: 1000, Confidence: ConfidenceHigh}},
		AlertID: "A-0007", Actions: []string{"block_all"},
	}
}

func TestEvent_SampleMatchesSchema(t *testing.T) {
	if err := Validate("event", sampleEvent()); err != nil {
		t.Fatal(err)
	}
}

func TestEvent_SchemaRejects(t *testing.T) {
	cases := map[string]func(*Event){
		"unknown type":        func(e *Event) { e.Type = "made.up" },
		"alert without check": func(e *Event) { e.Check = "" },
		"bad severity":        func(e *Event) { e.Severity = "LOW" },
		"bad action":          func(e *Event) { e.Actions = []string{"reboot"} },
		"bad session":         func(e *Event) { e.Session = "x" },
		"bad hash":            func(e *Event) { e.Hash = "md5:abc" },
		"unknown source":      func(e *Event) { e.Source = "browser" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			e := sampleEvent()
			mut(&e)
			if err := Validate("event", e); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestEventTypes_SchemaEnumMatchesGo(t *testing.T) {
	raw, err := schemaFS.ReadFile("schemas/event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties struct {
			Type struct {
				Enum []string `json:"enum"`
			} `json:"type"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(s.Properties.Type.Enum, ",")
	var want []string
	for _, t := range EventTypes() {
		want = append(want, string(t))
	}
	if got != strings.Join(want, ",") {
		t.Fatalf("schema enum and Go constants diverge:\nschema: %s\ngo:     %s", got, strings.Join(want, ","))
	}
}

func TestEvent_Accessors(t *testing.T) {
	e := sampleEvent()
	if e.Str("iface") != "eth0" || e.Int("dport") != 53 || e.ProcExe() != "/usr/bin/dig" {
		t.Fatal("accessors broken")
	}
	raw, _ := json.Marshal(e)
	var back Event
	_ = json.Unmarshal(raw, &back)
	if back.Int("dport") != 53 || back.ProcExe() != "/usr/bin/dig" {
		t.Fatal("accessors broken after JSON round trip")
	}
	if SeverityCritical.Rank() <= SeverityWarning.Rank() || Severity("x").Valid() {
		t.Fatal("severity rank broken")
	}
}
