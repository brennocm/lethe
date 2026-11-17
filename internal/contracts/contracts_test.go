package contracts

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAllSchemasCompile(t *testing.T) {
	if len(Names()) == 0 {
		t.Fatal("no schemas embedded")
	}
	// Any validation call triggers compilation of every schema.
	if err := ValidateJSON(Names()[0], []byte(`{}`)); err != nil && compileErr != nil {
		t.Fatalf("compile: %v", compileErr)
	}
}

func TestValidate_Version(t *testing.T) {
	good := `{"version":"dev","commit":"unknown","modified":false,"go_version":"go1.27.4",
	"platform":"linux/amd64","binary_sha256":"` + "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" + `","geo_db_date":"none"}`
	if err := ValidateJSON("version", []byte(good)); err != nil {
		t.Fatalf("good doc rejected: %v", err)
	}
	if err := ValidateJSON("version", []byte(`{"version":"dev","extra":1}`)); err == nil {
		t.Fatal("bad doc accepted")
	}
	if err := ValidateJSON("nope", []byte(`{}`)); err == nil {
		t.Fatal("unknown schema accepted")
	}
}

// SELF-004 and the offer of strict share one rule: a full, approved selftest under 24 h.
func TestSELF004_SelftestApproval(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	table := func(passed, full bool, age time.Duration) []byte {
		raw, _ := json.Marshal(SelftestResult{FinishedAt: now.Add(-age), Passed: passed, Full: full})
		return raw
	}
	for _, c := range []struct {
		raw []byte
		ok  bool
		why string
	}{
		{nil, false, SelftestNone},
		{[]byte("{"), false, SelftestUnreadable},
		{table(false, true, time.Hour), false, SelftestFailed},
		{table(true, false, time.Hour), false, SelftestPartial},
		{table(true, true, 25*time.Hour), false, SelftestStale},
		{table(true, true, time.Hour), true, ""},
	} {
		if ok, why := SelftestApproval(c.raw, now); ok != c.ok || why != c.why {
			t.Errorf("%s: %v %q", c.raw, ok, why)
		}
	}
}
