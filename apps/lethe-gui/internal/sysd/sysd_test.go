package sysd

import "testing"

// Only a plain user name reaches the unit name; root and anything with a path, a dot or an
// escape is refused (spec §16.2, ADR 0015).
func TestM13_ServiceUnitName(t *testing.T) {
	if u, err := Unit("alice"); err != nil || u != "lethed@alice.service" {
		t.Fatalf("%q %v", u, err)
	}
	for _, bad := range []string{"", "root", "../x", "a.service", "a b", "A", "a\\x2d", "x@y"} {
		if _, err := Unit(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
