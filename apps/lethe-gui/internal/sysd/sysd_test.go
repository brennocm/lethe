package sysd

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

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

// Only the JobRemoved of our own job decides, and only "done" is success (a failed cleanup is
// not reported as a released network).
func TestM81_JobResult(t *testing.T) {
	job := dbus.ObjectPath("/org/freedesktop/systemd1/job/42")
	sig := func(p dbus.ObjectPath, r string) *dbus.Signal {
		return &dbus.Signal{Name: "org.freedesktop.systemd1.Manager.JobRemoved", Body: []any{uint32(42), p, CleanupUnit, r}}
	}
	if r, ok := JobResult(sig(job, "failed"), job); !ok || r != "failed" {
		t.Fatalf("%q %v", r, ok)
	}
	if _, ok := JobResult(sig("/org/freedesktop/systemd1/job/7", "done"), job); ok {
		t.Fatal("another job's signal")
	}
	if _, ok := JobResult(&dbus.Signal{Name: "org.freedesktop.systemd1.Manager.UnitNew", Body: []any{}}, job); ok {
		t.Fatal("another signal")
	}
}
