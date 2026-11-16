package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// hungObject never answers until the caller gives up.
type hungObject struct{ dbus.BusObject }

func (hungObject) CallWithContext(ctx context.Context, _ string, _ dbus.Flags, _ ...any) *dbus.Call {
	<-ctx.Done()
	return &dbus.Call{Err: ctx.Err()}
}

// A stuck systemd-resolved must not hold discovery (and the daemon lock) forever.
func TestDiscover_ResolvedCallsHaveADeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := getProp(ctx, hungObject{}, "org.freedesktop.resolve1.Manager", "DNS"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("no error from a hung bus")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("getProp ignored its deadline")
	}
	if resolvedTimeout > 2*time.Second {
		t.Fatalf("resolved budget %v is too long for a pass under the daemon lock", resolvedTimeout)
	}
}
