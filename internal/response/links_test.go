package response

import (
	"errors"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestRESP_LinkStoreRestoresWhatPanicDowned: what link_down set down comes back up on unpanic,
// disarm or cleanup; a failure stays recorded for the next try, a vanished link is forgotten.
func TestRESP_LinkStoreRestoresWhatPanicDowned(t *testing.T) {
	s := LinkStore{Dir: t.TempDir()}
	for _, l := range []string{"wlan0", "eth0", "wlan0", "usb0"} {
		if err := s.Add(l); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := s.List(); !slices.Equal(got, []string{"wlan0", "eth0", "usb0"}) {
		t.Fatalf("%v", got)
	}
	var up []string
	done, err := s.Restore(func(l string) error {
		switch l {
		case "eth0":
			return errors.New("busy")
		case "usb0":
			return netlink.LinkNotFoundError{}
		}
		up = append(up, l)
		return nil
	})
	if err == nil || !slices.Equal(done, []string{"wlan0"}) || !slices.Equal(up, []string{"wlan0"}) {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if got, _ := s.List(); !slices.Equal(got, []string{"eth0"}) {
		t.Fatalf("left %v", got)
	}
	if done, err := s.Restore(func(string) error { return nil }); err != nil || !slices.Equal(done, []string{"eth0"}) {
		t.Fatalf("%v %v", done, err)
	}
	if got, _ := s.List(); len(got) != 0 {
		t.Fatalf("not cleared: %v", got)
	}
}
