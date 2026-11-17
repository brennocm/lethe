package response

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"

	"lethe/internal/platform"
)

// DefaultLinkDir holds the list of links lethe set down. It is root's (/run is), so only the
// daemon writes it, and it does not survive a reboot, as the links' state does not either.
const DefaultLinkDir = "/run/lethe-state"

const linksFile = "links-down"

// LinkStore remembers the egress links link_down set down, so that unpanic, disarm and
// `lethe cleanup` bring them back up, also after a crash. Only links that were up are recorded:
// a link the operator had down stays down.
type LinkStore struct{ Dir string }

func (s LinkStore) dir() string {
	if s.Dir == "" {
		return DefaultLinkDir
	}
	return s.Dir
}

// List returns the recorded links (none when the file does not exist).
func (s LinkStore) List() ([]string, error) {
	b, err := os.ReadFile(s.dir() + "/" + linksFile) // #nosec G304 -- fixed root-only path
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	return out, nil
}

func (s LinkStore) write(links []string) error {
	d, err := platform.OpenDir(s.dir(), 0o700)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if len(links) == 0 {
		if err := os.Remove(s.dir() + "/" + linksFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return platform.WriteFileAt(d, linksFile, []byte(strings.Join(links, "\n")+"\n"), 0o600, -1, -1)
}

// Add records iface.
func (s LinkStore) Add(iface string) error {
	cur, err := s.List()
	if err != nil {
		return err
	}
	if slices.Contains(cur, iface) {
		return nil
	}
	return s.write(append(cur, iface))
}

// Restore brings every recorded link up with up and forgets the ones that came back (or no
// longer exist). It returns the links brought up; the failures stay recorded for the next try.
func (s LinkStore) Restore(up func(string) error) ([]string, error) {
	cur, err := s.List()
	if err != nil || len(cur) == 0 {
		return nil, err
	}
	var done, left []string
	var errs []error
	for _, l := range cur {
		switch err := up(l); {
		case err == nil:
			done = append(done, l)
		case errors.As(err, new(netlink.LinkNotFoundError)):
			// gone (a USB adapter unplugged): nothing to bring back
		default:
			left = append(left, l)
			errs = append(errs, fmt.Errorf("%s: %w", l, err))
		}
	}
	if err := s.write(left); err != nil {
		errs = append(errs, err)
	}
	return done, errors.Join(errs...)
}

// NetlinkLinkUp sets iface up (the undo of RecordedLinkDown).
func NetlinkLinkUp(iface string) error {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(l)
}

// RecordedLinkDown sets iface down through netlink and records it in s, only if it was up.
func RecordedLinkDown(s LinkStore) func(string) error {
	return func(iface string) error {
		l, err := netlink.LinkByName(iface)
		if err != nil {
			return err
		}
		if l.Attrs().Flags&(1<<0) == 0 { // IFF_UP off: the operator's choice, not ours
			return nil
		}
		// record first: a crash between the two leaves a link to bring up that is already up
		if err := s.Add(iface); err != nil {
			return fmt.Errorf("record %s: %w", iface, err)
		}
		return netlink.LinkSetDown(l)
	}
}
