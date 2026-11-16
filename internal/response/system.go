package response

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/vishvananda/netlink"
)

// NetlinkLinkDown clears IFF_UP on iface (link_down).
func NetlinkLinkDown(iface string) error {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.LinkSetDown(l)
}

// Login1 is the part of org.freedesktop.login1 lock_screen uses.
type Login1 interface {
	SessionsOf(uid uint32) ([]dbus.ObjectPath, error)
	Lock(dbus.ObjectPath) error
}

// LockScreen locks every login1 session of uid (org.freedesktop.login1.Session.Lock).
func LockScreen(l Login1, uid uint32) error {
	paths, err := l.SessionsOf(uid)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("no login1 session for uid %d", uid)
	}
	var errs []error
	for _, p := range paths {
		errs = append(errs, l.Lock(p))
	}
	return errors.Join(errs...)
}

// SystemLogin1 talks to logind on the system bus.
type SystemLogin1 struct{ Conn *dbus.Conn }

// SessionsOf lists the session object paths of uid.
func (s SystemLogin1) SessionsOf(uid uint32) ([]dbus.ObjectPath, error) {
	var sessions []struct {
		ID   string
		UID  uint32
		User string
		Seat string
		Path dbus.ObjectPath
	}
	obj := s.Conn.Object("org.freedesktop.login1", "/org/freedesktop/login1")
	ctx, cancel := context.WithTimeout(context.Background(), login1Timeout)
	defer cancel()
	if err := obj.CallWithContext(ctx, "org.freedesktop.login1.Manager.ListSessions", 0).Store(&sessions); err != nil {
		return nil, fmt.Errorf("login1 ListSessions: %w", err)
	}
	var out []dbus.ObjectPath
	for _, x := range sessions {
		if x.UID == uid {
			out = append(out, x.Path)
		}
	}
	return out, nil
}

// Lock locks one session.
func (s SystemLogin1) Lock(p dbus.ObjectPath) error {
	ctx, cancel := context.WithTimeout(context.Background(), login1Timeout)
	defer cancel()
	return s.Conn.Object("org.freedesktop.login1", p).CallWithContext(ctx, "org.freedesktop.login1.Session.Lock", 0).Err
}

// login1Timeout bounds each logind call: responses run under the daemon lock, and a stuck logind
// must not hold back the actions and the panic that follow.
const login1Timeout = 2 * time.Second
