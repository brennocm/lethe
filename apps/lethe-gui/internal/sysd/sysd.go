// Package sysd starts lethe's service from the GUI through systemd's D-Bus API (no exec): the
// operator's instance lethed@<user>.service, with interactive authorization so polkit asks an
// administrator's password (org.freedesktop.systemd1.manage-units).
package sysd

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/godbus/dbus/v5"
)

// userRe is a portable user name (useradd's default): it names the unit instance, so nothing
// else may reach systemd's unit name.
var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Unit is the service unit of user.
func Unit(user string) (string, error) {
	if !userRe.MatchString(user) || user == "root" {
		return "", fmt.Errorf("user name %q cannot name the service; start it by hand (docs/runbooks/service-mode.md)", user)
	}
	return "lethed@" + user + ".service", nil
}

// Start asks systemd on the system bus to start the user's unit and waits for the call (the
// polkit prompt included). The daemon's own start is seen by the GUI's next poll.
func Start(ctx context.Context, user string) error {
	unit, err := Unit(user)
	if err != nil {
		return err
	}
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("system bus: %w", err)
	}
	defer func() { _ = conn.Close() }()
	var job dbus.ObjectPath
	call := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").
		CallWithContext(ctx, "org.freedesktop.systemd1.Manager.StartUnit", dbus.FlagAllowInteractiveAuthorization, unit, "replace")
	if err := call.Store(&job); err != nil {
		var de dbus.Error
		if errors.As(err, &de) && de.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return fmt.Errorf("%s is not installed (install the lethe package)", unit)
		}
		return err
	}
	return nil
}
