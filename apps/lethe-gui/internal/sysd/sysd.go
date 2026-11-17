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
	return startUnit(ctx, unit)
}

// CleanupUnit removes leftover lethe* tables after a crash (packaging/systemd).
const CleanupUnit = "lethe-cleanup.service"

// Cleanup starts lethe-cleanup.service (lethe cleanup as root, polkit asking the password) and
// waits for the oneshot to finish, so the panel can say whether the network came back.
func Cleanup(ctx context.Context) error {
	return startUnit(ctx, CleanupUnit)
}

// startUnit starts unit and waits for systemd to finish the job: StartUnit returns when the job
// is queued, so success is read from the JobRemoved signal ("done"), not from the call.
func startUnit(ctx context.Context, unit string) error {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("system bus: %w", err)
	}
	defer func() { _ = conn.Close() }()
	mgr := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	if err := conn.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.systemd1.Manager"), dbus.WithMatchMember("JobRemoved")); err != nil {
		return err
	}
	sigs := make(chan *dbus.Signal, 32)
	conn.Signal(sigs)
	if err := mgr.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.Subscribe", 0).Err; err != nil {
		return err
	}
	var job dbus.ObjectPath
	call := mgr.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.StartUnit", dbus.FlagAllowInteractiveAuthorization, unit, "replace")
	if err := call.Store(&job); err != nil {
		var de dbus.Error
		if errors.As(err, &de) && de.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return fmt.Errorf("%s is not installed (install the lethe package)", unit)
		}
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: no answer from systemd: %w", unit, ctx.Err())
		case sig := <-sigs:
			if sig == nil {
				return fmt.Errorf("%s: system bus closed", unit)
			}
			if r, ok := JobResult(sig, job); ok {
				if r != "done" {
					return fmt.Errorf("%s: %s (journalctl -u %s)", unit, r, unit)
				}
				return nil
			}
		}
	}
}

// JobResult reads a JobRemoved signal (id, job, unit, result) for job.
func JobResult(sig *dbus.Signal, job dbus.ObjectPath) (string, bool) {
	if sig.Name != "org.freedesktop.systemd1.Manager.JobRemoved" || len(sig.Body) != 4 {
		return "", false
	}
	p, ok := sig.Body[1].(dbus.ObjectPath)
	r, ok2 := sig.Body[3].(string)
	if !ok || !ok2 || p != job {
		return "", false
	}
	return r, true
}
