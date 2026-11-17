package agent

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"
)

// DBusNotifier sends notifications over the session bus. The sound goes as the freedesktop
// "sound-name" hint, so the notification server plays it (no external player is run).
type DBusNotifier struct{ Conn *dbus.Conn }

// NewDBusNotifier connects to the session bus of DBUS_SESSION_BUS_ADDRESS.
func NewDBusNotifier() (*DBusNotifier, error) {
	c, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, err
	}
	return &DBusNotifier{Conn: c}, nil
}

// Notify implements Notifier.
func (n *DBusNotifier) Notify(x Notification) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	urgency, icon, sound, timeout := byte(1), "dialog-warning", "dialog-warning", int32(10000)
	if x.Critical {
		urgency, icon, sound, timeout = 2, "dialog-error", "alarm-clock-elapsed", 0 // 0 = until dismissed
	}
	hints := map[string]dbus.Variant{"urgency": dbus.MakeVariant(urgency)}
	if x.Sound {
		hints["sound-name"] = dbus.MakeVariant(sound)
	} else {
		hints["suppress-sound"] = dbus.MakeVariant(true)
	}
	obj := n.Conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	return obj.CallWithContext(ctx, "org.freedesktop.Notifications.Notify", 0,
		"lethe", uint32(0), icon, x.Summary, x.Body, []string{}, hints, timeout).Err
}
