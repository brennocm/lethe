package discovery

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/godbus/dbus/v5"
)

// DBusResolved reads org.freedesktop.resolve1 on the system bus.
type DBusResolved struct{ Conn *dbus.Conn }

// NewDBusResolved connects to the system bus (private connection, closed by the caller).
func NewDBusResolved() (*DBusResolved, error) {
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	return &DBusResolved{Conn: c}, nil
}

// Close closes the bus connection.
func (r *DBusResolved) Close() error { return r.Conn.Close() }

type dnsEntry struct {
	Ifindex int32
	Family  int32
	Address []byte
}

type domainEntry struct {
	Ifindex int32
	Domain  string
	Routing bool
}

// Links returns per-link DNS servers, routing domains and DefaultRoute.
//
// godbus calls block until a reply arrives. Discovery runs under the daemon lock, so a stuck
// resolved would freeze the daemon (no alerts, no panic). The whole query shares one budget.
func (r *DBusResolved) Links(names map[int]string) ([]ResolvedLink, error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolvedTimeout)
	defer cancel()
	mgr := r.Conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
	var servers []dnsEntry
	if v, err := getProp(ctx, mgr, "org.freedesktop.resolve1.Manager", "DNS"); err != nil {
		return nil, fmt.Errorf("resolved DNS: %w", err)
	} else if err := v.Store(&servers); err != nil {
		return nil, fmt.Errorf("resolved DNS: %w", err)
	}
	var domains []domainEntry
	if v, err := getProp(ctx, mgr, "org.freedesktop.resolve1.Manager", "Domains"); err == nil {
		_ = v.Store(&domains)
	}
	byIdx := map[int]*ResolvedLink{}
	get := func(idx int) *ResolvedLink {
		if l, ok := byIdx[idx]; ok {
			return l
		}
		l := &ResolvedLink{Iface: names[idx], Servers: []string{}, Domains: []string{}}
		if idx == 0 {
			l.Iface = "(global)"
		}
		byIdx[idx] = l
		return l
	}
	for _, s := range servers {
		if a, ok := netip.AddrFromSlice(s.Address); ok {
			get(int(s.Ifindex)).Servers = append(get(int(s.Ifindex)).Servers, a.Unmap().String())
		}
	}
	for _, d := range domains {
		name := d.Domain
		if d.Routing {
			name = "~" + name
		}
		get(int(d.Ifindex)).Domains = append(get(int(d.Ifindex)).Domains, name)
	}
	out := make([]ResolvedLink, 0, len(byIdx))
	for idx, l := range byIdx {
		if idx > 0 {
			var path dbus.ObjectPath
			if err := mgr.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.GetLink", 0, int32(idx)).Store(&path); err == nil {
				if v, err := getProp(ctx, r.Conn.Object("org.freedesktop.resolve1", path), "org.freedesktop.resolve1.Link", "DefaultRoute"); err == nil {
					l.DefaultRoute, _ = v.Value().(bool)
				}
			}
		}
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Iface < out[j].Iface })
	return out, nil
}

// resolvedTimeout bounds one Links query.
const resolvedTimeout = time.Second

// getProp is GetProperty with a deadline.
func getProp(ctx context.Context, o dbus.BusObject, iface, prop string) (dbus.Variant, error) {
	var v dbus.Variant
	err := o.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, prop).Store(&v)
	return v, err
}
