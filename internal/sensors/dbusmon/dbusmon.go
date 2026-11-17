// Package dbusmon reads the system bus state the host checks need (spec §9.7, source
// dbus-system): NetworkManager (Wi-Fi in use, saved connections, connectivity check), GeoClue and
// the timedate1/locale1 fallbacks. Every read shares one deadline: a stuck service must never
// hold the daemon. Values that may match the baseline (SSID, BSSID, hostnames) stay inside State;
// checks report only field names.
package dbusmon

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// SourceID of this sensor.
const SourceID = "dbus-system"

// Timeout is the budget of one Read.
const Timeout = 2 * time.Second

const (
	nmDest      = "org.freedesktop.NetworkManager"
	nmPath      = "/org/freedesktop/NetworkManager"
	nmSettings  = "/org/freedesktop/NetworkManager/Settings"
	geoclueDest = "org.freedesktop.GeoClue2"
	wifiType    = 2 // NM_DEVICE_TYPE_WIFI
)

// Bus is the part of *dbus.Conn the reader uses.
type Bus interface {
	Object(dest string, path dbus.ObjectPath) dbus.BusObject
}

// State is one reading of the system bus.
type State struct {
	NM          NM       `json:"nm"`
	GeoClue     GeoClue  `json:"geoclue"`
	Timezone    string   `json:"timezone,omitempty"` // timedate1 (fallback of /etc/localtime)
	Keyboard    string   `json:"keyboard,omitempty"` // locale1 X11Layout
	Locale      string   `json:"locale,omitempty"`   // locale1 LANG
	Unavailable []string `json:"unavailable"`
}

// NM is the NetworkManager state.
type NM struct {
	Available         bool   `json:"available"`
	ConnectivityCheck bool   `json:"connectivity_check"`
	WiFi              []WiFi `json:"wifi"`
	Connections       []Conn `json:"connections"`
}

// WiFi is an associated wireless device.
type WiFi struct {
	Iface string `json:"iface"`
	SSID  string `json:"-"`
	BSSID string `json:"-"`
}

// Conn is one saved connection profile.
type Conn struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	SSID         string `json:"-"`
	Autoconnect  bool   `json:"autoconnect"`
	SendHostname bool   `json:"send_hostname"` // ipv4 or ipv6 dhcp-send-hostname
	DHCPHostname string `json:"-"`
}

// GeoClue is the geolocation service state.
type GeoClue struct {
	Running bool `json:"running"`
	InUse   bool `json:"in_use"`
}

// Reader reads State from a bus.
type Reader struct{ Bus Bus }

// Read collects the state; a service that is not running is reported as such, a failing one
// goes to Unavailable.
func (r Reader) Read() State {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	st := State{Unavailable: []string{}, NM: NM{WiFi: []WiFi{}, Connections: []Conn{}}}
	if r.has(ctx, nmDest) {
		if err := r.nm(ctx, &st.NM); err != nil {
			st.Unavailable = append(st.Unavailable, "networkmanager: "+err.Error())
		}
	}
	if r.has(ctx, geoclueDest) {
		st.GeoClue.Running = true
		if v, err := prop(ctx, r.Bus.Object(geoclueDest, "/org/freedesktop/GeoClue2/Manager"), "org.freedesktop.GeoClue2.Manager", "InUse"); err == nil {
			st.GeoClue.InUse, _ = v.Value().(bool)
		}
	}
	if r.has(ctx, "org.freedesktop.timedate1") {
		if v, err := prop(ctx, r.Bus.Object("org.freedesktop.timedate1", "/org/freedesktop/timedate1"), "org.freedesktop.timedate1", "Timezone"); err == nil {
			st.Timezone, _ = v.Value().(string)
		}
	}
	if r.has(ctx, "org.freedesktop.locale1") {
		loc := r.Bus.Object("org.freedesktop.locale1", "/org/freedesktop/locale1")
		if v, err := prop(ctx, loc, "org.freedesktop.locale1", "X11Layout"); err == nil {
			st.Keyboard, _ = v.Value().(string)
		}
		if v, err := prop(ctx, loc, "org.freedesktop.locale1", "Locale"); err == nil {
			if ls, ok := v.Value().([]string); ok {
				for _, l := range ls {
					if rest, ok := strings.CutPrefix(l, "LANG="); ok {
						st.Locale = rest
					}
				}
			}
		}
	}
	return st
}

// has asks the bus whether name has an owner, without activating the service.
func (r Reader) has(ctx context.Context, name string) bool {
	var ok bool
	c := r.Bus.Object("org.freedesktop.DBus", "/org/freedesktop/DBus").CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, name)
	return c.Err == nil && c.Store(&ok) == nil && ok
}

func prop(ctx context.Context, o dbus.BusObject, iface, name string) (dbus.Variant, error) {
	var v dbus.Variant
	c := o.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name)
	if c.Err != nil {
		return v, c.Err
	}
	return v, c.Store(&v)
}

func (r Reader) nm(ctx context.Context, out *NM) error {
	out.Available = true
	root := r.Bus.Object(nmDest, nmPath)
	if v, err := prop(ctx, root, nmDest, "ConnectivityCheckEnabled"); err == nil {
		out.ConnectivityCheck, _ = v.Value().(bool)
	}
	var devs []dbus.ObjectPath
	if c := root.CallWithContext(ctx, nmDest+".GetDevices", 0); c.Err != nil || c.Store(&devs) != nil {
		return errors.Join(errors.New("GetDevices"), c.Err)
	}
	for _, p := range devs {
		dev := r.Bus.Object(nmDest, p)
		t, err := prop(ctx, dev, nmDest+".Device", "DeviceType")
		if err != nil {
			continue
		}
		if dt, _ := t.Value().(uint32); dt != wifiType {
			continue
		}
		w := WiFi{}
		if v, err := prop(ctx, dev, nmDest+".Device", "Interface"); err == nil {
			w.Iface, _ = v.Value().(string)
		}
		ap, err := prop(ctx, dev, nmDest+".Device.Wireless", "ActiveAccessPoint")
		apPath, _ := ap.Value().(dbus.ObjectPath)
		if err != nil || apPath == "" || apPath == "/" {
			continue // not associated
		}
		apo := r.Bus.Object(nmDest, apPath)
		if v, err := prop(ctx, apo, nmDest+".AccessPoint", "Ssid"); err == nil {
			b, _ := v.Value().([]byte)
			w.SSID = string(b)
		}
		if v, err := prop(ctx, apo, nmDest+".AccessPoint", "HwAddress"); err == nil {
			s, _ := v.Value().(string)
			w.BSSID = strings.ToLower(s)
		}
		out.WiFi = append(out.WiFi, w)
	}
	var conns []dbus.ObjectPath
	set := r.Bus.Object(nmDest, nmSettings)
	if c := set.CallWithContext(ctx, nmDest+".Settings.ListConnections", 0); c.Err != nil || c.Store(&conns) != nil {
		return fmt.Errorf("ListConnections: %w", c.Err)
	}
	for _, p := range conns {
		var s map[string]map[string]dbus.Variant
		if c := r.Bus.Object(nmDest, p).CallWithContext(ctx, nmDest+".Settings.Connection.GetSettings", 0); c.Err != nil || c.Store(&s) != nil {
			continue
		}
		out.Connections = append(out.Connections, connFrom(s))
	}
	sort.Slice(out.Connections, func(i, j int) bool { return out.Connections[i].ID < out.Connections[j].ID })
	return nil
}

func connFrom(s map[string]map[string]dbus.Variant) Conn {
	str := func(sec, key string) string { v, _ := s[sec][key].Value().(string); return v }
	boolOr := func(sec, key string, def bool) bool {
		if v, ok := s[sec][key]; ok {
			if b, ok := v.Value().(bool); ok {
				return b
			}
		}
		return def
	}
	c := Conn{ID: str("connection", "id"), Type: str("connection", "type"), Autoconnect: boolOr("connection", "autoconnect", true)}
	if b, ok := s["802-11-wireless"]["ssid"].Value().([]byte); ok {
		c.SSID = string(b)
	}
	for _, fam := range []string{"ipv4", "ipv6"} {
		if _, ok := s[fam]; !ok {
			continue
		}
		if m := str(fam, "method"); m == "disabled" || m == "ignore" || m == "manual" || m == "link-local" {
			continue // no DHCP on this family
		}
		if boolOr(fam, "dhcp-send-hostname", true) {
			c.SendHostname = true
		}
		if h := str(fam, "dhcp-hostname"); h != "" {
			c.DHCPHostname = h
		}
	}
	return c
}
