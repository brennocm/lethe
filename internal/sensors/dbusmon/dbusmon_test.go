package dbusmon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type fakeObj struct {
	dbus.BusObject
	props   map[string]any // "iface.prop" → value
	methods map[string]any // method → single return value
	hang    bool
}

func (o *fakeObj) CallWithContext(ctx context.Context, method string, _ dbus.Flags, args ...any) *dbus.Call {
	if o.hang {
		<-ctx.Done()
		return &dbus.Call{Err: ctx.Err()}
	}
	if method == "org.freedesktop.DBus.Properties.Get" {
		v, ok := o.props[args[0].(string)+"."+args[1].(string)]
		if !ok {
			return &dbus.Call{Err: errors.New("no such property")}
		}
		return &dbus.Call{Body: []any{dbus.MakeVariant(v)}}
	}
	if method == "org.freedesktop.DBus.NameHasOwner" {
		v, ok := o.methods["owner:"+args[0].(string)]
		return &dbus.Call{Body: []any{ok && v.(bool)}}
	}
	v, ok := o.methods[method]
	if !ok {
		return &dbus.Call{Err: errors.New("no such method " + method)}
	}
	return &dbus.Call{Body: []any{v}}
}

type fakeBus map[dbus.ObjectPath]*fakeObj

func (b fakeBus) Object(_ string, p dbus.ObjectPath) dbus.BusObject {
	if o, ok := b[p]; ok {
		return o
	}
	return &fakeObj{}
}

func nmBus() fakeBus {
	v := dbus.MakeVariant
	return fakeBus{
		"/org/freedesktop/DBus": {methods: map[string]any{"owner:" + nmDest: true, "owner:" + geoclueDest: true, "owner:org.freedesktop.locale1": true}},
		nmPath: {props: map[string]any{nmDest + ".ConnectivityCheckEnabled": true},
			methods: map[string]any{nmDest + ".GetDevices": []dbus.ObjectPath{"/d/1", "/d/2"}}},
		"/d/1": {props: map[string]any{nmDest + ".Device.DeviceType": uint32(1), nmDest + ".Device.Interface": "eth0"}},
		"/d/2": {props: map[string]any{nmDest + ".Device.DeviceType": uint32(2), nmDest + ".Device.Interface": "wlan0",
			nmDest + ".Device.Wireless.ActiveAccessPoint": dbus.ObjectPath("/ap/9")}},
		"/ap/9":    {props: map[string]any{nmDest + ".AccessPoint.Ssid": []byte("CasaSentinela"), nmDest + ".AccessPoint.HwAddress": "02:00:5E:AA:BB:CC"}},
		nmSettings: {methods: map[string]any{nmDest + ".Settings.ListConnections": []dbus.ObjectPath{"/c/1", "/c/2"}}},
		"/c/1": {methods: map[string]any{nmDest + ".Settings.Connection.GetSettings": map[string]map[string]dbus.Variant{
			"connection":      {"id": v("CasaSentinela"), "type": v("802-11-wireless")},
			"802-11-wireless": {"ssid": v([]byte("CasaSentinela"))},
			"ipv4":            {"method": v("auto")},
		}}},
		"/c/2": {methods: map[string]any{nmDest + ".Settings.Connection.GetSettings": map[string]map[string]dbus.Variant{
			"connection": {"id": v("cabo"), "type": v("802-3-ethernet"), "autoconnect": v(false)},
			"ipv4":       {"method": v("auto"), "dhcp-send-hostname": v(false)},
			"ipv6":       {"method": v("ignore")},
		}}},
		"/org/freedesktop/GeoClue2/Manager": {props: map[string]any{"org.freedesktop.GeoClue2.Manager.InUse": true}},
		"/org/freedesktop/locale1": {props: map[string]any{"org.freedesktop.locale1.X11Layout": "br",
			"org.freedesktop.locale1.Locale": []string{"LANG=pt_BR.UTF-8", "LC_TIME=pt_BR.UTF-8"}}},
	}
}

func TestNET007_NET013_NET014_HOST008_HOST009_Read(t *testing.T) {
	st := Reader{Bus: nmBus()}.Read()
	nm := st.NM
	if !nm.Available || !nm.ConnectivityCheck || len(nm.WiFi) != 1 || nm.WiFi[0].SSID != "CasaSentinela" || nm.WiFi[0].BSSID != "02:00:5e:aa:bb:cc" {
		t.Fatalf("nm %+v", nm)
	}
	if len(nm.Connections) != 2 {
		t.Fatalf("connections %+v", nm.Connections)
	}
	home, cable := nm.Connections[0], nm.Connections[1]
	if home.ID != "CasaSentinela" || !home.Autoconnect || !home.SendHostname || home.SSID != "CasaSentinela" {
		t.Fatalf("home %+v", home)
	}
	if cable.Autoconnect || cable.SendHostname {
		t.Fatalf("cable %+v", cable)
	}
	if !st.GeoClue.Running || !st.GeoClue.InUse || st.Keyboard != "br" || st.Locale != "pt_BR.UTF-8" {
		t.Fatalf("%+v", st)
	}
}

func TestM9_DBusNoServices(t *testing.T) {
	st := Reader{Bus: fakeBus{}}.Read()
	if st.NM.Available || st.GeoClue.Running || len(st.Unavailable) != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestM9_DBusHungServiceHasDeadline(t *testing.T) {
	b := nmBus()
	b[nmPath].hang = true
	done := make(chan State, 1)
	go func() { done <- Reader{Bus: b}.Read() }()
	select {
	case st := <-done:
		if len(st.Unavailable) == 0 {
			t.Fatalf("a hung NetworkManager must be reported: %+v", st)
		}
	case <-time.After(Timeout + 2*time.Second):
		t.Fatal("Read ignored its deadline")
	}
}
