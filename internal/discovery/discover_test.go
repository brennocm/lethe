package discovery

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"lethe/internal/contracts"
)

type fakeKernel struct {
	links   []KernelLink
	routes4 []RawRoute
	routes6 []RawRoute
	get     map[netip.Addr]RawRoute
	wg      []WGDevice
	wgErr   error
	legacy  bool
	rules   []Rule
}

func (f fakeKernel) Links() ([]KernelLink, error) { return f.links, nil }
func (f fakeKernel) DefaultRoutes(fam int) ([]RawRoute, error) {
	if fam == unix.AF_INET {
		return f.routes4, nil
	}
	return f.routes6, nil
}
func (f fakeKernel) RouteGet(dst netip.Addr) (RawRoute, error) {
	if r, ok := f.get[dst]; ok {
		return r, nil
	}
	return RawRoute{}, errors.New("unreachable")
}
func (f fakeKernel) WireGuard() ([]WGDevice, error) {
	if f.wgErr != nil {
		return nil, f.wgErr
	}
	return f.wg, nil
}
func (f fakeKernel) IPv6Disabled(string) bool { return false }
func (f fakeKernel) Rules() ([]Rule, error)   { return f.rules, nil }
func (f fakeKernel) LegacyIPTables() bool     { return f.legacy }

type fakeResolved struct{ err error }

func (f fakeResolved) Links(names map[int]string) ([]ResolvedLink, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []ResolvedLink{{Iface: names[3], Servers: []string{"10.64.0.1"}, DefaultRoute: true, Domains: []string{"~."}}}, nil
}

func wgLaptop() fakeKernel {
	return fakeKernel{
		links: []KernelLink{
			{LinkInfo: LinkInfo{Index: 1, Name: "lo", Type: "device"}, Up: true},
			{LinkInfo: LinkInfo{Index: 2, Name: "wlp2s0", Type: "device", HasDevice: true}, Up: true, Running: true, MAC: "02:00:00:00:00:01", PermMAC: "02:00:00:00:00:01",
				Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24"), netip.MustParsePrefix("2001:db8:1::20/64"), netip.MustParsePrefix("fe80::1/64")}},
			{LinkInfo: LinkInfo{Index: 3, Name: "wg0", Type: "wireguard"}, Up: true, Running: true, Addrs: []netip.Prefix{netip.MustParsePrefix("10.64.0.2/32")}},
		},
		routes4: []RawRoute{{LinkIndex: 3, Table: 51820}, {LinkIndex: 2, Gateway: netip.MustParseAddr("192.168.1.1"), Table: 254}},
		routes6: []RawRoute{{LinkIndex: 2, Gateway: netip.MustParseAddr("fe80::1"), Table: 254}},
		get:     map[netip.Addr]RawRoute{ProbeV4: {LinkIndex: 3, Table: 51820}, ProbeV6: {LinkIndex: 2, Table: 254}},
		wg: []WGDevice{{Name: "wg0", FwMark: 0xca6c, Peers: []WGPeerRaw{{Endpoint: netip.MustParseAddrPort("203.0.113.10:51820"),
			Stats: WGPeer{LastHandshake: time.Unix(100, 0), TxBytes: 10}}}}},
	}
}

func writeResolv(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "stub-resolv.conf")
	_ = os.WriteFile(target, []byte(content), 0o600)
	link := filepath.Join(dir, "resolv.conf")
	_ = os.Symlink(target, link)
	return link
}

func TestDiscover_WireGuardLaptop(t *testing.T) {
	rc := writeResolv(t, "# managed\nnameserver 127.0.0.53\noptions edns0\nnameserver fe80::1%wlp2s0\n")
	s := Discover(wgLaptop(), Options{ResolvConfPath: rc, Resolved: fakeResolved{},
		ProfileEndpoints: []Endpoint{{Addr: netip.MustParseAddrPort("198.51.100.9:443"), Proto: "tcp"}}, Now: time.Unix(0, 0)})
	if c := mustIface(t, s, "wg0").Class; c != ClassTunnel {
		t.Fatal(c)
	}
	if len(s.CaptureIfaces) != 1 || s.CaptureIfaces[0] != "wlp2s0" {
		t.Fatalf("capture %v", s.CaptureIfaces)
	}
	if got := s.Endpoints; len(got) != 2 || got[0] != "198.51.100.9:443/tcp" || got[1] != "203.0.113.10:51820/udp" {
		t.Fatalf("endpoints %v", got)
	}
	if s.Tunnels[0].FwMark != 0xca6c || s.Tunnels[0].Peers[0].Endpoint != "203.0.113.10:51820" {
		t.Fatalf("tunnel %+v", s.Tunnels[0])
	}
	if s.Routes.ProbeV4.Class != ClassTunnel || s.Routes.ProbeV6.Class != ClassEgress || s.Routes.DefaultV6[0].Iface != "wlp2s0" {
		t.Fatalf("routes %+v", s.Routes)
	}
	w := mustIface(t, s, "wlp2s0")
	if len(w.GlobalV6) != 1 || w.GlobalV6[0] != "2001:db8:1::20" {
		t.Fatalf("global v6 %v", w.GlobalV6)
	}
	if !s.DNS.ResolvConf.Stub || s.DNS.ResolvConf.Target == "" || len(s.DNS.ResolvConf.Nameservers) != 2 || !s.DNS.Resolved.Available {
		t.Fatalf("dns %+v", s.DNS)
	}
	if len(s.Unavailable) != 0 {
		t.Fatalf("gaps %v", s.Unavailable)
	}
	if err := contracts.Validate("discover", s); err != nil {
		t.Fatal(err)
	}
	if eps := s.ParsedEndpoints(); len(eps) != 2 || eps[1].Proto != "udp" {
		t.Fatal(eps)
	}
}

func TestDiscover_GapsAreReported(t *testing.T) {
	k := wgLaptop()
	k.wgErr = errors.New("no genetlink")
	k.legacy = true
	s := Discover(k, Options{ResolvConfPath: filepath.Join(t.TempDir(), "none"), Resolved: fakeResolved{err: errors.New("no bus")}})
	want := map[string]bool{"wgctrl": true, "resolv.conf": true, "resolved": true}
	for _, g := range s.Unavailable {
		delete(want, g)
	}
	if len(want) != 0 || !s.LegacyIPTables {
		t.Fatalf("missing gaps %v in %v", want, s.Unavailable)
	}
	// wg0 still appears as a generic tunnel even without wgctrl
	if len(s.Tunnels) != 1 || s.Tunnels[0].Kind != "generic" {
		t.Fatalf("%+v", s.Tunnels)
	}
	if err := contracts.Validate("discover", s); err != nil {
		t.Fatal(err)
	}
	if s2 := Discover(k, Options{}); len(s2.Unavailable) == 0 {
		t.Fatal("nil resolved client must be a gap")
	}
}

func TestParseEndpoint(t *testing.T) {
	for _, bad := range []string{"1.2.3.4:51820", "1.2.3.4/udp", "1.2.3.4:0/udp", "x:1/udp", "1.2.3.4:1/sctp"} {
		if _, err := ParseEndpoint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	e, err := ParseEndpoint("[::ffff:1.2.3.4]:53/tcp")
	if err != nil || e.String() != "1.2.3.4:53/tcp" {
		t.Fatalf("%v %v", e, err)
	}
}

func mustIface(t *testing.T, s Snapshot, name string) Iface {
	t.Helper()
	i, ok := s.Iface(name)
	if !ok {
		t.Fatalf("no iface %s", name)
	}
	return i
}
