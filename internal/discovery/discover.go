package discovery

import (
	"net/netip"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

// Options configure one discovery pass.
type Options struct {
	Overrides        Overrides
	ProfileEndpoints []Endpoint // profile egress.endpoints
	ResolvConfPath   string     // default /etc/resolv.conf
	Resolved         ResolvedClient
	Now              time.Time
}

// Discover takes a snapshot of the environment. Read failures become entries in Unavailable,
// never silent omissions (principle 1).
func Discover(k Kernel, opt Options) Snapshot {
	s := Snapshot{TakenAt: opt.Now.UTC(), Ifaces: []Iface{}, CaptureIfaces: []string{}, Tunnels: []Tunnel{}, Endpoints: []string{}, Unavailable: []string{}}
	gap := func(src string) { s.Unavailable = append(s.Unavailable, src) }

	links, err := k.Links()
	if err != nil {
		gap("netlink:links")
	}
	infos := make([]LinkInfo, 0, len(links))
	names := map[int]string{}
	for _, l := range links {
		infos = append(infos, l.LinkInfo)
		names[l.Index] = l.Name
	}
	classes := Classify(infos, opt.Overrides)
	for _, l := range links {
		ifc := Iface{LinkInfo: l.LinkInfo, Class: classes[l.Name], Up: l.Up, Running: l.Running, MAC: l.MAC, PermMAC: l.PermMAC,
			Addrs: []string{}, GlobalV6: []string{}, IPv6Disabled: k.IPv6Disabled(l.Name)}
		for _, a := range l.Addrs {
			ifc.Addrs = append(ifc.Addrs, a.String())
			if a.Addr().Is6() && a.Addr().IsGlobalUnicast() && !a.Addr().IsPrivate() {
				ifc.GlobalV6 = append(ifc.GlobalV6, a.Addr().String())
			}
		}
		s.Ifaces = append(s.Ifaces, ifc)
	}
	s.CaptureIfaces = CaptureIfaces(infos, classes, opt.Overrides)

	endpoints := map[string]bool{}
	for _, e := range opt.ProfileEndpoints {
		endpoints[e.String()] = true
	}
	wg, err := k.WireGuard()
	if err != nil {
		gap("wgctrl")
	}
	wgNames := map[string]bool{}
	for _, d := range wg {
		wgNames[d.Name] = true
		t := Tunnel{Iface: d.Name, Kind: "wireguard", FwMark: d.FwMark, Peers: []WGPeer{}}
		for _, p := range d.Peers {
			wp := p.Stats
			if p.Endpoint.IsValid() {
				wp.Endpoint = p.Endpoint.String()
				endpoints[Endpoint{Addr: p.Endpoint, Proto: "udp"}.String()] = true
			}
			t.Peers = append(t.Peers, wp)
		}
		s.Tunnels = append(s.Tunnels, t)
	}
	for _, l := range links {
		if classes[l.Name] == ClassTunnel && !wgNames[l.Name] {
			kind := "generic"
			if l.Type == "tuntap" {
				kind = "tun"
			}
			s.Tunnels = append(s.Tunnels, Tunnel{Iface: l.Name, Kind: kind})
		}
	}
	sort.Slice(s.Tunnels, func(i, j int) bool { return s.Tunnels[i].Iface < s.Tunnels[j].Iface })
	for e := range endpoints {
		s.Endpoints = append(s.Endpoints, e)
	}
	sort.Strings(s.Endpoints)

	route := func(r RawRoute) Route {
		out := Route{Dst: "default", Iface: names[r.LinkIndex], Table: r.Table}
		out.Class = classes[out.Iface]
		if r.Dst.IsValid() {
			out.Dst = r.Dst.String()
		}
		if r.Gateway.IsValid() {
			out.Gateway = r.Gateway.String()
		}
		return out
	}
	s.Routes.DefaultV4, s.Routes.DefaultV6 = []Route{}, []Route{}
	if rs, err := k.DefaultRoutes(unix.AF_INET); err == nil {
		for _, r := range rs {
			s.Routes.DefaultV4 = append(s.Routes.DefaultV4, route(r))
		}
	} else {
		gap("netlink:routes4")
	}
	if rs, err := k.DefaultRoutes(unix.AF_INET6); err == nil {
		for _, r := range rs {
			s.Routes.DefaultV6 = append(s.Routes.DefaultV6, route(r))
		}
	}
	s.Routes.Rules = []Rule{}
	if rs, err := k.Rules(); err == nil {
		s.Routes.Rules = append(s.Routes.Rules, rs...)
	} else {
		gap("netlink:rules")
	}
	for _, p := range []struct {
		dst netip.Addr
		set **Route
	}{{ProbeV4, &s.Routes.ProbeV4}, {ProbeV6, &s.Routes.ProbeV6}} {
		if r, err := k.RouteGet(p.dst); err == nil {
			rt := route(r)
			rt.Dst = p.dst.String()
			*p.set = &rt
		}
	}

	path := opt.ResolvConfPath
	if path == "" {
		path = "/etc/resolv.conf"
	}
	if rc, err := ReadResolvConf(path); err == nil {
		s.DNS.ResolvConf = rc
	} else {
		s.DNS.ResolvConf = rc
		gap("resolv.conf")
	}
	s.DNS.Resolved.Links = []ResolvedLink{}
	if opt.Resolved != nil {
		if ls, err := opt.Resolved.Links(names); err == nil {
			s.DNS.Resolved = Resolved{Available: true, Links: ls}
		} else {
			gap("resolved")
		}
	} else {
		gap("resolved")
	}
	s.LegacyIPTables = k.LegacyIPTables()
	return s
}
