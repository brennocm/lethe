//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"antrea.io/packet"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/guard"
	"lethe/internal/sensors/nflog"
	"lethe/test/netlab"
)

func labConfig() guard.Config {
	return guard.Config{
		Tunnels:   []string{netlab.DUTTunnel},
		Egress:    []string{netlab.DUTEgress},
		Endpoints: []guard.Endpoint{{Addr: netip.MustParseAddrPort("198.18.0.2:51820"), Proto: unix.IPPROTO_UDP}},
		L2:        true,
	}
}

func nft(t *testing.T) *nftables.Conn {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func dump(t *testing.T) string {
	t.Helper()
	d, err := guard.Dump(nft(t))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func arm(t *testing.T, cfg guard.Config) {
	t.Helper()
	rs, err := guard.Strict(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Apply(nft(t), rs); err != nil {
		t.Fatalf("apply strict: %v", err)
	}
	t.Cleanup(func() { _ = guard.Remove(nft(t), guard.All()...) })
}

// sendUDP sends one datagram; under the strict guard the kernel answers EPERM, which is fine.
func sendUDP(t *testing.T, dst string, bindEgress bool, payload []byte) {
	t.Helper()
	d := net.Dialer{}
	if bindEgress {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) { _ = unix.BindToDevice(int(fd), netlab.DUTEgress) })
		}
	}
	c, err := d.Dial("udp", dst)
	if err != nil {
		return // no route (e.g. panic) is a block too
	}
	_, _ = c.Write(payload)
	_ = c.Close()
}

// sendRaw writes a frame on the egress with an AF_PACKET socket: it bypasses the inet hooks
// and must be stopped by netdev lethe_l2 (§8.2, §11.5).
func sendRaw(t *testing.T, ethertype uint16, payload []byte) {
	t.Helper()
	ifi, err := net.InterfaceByName(netlab.DUTEgress)
	if err != nil {
		t.Fatal(err)
	}
	c, err := packet.Listen(ifi, packet.Raw, int(ethertype), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	f := make([]byte, 14, 14+len(payload))
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], ifi.HardwareAddr)
	binary.BigEndian.PutUint16(f[12:], ethertype)
	f = append(f, payload...)
	// a netdev egress drop surfaces as ENOBUFS (NET_XMIT_DROP) to the sender
	if _, err := c.WriteTo(f, &packet.Addr{HardwareAddr: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}); err != nil && !errors.Is(err, unix.ENOBUFS) && !errors.Is(err, unix.EPERM) {
		t.Fatalf("raw write: %v", err)
	}
}

func rawIPv4UDP(dst [4]byte, dport uint16) []byte {
	p := make([]byte, 28)
	p[0], p[8], p[9] = 0x45, 64, unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(p[2:], 28)
	copy(p[12:16], []byte{10, 0, 0, 2})
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:], 40000)
	binary.BigEndian.PutUint16(p[22:], dport)
	binary.BigEndian.PutUint16(p[24:], 8)
	return p
}

func leaksOnWire(frames []netlab.Frame, allowEndpoint bool) []netlab.Frame {
	var out []netlab.Frame
	for _, f := range frames {
		if netlab.IsLinkControl(f.Data) || (allowEndpoint && netlab.UDPTo(f.Data, net.ParseIP("198.18.0.2"), netlab.WGPort)) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func TestE2E_M6_FullRulesetAcceptedByKernel(t *testing.T) {
	netlab.New(t, true)
	cfg := labConfig()
	tor := uint32(0)
	cfg.TorUID = &tor
	cfg.WGMark = 0xca6c
	feat, err := guard.Probe(nft(t))
	if err != nil {
		t.Fatal(err)
	}
	if !feat.L2 {
		t.Fatal("netlab kernels must have the netdev egress hook")
	}
	if feat.SocketCgroup {
		cfg.VPN = &guard.Cgroup{Path: "system.slice/openvpn.service", Level: 2, ID: 12345}
	} else {
		t.Log("kernel without nft_socket: socket cgroupv2 rule not exercised")
	}
	cfg.LAN = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("fd00:1::/64")}
	arm(t, cfg)
	d := dump(t)
	for _, want := range []string{"table inet lethe chain output", "table netdev lethe_l2 chain egress_ltx0", "set endpoints4"} {
		if !strings.Contains(d, want) {
			t.Fatalf("missing %q in\n%s", want, d)
		}
	}
	// set update without touching the chains
	cfg.Endpoints = append(cfg.Endpoints, guard.Endpoint{Addr: netip.MustParseAddrPort("198.18.0.3:51820"), Proto: unix.IPPROTO_UDP})
	rs, _ := guard.Strict(cfg)
	if err := guard.UpdateSets(nft(t), rs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dump(t), "c6120003") { // 198.18.0.3
		t.Fatal("updated endpoint not in the kernel set")
	}
	rp, err := guard.Panic(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Apply(nft(t), rp); err != nil {
		t.Fatalf("apply panic: %v", err)
	}
	cfg.KeepTunnel = true
	rk, _ := guard.Panic(cfg)
	if err := guard.Apply(nft(t), rk); err != nil {
		t.Fatalf("apply keep-tunnel panic: %v", err)
	}
	if err := guard.Remove(nft(t), guard.All()...); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump(t), "lethe") {
		t.Fatal("tables left after disarm")
	}
}

func TestE2E_M6_BridgeTable(t *testing.T) {
	lab := netlab.New(t, false)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(lab.In(lab.DUT, func() error {
		br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "ltbr0"}}
		if err := netlink.LinkAdd(br); err != nil {
			return err
		}
		port := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ltd0", MasterIndex: 0}}
		if err := netlink.LinkAdd(port); err != nil {
			return err
		}
		return netlink.LinkSetMaster(port, br)
	}))
	defer func() {
		_ = lab.In(lab.DUT, func() error {
			for _, n := range []string{"ltd0", "ltbr0"} {
				if l, err := netlink.LinkByName(n); err == nil {
					_ = netlink.LinkDel(l)
				}
			}
			return nil
		})
	}()
	if feat, err := guard.Probe(nft(t)); err != nil || !feat.Bridge {
		t.Skipf("kernel without the nf_tables bridge family (CONFIG_NF_TABLES_BRIDGE): %v", err)
	}
	cfg := labConfig()
	cfg.Bridges = map[string][]string{"ltbr0": {"ltd0"}}
	rs, err := guard.Strict(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Apply(nft(t), rs); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = guard.Remove(nft(t), guard.All()...) }()
	if !strings.Contains(dump(t), "table bridge lethe chain forward") {
		t.Fatal("bridge table missing")
	}
}

// TestE2E_AC04_StrictBlocksWhenTunnelDrops covers AC-04 (TUN-001 itself arrives in M8):
// NET-002 is logged with the sender UID and nothing but link control reaches the isp.
func TestE2E_AC04_StrictBlocksWhenTunnelDrops(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	arm(t, labConfig())
	blocked := make(chan nflog.Blocked, 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nflogErr := make(chan error, 1)
	go func() { nflogErr <- nflog.Run(ctx, guard.LogGroup, blocked, func(time.Time) {}) }()
	time.Sleep(100 * time.Millisecond)
	sn := lab.Sniff(t)
	start := time.Now()

	sendUDP(t, "10.200.0.1:9", false, []byte("through the tunnel")) // allowed: rides WireGuard
	lab.SetTunnel(t, false)
	defer lab.SetTunnel(t, true)
	sendUDP(t, "192.0.2.1:9", false, []byte("tunnel is down"))
	sendUDP(t, "198.51.100.1:443", true, []byte("bound to the egress"))
	sendRaw(t, unix.ETH_P_IP, rawIPv4UDP([4]byte{192, 0, 2, 7}, 9)) // AF_PACKET, bypasses inet
	sendRaw(t, 0x88b5, []byte("experimental ethertype"))

	var got *nflog.Blocked
	timeout := time.After(3 * time.Second)
	for got == nil {
		select {
		case b := <-blocked:
			if b.Leak.Dst.String() == "192.0.2.1" && b.Prefix == "LETHE-BLOCK " {
				got = &b
			}
		case err := <-nflogErr:
			t.Fatalf("nflog: %v", err)
		case <-timeout:
			t.Fatal("no NET-002 for the blocked datagram")
		}
	}
	if got.UID != os.Getuid() || got.OutIface != netlab.DUTEgress {
		t.Fatalf("blocked %+v (want uid %d)", got, os.Getuid())
	}
	f := checks.FromBlocked(*got, contracts.Proc{})
	if f.Check != "NET-002" || f.Severity != contracts.SeverityWarning {
		t.Fatalf("%+v", f)
	}
	time.Sleep(300 * time.Millisecond)
	if leaks := leaksOnWire(sn.Since(start), true); len(leaks) != 0 {
		t.Fatalf("sniffer saw %d leaked frames, first % x", len(leaks), leaks[0].Data[:min(48, len(leaks[0].Data))])
	}
}

// TestE2E_AC08_PanicBlocksEverything covers the nftables part of AC-08.
func TestE2E_AC08_PanicBlocksEverything(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	cfg := labConfig()
	arm(t, cfg)
	sn := lab.Sniff(t)
	sendUDP(t, "10.200.0.1:9", false, []byte("before"))
	time.Sleep(100 * time.Millisecond)
	if len(sn.Since(time.Time{})) == 0 {
		t.Fatal("sniffer saw nothing before the panic: test is not measuring anything")
	}
	rp, err := guard.Panic(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	if err := guard.Apply(nft(t), rp); err != nil {
		t.Fatal(err)
	}
	applied := time.Now()
	if d := applied.Sub(t0); d > 200*time.Millisecond {
		t.Fatalf("block_all took %s (> 200 ms)", d)
	}
	for range 5 {
		sendUDP(t, "10.200.0.1:9", false, []byte("tunnel during panic"))
		sendUDP(t, "192.0.2.1:9", true, []byte("egress during panic"))
		sendRaw(t, unix.ETH_P_IP, rawIPv4UDP([4]byte{192, 0, 2, 7}, 9))
		sendRaw(t, unix.ETH_P_ARP, make([]byte, 28))
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(2500 * time.Millisecond) // a WireGuard keepalive (2 s) would show up here
	if fs := sn.Since(applied); len(fs) != 0 {
		t.Fatalf("%d frames left during panic, first % x", len(fs), fs[0].Data[:min(48, len(fs[0].Data))])
	}

	// unpanic (the authorization part is M7): tunnel traffic flows again
	if err := guard.Remove(nft(t), guard.TableRef{Family: nftables.TableFamilyINet, Name: guard.TablePanic}); err != nil {
		t.Fatal(err)
	}
	rs, _ := guard.Strict(cfg)
	if err := guard.Apply(nft(t), rs); err != nil { // restores lethe_l2 to the strict version
		t.Fatal(err)
	}
	released := time.Now()
	sendUDP(t, "10.200.0.1:9", false, []byte("after"))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range sn.Since(released) {
			if netlab.UDPTo(f.Data, net.ParseIP("198.18.0.2"), netlab.WGPort) {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("tunnel did not come back after unpanic")
}

func TestE2E_AC08_PanicKeepTunnel(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	cfg := labConfig()
	cfg.KeepTunnel = true
	rp, err := guard.Panic(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Apply(nft(t), rp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Remove(nft(t), guard.All()...) })
	sn := lab.Sniff(t)
	start := time.Now()
	sendUDP(t, "192.0.2.1:9", true, []byte("egress during keep_tunnel panic"))
	sendUDP(t, "10.200.0.1:9", false, []byte("tunnel stays"))
	time.Sleep(500 * time.Millisecond)
	var sawTunnel bool
	for _, f := range sn.Since(start) {
		if netlab.UDPTo(f.Data, net.ParseIP("198.18.0.2"), netlab.WGPort) {
			sawTunnel = true
		}
	}
	if !sawTunnel {
		t.Fatal("keep_tunnel must keep the WireGuard transport")
	}
	if leaks := leaksOnWire(sn.Since(start), true); len(leaks) != 0 {
		t.Fatalf("%d leaked frames", len(leaks))
	}
}

// TestE2E_AC09_TablesSurviveKill9 arms from a child process, kills it with SIGKILL and
// checks fail-closed; then cleanup removes only lethe* tables (AC-09).
func TestE2E_AC09_TablesSurviveKill9(t *testing.T) {
	if os.Getenv("LETHE_AC09_CHILD") == "1" {
		if err := netlab.AssertNotHostNamespace(); err != nil {
			t.Fatal(err)
		}
		rs, err := guard.Strict(labConfig())
		if err != nil {
			t.Fatal(err)
		}
		c, _ := nftables.New()
		if err := guard.Apply(c, rs); err != nil {
			t.Fatal(err)
		}
		_, _ = os.Stdout.WriteString("ARMED\n")
		time.Sleep(time.Minute)
		return
	}
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	t.Cleanup(func() { _, _ = guard.Cleanup(nft(t)) })
	c := nft(t)
	foreign := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "killswitch"})
	pol := nftables.ChainPolicyAccept
	c.AddChain(&nftables.Chain{Name: "output", Table: foreign, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &pol})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	defer func() { c := nft(t); c.DelTable(foreign); _ = c.Flush() }()

	cmd := exec.Command(os.Args[0], "-test.run=^TestE2E_AC09_TablesSurviveKill9$", "-test.count=1")
	cmd.Env = append(os.Environ(), "LETHE_AC09_CHILD=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	armed := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if sc.Text() == "ARMED" {
				armed <- true
				return
			}
		}
		armed <- false
	}()
	select {
	case ok := <-armed:
		if !ok {
			t.Fatal("child exited without arming")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child did not arm")
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()

	if !strings.Contains(dump(t), "table inet lethe chain output") {
		t.Fatal("strict table did not survive the daemon's death")
	}
	sn := lab.Sniff(t)
	start := time.Now()
	sendUDP(t, "192.0.2.1:9", true, []byte("after kill -9"))
	sendRaw(t, unix.ETH_P_IP, rawIPv4UDP([4]byte{192, 0, 2, 7}, 9))
	time.Sleep(300 * time.Millisecond)
	if leaks := leaksOnWire(sn.Since(start), true); len(leaks) != 0 {
		t.Fatalf("%d leaked frames after kill -9", len(leaks))
	}

	removed, err := guard.Cleanup(nft(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Fatalf("removed %+v", removed)
	}
	d := dump(t)
	if strings.Contains(d, "lethe") || !strings.Contains(d, "table inet killswitch") {
		t.Fatalf("cleanup must remove lethe* only:\n%s", d)
	}
}

// TestE2E_AC13_RulesetRestoredAfterDisarm covers AC-13.
func TestE2E_AC13_RulesetRestoredAfterDisarm(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	c := nft(t)
	third := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "vpnclient"})
	pol := nftables.ChainPolicyAccept
	c.AddChain(&nftables.Chain{Name: "out", Table: third, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &pol})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	defer func() { c := nft(t); c.DelTable(third); _ = c.Flush() }()
	before := dump(t)

	cfg := labConfig()
	rs, _ := guard.Strict(cfg)
	if err := guard.Apply(nft(t), rs); err != nil {
		t.Fatal(err)
	}
	rp, _ := guard.Panic(cfg)
	if err := guard.Apply(nft(t), rp); err != nil {
		t.Fatal(err)
	}
	if err := guard.Remove(nft(t), guard.All()...); err != nil {
		t.Fatal(err)
	}
	if after := dump(t); after != before {
		t.Fatalf("ruleset differs after disarm:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestE2E_M6_RawSocketsNeedTheL2Layer is the control for §8.2: without netdev lethe_l2 an
// AF_PACKET sender walks around the inet table; with it, the frame is dropped.
func TestE2E_M6_RawSocketsNeedTheL2Layer(t *testing.T) {
	lab := netlab.New(t, true)
	cfg := labConfig()
	cfg.L2 = false
	arm(t, cfg)
	sn := lab.Sniff(t)
	start := time.Now()
	sendRaw(t, unix.ETH_P_IP, rawIPv4UDP([4]byte{192, 0, 2, 7}, 9))
	time.Sleep(200 * time.Millisecond)
	if len(leaksOnWire(sn.Since(start), true)) == 0 {
		t.Fatal("control failed: the raw frame should bypass the inet table")
	}
	cfg.L2 = true
	arm(t, cfg)
	start = time.Now()
	sendRaw(t, unix.ETH_P_IP, rawIPv4UDP([4]byte{192, 0, 2, 7}, 9))
	time.Sleep(200 * time.Millisecond)
	if leaks := leaksOnWire(sn.Since(start), true); len(leaks) != 0 {
		t.Fatalf("netdev lethe_l2 let %d raw frames out", len(leaks))
	}
}
